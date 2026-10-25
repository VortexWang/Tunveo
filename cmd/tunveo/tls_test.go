package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VortexWang/Tunveo/internal/common"
)

func certificateFiles(t *testing.T) (string, string, []byte) {
	t.Helper()
	cfg, err := common.NewTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	cert := cfg.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	crtPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(crtPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	return crtPath, keyPath, cert.Certificate[0]
}

func TestStrictTLSRejectsInvalidMaterialBeforeCoreConstruction(t *testing.T) {
	crt, key, _ := certificateFiles(t)
	_, otherKey, _ := certificateFiles(t)
	invalid := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(invalid, []byte("not PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, crt, key string }{
		{"missing-both", "", ""}, {"missing-cert", "", key}, {"missing-key", crt, ""},
		{"absent-cert", crt + ".absent", key}, {"absent-key", crt, key + ".absent"},
		{"malformed-cert", invalid, key}, {"malformed-key", crt, invalid},
		{"mismatched-key", crt, otherKey}, {"directory", filepath.Dir(crt), key},
	}
	logger := common.NewLogger(common.None, false)
	for _, tc := range cases {
		for _, role := range []string{"server", "master", "client"} {
			for _, pool := range []string{"0", "1", "2", "3"} {
				t.Run(tc.name+"/"+role+"/pool="+pool, func(t *testing.T) {
					u := &url.URL{Scheme: role, Host: "127.0.0.1:10101", Path: "/127.0.0.1:8080"}
					q := url.Values{"tls": {"2"}, "crt": {tc.crt}, "key": {tc.key}, "type": {pool}}
					u.RawQuery = q.Encode()
					code, cfg, err := getTLSProtocol(u, logger)
					if err == nil || code != "" || cfg != nil || !strings.Contains(err.Error(), "TLS mode 2") {
						t.Fatalf("invalid material accepted: code=%q cfg=%v err=%v", code, cfg, err)
					}
					core, err := createCore(u, logger)
					if core != nil || err == nil || !strings.Contains(err.Error(), "initialize TLS") {
						t.Fatalf("runtime constructed on invalid TLS: core=%T err=%v", core, err)
					}
				})
			}
		}
	}
}

func TestStrictTLSValidCertificateHandshake(t *testing.T) {
	crt, key, want := certificateFiles(t)
	u := &url.URL{RawQuery: url.Values{"tls": {"2"}, "crt": {crt}, "key": {key}}.Encode()}
	code, cfg, err := getTLSProtocol(u, common.NewLogger(common.None, false))
	if err != nil || code != "2" || cfg == nil {
		t.Fatalf("code=%q err=%v", code, err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatal("TLS 1.3 minimum lost")
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(3 * time.Second))
	b.SetDeadline(time.Now().Add(3 * time.Second))
	server := tls.Server(a, cfg)
	// This test checks exact wire certificate identity, independently of DNS trust.
	client := tls.Client(b, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	done := make(chan error, 1)
	go func() { done <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	state := client.ConnectionState()
	if state.Version != tls.VersionTLS13 || len(state.PeerCertificates) != 1 || !bytes.Equal(state.PeerCertificates[0].Raw, want) {
		t.Fatal("server did not present configured certificate over TLS 1.3")
	}
}

func TestTLSModeDefaultsAndRAMCertificate(t *testing.T) {
	for _, mode := range []string{"", "0", "1"} {
		t.Run("mode="+mode, func(t *testing.T) {
			u := &url.URL{RawQuery: url.Values{"tls": {mode}}.Encode()}
			code, cfg, err := getTLSProtocol(u, common.NewLogger(common.None, false))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "1" {
				if code != "1" || cfg == nil || len(cfg.Certificates) != 1 || cfg.MinVersion != tls.VersionTLS13 {
					t.Fatal("RAM certificate mode changed")
				}
			} else if code != "0" || cfg != nil {
				t.Fatal("plaintext mode changed")
			}
		})
	}
}

func TestStartRejectsStrictTLSForURLAndFlags(t *testing.T) {
	for _, role := range []string{"server", "master", "client"} {
		for _, format := range []string{"url", "flags"} {
			t.Run(role+"/"+format, func(t *testing.T) {
				args := []string{"tunveo", fmt.Sprintf("%s://127.0.0.1:10101/127.0.0.1:8080?tls=2&log=none", role)}
				if format == "flags" {
					args = []string{"tunveo", role, "--tls", "2", "--log", "none"}
				}
				err := start(args)
				if err == nil || !strings.Contains(err.Error(), "TLS mode 2") {
					t.Fatalf("startup must fail at TLS initialization: %v", err)
				}
			})
		}
	}
}

// Exercise run/exit in a child process so returning an initialization error alone
// cannot hide a successful exit status or an accidental runtime start.
func TestStrictTLSProcessExit(t *testing.T) {
	if os.Getenv("TUNVEO_TEST_STRICT_TLS_CHILD") == "1" {
		os.Args = []string{"tunveo", os.Getenv("TUNVEO_TEST_STRICT_TLS_URL")}
		run()
		return
	}
	for _, role := range []string{"server", "master", "client"} {
		t.Run(role, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStrictTLSProcessExit$")
			cmd.Env = append(os.Environ(), "TUNVEO_TEST_STRICT_TLS_CHILD=1", "TUNVEO_TEST_STRICT_TLS_URL="+role+"://127.0.0.1:10101/127.0.0.1:8080?tls=2")
			output, err := cmd.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if ctx.Err() != nil || !ok || exit.ExitCode() != 1 {
				t.Fatalf("expected prompt exit 1: %v output=%s", err, output)
			}
			text := string(output)
			if !strings.Contains(text, "TLS mode 2") || strings.Contains(text, "TLS code-1") || strings.Contains(text, "started:") {
				t.Fatalf("missing error or downgraded runtime: %s", text)
			}
		})
	}
}
