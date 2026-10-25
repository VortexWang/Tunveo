package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VortexWang/Tunveo/internal/common"
)

func tlsURL(t *testing.T, mode string, paths ...string) *url.URL {
	t.Helper()
	u, _ := url.Parse("server://fixture-only@127.0.0.1:0/127.0.0.1:1")
	q := url.Values{"tls": {mode}}
	if len(paths) > 0 {
		q.Set("crt", paths[0])
		q.Set("key", paths[1])
	}
	u.RawQuery = q.Encode()
	return u
}

func writePair(t *testing.T) (string, string) {
	t.Helper()
	cfg, err := common.NewTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(cfg.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	crt, priv := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	for p, b := range map[string][]byte{crt: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cfg.Certificates[0].Certificate[0]}), priv: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})} {
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return crt, priv
}

func TestTLSModesFailClosed(t *testing.T) {
	logger := common.NewLogger(common.None, false)
	crt, key := writePair(t)
	_, otherKey := writePair(t)
	malformed := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(malformed, []byte("invalid PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, mode string
		paths      []string
		fail       bool
	}{
		{"default", "", nil, false}, {"plain", "0", nil, false}, {"ephemeral", "1", nil, false},
		{"valid", "2", []string{crt, key}, false}, {"missing options", "2", nil, true},
		{"missing files", "2", []string{crt + "missing", key}, true}, {"mismatch", "2", []string{crt, otherKey}, true},
		{"malformed", "2", []string{malformed, key}, true}, {"unsupported", "3", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mode, cfg, err := getTLSProtocol(tlsURL(t, tc.mode, tc.paths...), logger)
			if tc.fail {
				if err == nil || cfg != nil || mode != "" {
					t.Fatalf("failure must not return fallback: mode=%q config=%v err=%v", mode, cfg, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "0" {
				if cfg != nil {
					t.Fatal("plaintext has config")
				}
				return
			}
			if mode != tc.mode || cfg == nil || cfg.MinVersion != tls.VersionTLS13 {
				t.Fatal("wrong TLS mode")
			}
		})
	}
	// An unavailable RNG must not turn mode 1 into mode 0; mode 2 and plaintext
	// must not depend on generating an unused ephemeral certificate.
	broken := func() (*tls.Config, error) { return nil, errors.New("injected RNG failure") }
	if mode, cfg, err := configureTLS(tlsURL(t, "1"), logger, broken, tls.LoadX509KeyPair); err == nil || cfg != nil || mode != "" {
		t.Fatal("generation downgraded")
	}
	for _, mode := range []string{"0", "2"} {
		if _, _, err := configureTLS(tlsURL(t, mode, crt, key), logger, broken, tls.LoadX509KeyPair); err != nil {
			t.Fatal(err)
		}
	}
	// Constructor must stop before creating a running core on strict failure.
	if core, err := createCore(tlsURL(t, "2"), logger); err == nil || core != nil {
		t.Fatal("invalid strict config created a core")
	}
}

func TestCertificateReloadConcurrentAndRetainsLastGood(t *testing.T) {
	previous := common.ReloadInterval
	common.ReloadInterval = 0
	defer func() { common.ReloadInterval = previous }()
	first, err := common.NewTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	second, err := common.NewTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	load := func(string, string) (tls.Certificate, error) {
		n := calls.Add(1)
		if n == 1 {
			return first.Certificates[0], nil
		}
		if n == 2 {
			return second.Certificates[0], nil
		}
		return tls.Certificate{}, errors.New("injected reload error")
	}
	mode, cfg, err := configureTLS(tlsURL(t, "2", "cert", "key"), common.NewLogger(common.None, false), common.NewTLSConfig, load)
	if err != nil || mode != "2" {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				cert, err := cfg.GetCertificate(nil)
				if err != nil || cert == nil || cert.Certificate[0][0] != second.Certificates[0].Certificate[0][0] {
					t.Error("reload failed")
				}
				if string(cert.Certificate[0]) != string(second.Certificates[0].Certificate[0]) {
					t.Error("lost last good certificate")
				}
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 641 {
		t.Fatalf("expected serialized reload attempts, got %d", calls.Load())
	}
	// Returned configs perform a real TLS handshake using the retained pair.
	listener, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		done <- conn.(*tls.Conn).Handshake()
	}()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if string(conn.ConnectionState().PeerCertificates[0].Raw) != string(second.Certificates[0].Certificate[0]) {
		t.Fatal("wrong certificate on wire")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCoreRejectsNonpositiveReloadBeforeTLS(t *testing.T) {
	old := common.ReloadInterval
	common.ReloadInterval = 0
	defer func() { common.ReloadInterval = old }()
	core, err := createCore(nil, common.NewLogger(common.None, false))
	if err == nil || core != nil {
		t.Fatal("core initialization accepted invalid reload interval")
	}
}
