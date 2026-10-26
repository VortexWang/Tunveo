package common

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestTLSIdentityAndClientHello(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"matrix.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1"), net.ParseIP("fe80::1")}, BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	for _, tc := range []struct {
		name, host, override, wantSNI string
		reject                        bool
	}{
		{"IPv4 default", "127.0.0.1", "", "", false},
		{"IPv6 default", "::1", "", "", false},
		{"IPv6 zone", "fe80::1%eth0", "", "", false},
		{"DNS default", "matrix.test", "", "matrix.test", false},
		{"explicit DNS over IP", "127.0.0.1", "matrix.test", "matrix.test", false},
		{"none is literal", "127.0.0.1", "none", "none", true},
		{"wrong explicit identity", "127.0.0.1", "wrong.test", "wrong.test", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			offered := make(chan string, 1)
			finished := make(chan error, 1)
			config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { offered <- hello.ServerName; return nil, nil }}
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					finished <- err
					return
				}
				defer conn.Close()
				finished <- tls.Server(conn, config).HandshakeContext(ctx)
			}()
			query := url.Values{}
			if tc.override != "" {
				query.Set("sni", tc.override)
			}
			c := NewCommonPtr(NewLogger(None, false), nil)
			c.ParsedURL = &url.URL{Scheme: "client", Host: net.JoinHostPort(tc.host, "443"), RawQuery: query.Encode()}
			c.ServerName = tc.host
			c.GetServerName()
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			client := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: c.ServerName})
			defer client.Close()
			err = client.HandshakeContext(ctx)
			if tc.reject {
				var mismatch x509.HostnameError
				if !errors.As(err, &mismatch) {
					t.Fatalf("wanted hostname rejection, got %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			client.Close()
			select {
			case name := <-offered:
				if name != tc.wantSNI {
					t.Fatalf("ClientHello SNI=%q want %q", name, tc.wantSNI)
				}
			case <-ctx.Done():
				t.Fatal("missing ClientHello")
			}
			select {
			case serverErr := <-finished:
				if !tc.reject && serverErr != nil {
					t.Fatal(serverErr)
				}
			case <-ctx.Done():
				t.Fatal("server handshake did not finish")
			}
		})
	}
}
