// tls.go selects and constructs the TLS configuration based on the "tls"
// query parameter:
//   - tls=0 (default): plaintext, no TLS.
//   - tls=1: ephemeral RAM certificate (ECDSA P-256, TLS 1.3 only).
//   - tls=2: file-based certificate with hot-reload every ReloadInterval.
package main

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"time"

	"github.com/VortexWang/Tunveo/internal/common"
)

// getTLSProtocol extracts and configures TLS based on the "tls" query parameter:
//   - tls=0 (default): plaintext (no TLS), returns code "0" and nil config
//   - tls=1: ephemeral self-signed certificate in RAM (ECDSA P-256, TLS 1.3 only)
//   - tls=2: file-based certificate (crt/key parameters) with hot-reload every ReloadInterval
//
// Returns an error before runtime construction if requested TLS material cannot
// be loaded or generated. Explicit TLS modes must never silently downgrade.
func getTLSProtocol(parsedURL *url.URL, logger *common.Logger) (string, *tls.Config, error) {
	switch parsedURL.Query().Get("tls") {
	case "1":
		tlsConfig, err := common.NewTLSConfig()
		if err != nil {
			return "", nil, fmt.Errorf("TLS mode 1: generate certificate: %w", err)
		}
		tlsConfig.MinVersion = tls.VersionTLS13
		logger.Info("TLS code-1: RAM cert with TLS 1.3")
		return "1", tlsConfig, nil
	case "2":
		crtFile, keyFile := parsedURL.Query().Get("crt"), parsedURL.Query().Get("key")
		if crtFile == "" || keyFile == "" {
			return "", nil, fmt.Errorf("TLS mode 2: both crt and key parameters are required")
		}
		cert, err := tls.LoadX509KeyPair(crtFile, keyFile)
		if err != nil {
			return "", nil, fmt.Errorf("TLS mode 2: load certificate: %w", err)
		}

		cachedCert := cert
		lastReload := time.Now()
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS13,
			GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if time.Since(lastReload) >= common.ReloadInterval {
					newCert, err := tls.LoadX509KeyPair(crtFile, keyFile)
					if err != nil {
						logger.Error("Certificate reload failed: %v", err)
					} else {
						logger.Debug("TLS cert reloaded: %v", crtFile)
						cachedCert = newCert
					}
					lastReload = time.Now()
				}
				return &cachedCert, nil
			},
		}

		if cert.Leaf != nil {
			logger.Info("TLS code-2: %v with TLS 1.3", cert.Leaf.Subject.CommonName)
		} else {
			logger.Warn("TLS code-2: unknown cert name with TLS 1.3")
		}
		return "2", tlsConfig, nil
	default:
		logger.Warn("TLS code-0: unencrypted")
		return "0", nil, nil
	}
}
