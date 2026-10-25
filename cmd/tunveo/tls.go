// tls.go selects plaintext, ephemeral TLS, or reloadable file-backed TLS.
package main

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/VortexWang/Tunveo/internal/common"
)

// getTLSProtocol never downgrades an explicitly requested TLS mode on failure.
func getTLSProtocol(u *url.URL, logger *common.Logger) (string, *tls.Config, error) {
	return configureTLS(u, logger, common.NewTLSConfig, tls.LoadX509KeyPair)
}

func configureTLS(u *url.URL, logger *common.Logger, generate func() (*tls.Config, error), load func(string, string) (tls.Certificate, error)) (string, *tls.Config, error) {
	switch mode := u.Query().Get("tls"); mode {
	case "", "0":
		logger.Warn("TLS code-0: unencrypted")
		return "0", nil, nil
	case "1":
		cfg, err := generate()
		if err != nil {
			return "", nil, fmt.Errorf("TLS mode 1: certificate generation failed: %w", err)
		}
		cfg.MinVersion = tls.VersionTLS13
		logger.Info("TLS code-1: RAM cert with TLS 1.3")
		return "1", cfg, nil
	case "2":
		crt, key := u.Query().Get("crt"), u.Query().Get("key")
		if crt == "" || key == "" {
			return "", nil, fmt.Errorf("TLS mode 2: both crt and key are required")
		}
		cert, err := load(crt, key)
		if err != nil {
			return "", nil, fmt.Errorf("TLS mode 2: certificate load failed: %w", err)
		}
		// Published certificate objects are immutable. Serialize reload attempts and
		// publish a new pointer only after a complete pair has loaded successfully.
		var mu sync.Mutex
		cached := &cert
		lastReload := time.Now()
		cfg := &tls.Config{MinVersion: tls.VersionTLS13}
		cfg.GetCertificate = func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			defer mu.Unlock()
			if time.Since(lastReload) >= common.ReloadInterval {
				next, err := load(crt, key)
				if err != nil {
					logger.Error("Certificate reload failed; retaining previous certificate: %v", err)
				} else {
					cached = &next
					logger.Debug("TLS cert reloaded")
				}
				lastReload = time.Now()
			}
			return cached, nil
		}
		logger.Info("TLS code-2: file certificate with TLS 1.3")
		return "2", cfg, nil
	default:
		return "", nil, fmt.Errorf("invalid TLS mode: expected 0, 1 or 2")
	}
}
