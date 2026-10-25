package master

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	ManagementBodyLimit    = 1 << 20
	ManagementRequestLimit = 32
	ManagementSSELimit     = 32
	ManagementHeaderLimit  = 32 << 10
	ManagementBodyTimeout  = 10 * time.Second
	ManagementWriteTimeout = 5 * time.Second
	ManagementHeartbeat    = 15 * time.Second
)

// Handler is shared by the real server and tests. Authentication fails closed
// when persisted credentials disappear; no handler is reached in that state.
func (m *Master) Handler() http.Handler {
	mux := http.NewServeMux()
	protected := map[string]http.HandlerFunc{
		m.Prefix + "/instances": m.HandleInstances, m.Prefix + "/instances/": m.HandleInstanceDetail,
		m.Prefix + "/events": m.HandleSSE, m.Prefix + "/info": m.HandleInfo, m.Prefix + "/tcping": m.HandleTCPing,
		strings.TrimSuffix(m.Prefix, "/"+OpenAPIVersion) + "/" + NextMCPVersion: m.HandleMCP,
	}
	for path, h := range protected {
		sse := path == m.Prefix+"/events"
		if !sse {
			h = m.serialized(h)
		}
		mux.Handle(path, m.protected(h, sse))
	}
	for path, h := range map[string]http.HandlerFunc{m.Prefix + "/docs": m.HandleSwaggerUI, m.Prefix + "/openapi.json": m.HandleOpenAPISpec} {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			SetCorsHeaders(w)
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}
			h(w, r)
		})
	}
	return mux
}
func (m *Master) credentialStatus(r *http.Request) int {
	key, ok := m.findInstanceLocked(APIKeyID)
	if !ok || key == nil || key.URL == "" {
		return http.StatusServiceUnavailable
	}
	values := r.Header.Values("X-API-Key")
	if len(values) != 1 || values[0] == "" || subtle.ConstantTimeCompare([]byte(values[0]), []byte(key.URL)) != 1 {
		return http.StatusUnauthorized
	}
	return 0
}
func (m *Master) protected(next http.HandlerFunc, sse bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetCorsHeaders(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		if m.managementStopped.Load() {
			HTTPError(w, "Management is stopping", http.StatusServiceUnavailable)
			return
		}
		m.keyMu.RLock()
		status := m.credentialStatus(r)
		m.keyMu.RUnlock()
		if status != 0 {
			HTTPError(w, "Management authentication unavailable or invalid", status)
			return
		}
		if sse {
			if r.Method != http.MethodGet {
				HTTPError(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
				HTTPError(w, "SSE requests must not contain a body", http.StatusBadRequest)
				return
			}
		}
		if !sse {
			m.admissionOnce.Do(func() { m.admission = make(chan struct{}, ManagementRequestLimit) })
			select {
			case m.admission <- struct{}{}:
				defer func() { <-m.admission }()
			default:
				w.Header().Set("Retry-After", "1")
				HTTPError(w, "Too many management requests", http.StatusTooManyRequests)
				return
			}
		}
		if r.ContentLength > ManagementBodyLimit {
			HTTPError(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		if !sse && r.Body != nil && r.Body != http.NoBody {
			controller := http.NewResponseController(w)
			controller.SetReadDeadline(time.Now().Add(ManagementBodyTimeout))
			body := http.MaxBytesReader(w, r.Body, ManagementBodyLimit)
			data, err := io.ReadAll(body)
			body.Close()
			controller.SetReadDeadline(time.Time{})
			if err != nil {
				var large *http.MaxBytesError
				var timeout net.Error
				code := http.StatusBadRequest
				if errors.As(err, &large) {
					code = http.StatusRequestEntityTooLarge
				} else if errors.As(err, &timeout) && timeout.Timeout() {
					code = http.StatusRequestTimeout
				}
				HTTPError(w, "Invalid or incomplete request body", code)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(data))
		}
		if !sse {
			http.NewResponseController(w).SetWriteDeadline(time.Now().Add(ManagementWriteTimeout))
		}
		next(w, r)
	})
}

// Consume exactly one JSON value before any mutation/tool dispatch.
func decodeManagementJSON(r io.Reader, v any) error {
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("request must contain one JSON value")
	}
	return nil
}
func (m *Master) managementServer() *http.Server {
	return &http.Server{Addr: m.TunnelTCPAddr.String(), ErrorLog: m.Logger.StdLogger(), Handler: m.Handler(), TLSConfig: m.MTLSConfig,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: ManagementHeaderLimit}
}
