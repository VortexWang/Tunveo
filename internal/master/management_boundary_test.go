package master

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/VortexWang/Tunveo/internal/common"
)

var expectManagementFailure = false

func boundaryMaster() *Master {
	return &Master{Common: common.NewCommon(common.NewLogger(common.None, false), nil), Prefix: "/api/v1", NotifyChannel: make(chan *InstanceEvent, 16), TCPingSem: make(chan struct{}, 10)}
}
func boundaryResult(t *testing.T, name string, broken bool) {
	t.Helper()
	if expectManagementFailure {
		if !broken {
			t.Fatal("expected defect", name)
		}
		t.Log("REPRODUCED-" + name + ":")
		return
	}
	if broken {
		t.Fatal("boundary regression", name)
	}
	t.Log("PASSED-" + name + ":")
}
func TestManagementMissingKeyFailsClosed(t *testing.T) {
	for _, empty := range []bool{false, true} {
		m := boundaryMaster()
		if empty {
			m.Instances.Store(APIKeyID, &Instance{ID: APIKeyID})
		}
		r := httptest.NewRequest("GET", "/api/v1/instances", nil)
		w := httptest.NewRecorder()
		fixtureManagementHandler(m).ServeHTTP(w, r)
		boundaryResult(t, "AUTH", w.Code != http.StatusServiceUnavailable)
	}
}
func TestManagementBodyLimit(t *testing.T) {
	m := boundaryMaster()
	m.Instances.Store(APIKeyID, &Instance{ID: APIKeyID, URL: "synthetic-management-key"})
	data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "padding": strings.Repeat("x", (1<<20)+1)})
	for _, chunked := range []bool{false, true} {
		r := httptest.NewRequest("POST", "/api/v2", strings.NewReader(string(data)))
		if chunked {
			r.ContentLength = -1
		}
		r.Header.Set("X-API-Key", "synthetic-management-key")
		w := httptest.NewRecorder()
		fixtureManagementHandler(m).ServeHTTP(w, r)
		boundaryResult(t, "BODY", w.Code != http.StatusRequestEntityTooLarge)
	}
}
func TestManagementTrailingJSONRejected(t *testing.T) {
	m := boundaryMaster()
	m.Instances.Store(APIKeyID, &Instance{ID: APIKeyID, URL: "synthetic-management-key"})
	r := httptest.NewRequest("POST", "/api/v2", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"} {}`))
	r.Header.Set("X-API-Key", "synthetic-management-key")
	w := httptest.NewRecorder()
	fixtureManagementHandler(m).ServeHTTP(w, r)
	boundaryResult(t, "TRAILING", !strings.Contains(w.Body.String(), `"error"`))
}

type boundarySSEWriter struct {
	mu      sync.Mutex
	header  http.Header
	data    strings.Builder
	flushed chan struct{}
	once    sync.Once
}

func (w *boundarySSEWriter) Header() http.Header { return w.header }
func (w *boundarySSEWriter) WriteHeader(int)     {}
func (w *boundarySSEWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.data.Write(b)
}
func (w *boundarySSEWriter) Flush() { w.once.Do(func() { close(w.flushed) }) }
func TestManagementSSEOmitsAPIKey(t *testing.T) {
	m := boundaryMaster()
	m.Instances.Store(APIKeyID, &Instance{ID: APIKeyID, URL: "synthetic-management-key"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest("GET", "/api/v1/events", nil).WithContext(ctx)
	r.Header.Set("X-API-Key", "synthetic-management-key")
	w := &boundarySSEWriter{header: http.Header{}, flushed: make(chan struct{})}
	done := make(chan struct{})
	go func() { fixtureManagementHandler(m).ServeHTTP(w, r); close(done) }()
	select {
	case <-w.flushed:
	case <-time.After(time.Second):
		t.Fatal("no SSE flush")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SSE did not stop")
	}
	w.mu.Lock()
	leaked := strings.Contains(w.data.String(), "synthetic-management-key")
	w.mu.Unlock()
	boundaryResult(t, "SSEKEY", leaked)
}
func TestManagementCanceledPingStopsWaiting(t *testing.T) {
	m := boundaryMaster()
	for range cap(m.TCPingSem) {
		m.TCPingSem <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	fixtureManagementPing(m, ctx, "127.0.0.1:1")
	boundaryResult(t, "CANCEL", time.Since(start) > 300*time.Millisecond)
}

var _ io.Writer = (*boundarySSEWriter)(nil)
