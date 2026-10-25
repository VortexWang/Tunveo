package master

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestManagementAuthAllRoutes(t *testing.T) {
	m := boundaryMaster()
	m.Instances.Store(APIKeyID, &Instance{ID: APIKeyID, URL: "fixture-key"})
	h := m.Handler()
	for _, path := range []string{"/api/v1/instances", "/api/v1/instances/absent", "/api/v1/info", "/api/v1/tcping", "/api/v1/events", "/api/v2"} {
		for _, kind := range []string{"missing", "wrong", "duplicate"} {
			r := httptest.NewRequest("GET", path, nil)
			if kind != "missing" {
				r.Header.Set("X-API-Key", "wrong")
			}
			if kind == "duplicate" {
				r.Header.Add("X-API-Key", "fixture-key")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 401 {
				t.Fatal(path, kind, w.Code)
			}
		}
	}
	for _, path := range []string{"/api/v1/docs", "/api/v1/openapi.json"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatal(path, w.Code)
		}
	}
}
func TestManagementAdmissionReturnsImmediately(t *testing.T) {
	m := boundaryMaster()
	m.Instances.Store(APIKeyID, &Instance{ID: APIKeyID, URL: "fixture-key"})
	entered := make(chan struct{}, ManagementRequestLimit)
	release := make(chan struct{})
	h := m.protected(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-release }, false)
	req := func() *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("X-API-Key", "fixture-key")
		return r
	}
	var wg sync.WaitGroup
	for range ManagementRequestLimit {
		wg.Go(func() { h.ServeHTTP(httptest.NewRecorder(), req()) })
	}
	for range ManagementRequestLimit {
		<-entered
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req())
	if w.Code != 429 {
		t.Fatal(w.Code)
	}
	close(release)
	wg.Wait()
	if len(m.admission) != 0 {
		t.Fatal("permits leaked")
	}
}
func TestManagementSSECapacityAndPublicationRetirement(t *testing.T) {
	m := boundaryMaster()
	m.Instances.Store(APIKeyID, &Instance{ID: APIKeyID, URL: "fixture-key"})
	dispatcherDone := make(chan struct{})
	go func() { m.StartEventDispatcher(); close(dispatcherDone) }()
	h := m.Handler()
	var handlers sync.WaitGroup
	for range ManagementSSELimit {
		r := httptest.NewRequest("GET", "/api/v1/events", nil)
		r.Header.Set("X-API-Key", "fixture-key")
		w := &boundarySSEWriter{header: http.Header{}, flushed: make(chan struct{})}
		handlers.Go(func() { h.ServeHTTP(w, r) })
		<-w.flushed
	}
	r := httptest.NewRequest("GET", "/api/v1/events", nil)
	r.Header.Set("X-API-Key", "fixture-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatal(w.Code)
	}
	var writers sync.WaitGroup
	for range 8 {
		writers.Go(func() {
			for range 100 {
				m.SendSSEEvent("update", &Instance{ID: "immutable-fixture"})
			}
		})
	}
	for range 8 {
		writers.Go(m.ShutdownSSEConnections)
	}
	writers.Wait()
	handlers.Wait()
	m.sseMu.Lock()
	count := m.sseCount
	m.sseMu.Unlock()
	if count != 0 {
		t.Fatal("subscriptions leaked")
	}
	m.eventMu.Lock()
	m.eventsClosed = true
	close(m.NotifyChannel)
	m.eventMu.Unlock()
	<-dispatcherDone
	m.SendSSEEvent("late", nil)
}
func TestManagementRotationUsesImmutableCredential(t *testing.T) {
	m := boundaryMaster()
	m.StatePath = filepath.Join(t.TempDir(), "state.gob")
	old := &Instance{ID: APIKeyID, URL: "fixture-key"}
	m.Instances.Store(APIKeyID, old)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 100 {
				r := httptest.NewRequest("GET", "/api/v1/instances", nil)
				r.Header.Set("X-API-Key", "fixture-key")
				w := httptest.NewRecorder()
				m.Handler().ServeHTTP(w, r)
			}
		})
	}
	next := m.ReGenerateAPIKey(old)
	workers.Wait()
	if old.URL != "fixture-key" || next.URL == old.URL {
		t.Fatal("rotation mutated shared credential")
	}
	r := httptest.NewRequest("GET", "/api/v1/instances", nil)
	r.Header.Set("X-API-Key", next.URL)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	// Observe the asynchronous atomic rename before TempDir cleanup.
	deadline := time.Now().Add(time.Second)
	for {
		key, err := ReadAPIKey(m.StatePath)
		if err == nil && key == next.URL {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("key not persisted", err)
		}
		time.Sleep(time.Millisecond)
	}
}
func TestManagementSSEWriteErrorRetiresSubscription(t *testing.T) {
	m := boundaryMaster()
	m.Instances.Store(APIKeyID, &Instance{ID: APIKeyID, URL: "fixture-key"})
	r := httptest.NewRequest("GET", "/api/v1/events", nil)
	r.Header.Set("X-API-Key", "fixture-key")
	w := &failedSSEWriter{header: http.Header{}}
	m.Handler().ServeHTTP(w, r)
	if m.sseCount != 0 {
		t.Fatal("failed write leaked subscription")
	}
}

type failedSSEWriter struct{ header http.Header }

func (w *failedSSEWriter) Header() http.Header       { return w.header }
func (w *failedSSEWriter) WriteHeader(int)           {}
func (w *failedSSEWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (w *failedSSEWriter) Flush()                    {}
func TestManagementHTTPServerLimitsAndNormalMCP(t *testing.T) {
	m := boundaryMaster()
	m.TunnelTCPAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
	server := m.managementServer()
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.IdleTimeout <= 0 || server.MaxHeaderBytes != ManagementHeaderLimit || server.WriteTimeout != 0 {
		t.Fatal("HTTP limits invalid for SSE")
	}
	m.Instances.Store(APIKeyID, &Instance{ID: APIKeyID, URL: "fixture-key"})
	ts := httptest.NewServer(m.Handler())
	defer ts.Close()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", ts.URL+"/api/v2", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	req.Header.Set("X-API-Key", "fixture-key")
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	var result map[string]any
	if e = json.NewDecoder(resp.Body).Decode(&result); e != nil || result["result"] == nil {
		t.Fatal(e, result)
	}
}

type deadlineRecordingSSE struct {
	*boundarySSEWriter
	until time.Time
}

func (w *deadlineRecordingSSE) SetWriteDeadline(t time.Time) error { w.until = t; return nil }
func TestManagementSSEClearsFrameDeadline(t *testing.T) {
	m := boundaryMaster()
	m.Instances.Store(APIKeyID, &Instance{ID: APIKeyID, URL: "fixture-key"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest("GET", "/api/v1/events", nil).WithContext(ctx)
	r.Header.Set("X-API-Key", "fixture-key")
	w := &deadlineRecordingSSE{boundarySSEWriter: &boundarySSEWriter{header: http.Header{}, flushed: make(chan struct{})}}
	done := make(chan struct{})
	go func() { m.Handler().ServeHTTP(w, r); close(done) }()
	<-w.flushed
	cancel()
	<-done
	if !w.until.IsZero() {
		t.Fatal("frame deadline left active while idle")
	}
}

func TestManagementSSERejectsBodiesBeforeReading(t *testing.T) {
	m := boundaryMaster()
	m.Instances.Store(APIKeyID, &Instance{ID: APIKeyID, URL: "fixture-key"})
	for _, method := range []string{"GET", "POST"} {
		r := httptest.NewRequest(method, "/api/v1/events", nil)
		r.ContentLength = -1
		r.TransferEncoding = []string{"chunked"}
		r.Body = unreadableBoundaryBody{}
		r.Header.Set("X-API-Key", "fixture-key")
		w := httptest.NewRecorder()
		m.Handler().ServeHTTP(w, r)
		expected := 400
		if method == "POST" {
			expected = 405
		}
		if w.Code != expected {
			t.Fatal(w.Code)
		}
	}
}

type unreadableBoundaryBody struct{}

func (unreadableBoundaryBody) Read([]byte) (int, error) {
	panic("SSE request body was read before admission")
}
func (unreadableBoundaryBody) Close() error { return nil }
