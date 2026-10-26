package websocket

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Real TLS handshakes/HTTP requests are held before upgrade so simultaneous
// createConnection calls remain observable without changing production code.
func TestClientManagerBoundsConcurrentDials(t *testing.T) {
	var active, peak atomic.Int32
	release := make(chan struct{})
	released := false
	ready := make(chan struct{}, 16)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		ready <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		http.Error(w, "controlled dial gate", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	p := NewClientPool(16, 16, time.Second, time.Second, time.Second, "1", strings.TrimPrefix(srv.URL, "https://"))
	done := make(chan struct{})
	go func() { defer close(done); p.ClientManager() }()
	defer func() {
		p.Close()
		if !released {
			close(release)
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("manager did not cancel gated dials")
		}
	}()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for range 4 {
		select {
		case <-ready:
		case <-deadline.C:
			t.Fatal("four actual TLS requests did not reach gate")
		}
	}
	// A fifth arrival proves over-admission; otherwise the four slots stay held.
	select {
	case <-ready:
		t.Fatalf("DIAL-LIMIT: fifth simultaneous TLS request; peak=%d", peak.Load())
	case <-time.After(500 * time.Millisecond):
	}
	if peak.Load() != 4 {
		t.Fatalf("DIAL-LIMIT: peak=%d want4", peak.Load())
	}
	close(release)
	// Permit the remaining twelve queued attempts to run, rather than silently
	// reducing configured capacity or dropping the rest of the batch.
	released = true
	for range 12 {
		select {
		case <-ready:
		case <-time.After(5 * time.Second):
			t.Fatal("batch deficit was not fully attempted")
		}
	}
}
