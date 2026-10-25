package http2

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	idlequeue "github.com/VortexWang/Tunveo/internal/tunnelpool/idle"
)

type blockedResponse struct {
	entered, abort chan struct{}
	once           sync.Once
}

func (w *blockedResponse) Header() http.Header { return http.Header{} }
func (w *blockedResponse) WriteHeader(int)     {}
func (w *blockedResponse) Write([]byte) (int, error) {
	close(w.entered)
	<-w.abort
	return 0, io.ErrClosedPipe
}
func (w *blockedResponse) SetWriteDeadline(time.Time) error {
	w.once.Do(func() { close(w.abort) })
	return nil
}
func TestResponseCloseJoinsWriterBeforeHandlerReturns(t *testing.T) {
	raw := &blockedResponse{entered: make(chan struct{}), abort: make(chan struct{})}
	w := &responseWriter{rw: raw}
	written := make(chan error, 1)
	go func() { _, err := w.Write([]byte("x")); written <- err }()
	<-raw.entered
	closed := make(chan struct{})
	go func() { w.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("stream close stuck behind write")
	}
	if err := <-written; err != io.ErrClosedPipe {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("late")); err != io.ErrClosedPipe {
		t.Fatal("late response writer touched handler", err)
	}
}
func TestStreamKeepsOriginalPhysicalConnection(t *testing.T) {
	first, peer := net.Pipe()
	defer first.Close()
	defer peer.Close()
	second, other := net.Pipe()
	defer second.Close()
	defer other.Close()
	p := &Pool{idle: idlequeue.New[net.Conn](1), ctx: context.Background()}
	owned := &StreamConn{conn: first, localAddr: first.LocalAddr(), remoteAddr: first.RemoteAddr()}
	p.idle.Publish(p.ctx, "one", owned)
	p.session.Store(&h2Session{conn: second})
	got, err := p.OutgoingGet("one", time.Second)
	if err != nil || got != owned || got.(*StreamConn).conn != first {
		t.Fatal("stream rebound to latest physical connection", err)
	}
}

func TestPeerCloseKeepsIdleIDForDelayedControlClaim(t *testing.T) {
	physical, other := net.Pipe()
	defer physical.Close()
	defer other.Close()
	p := &Pool{idle: idlequeue.New[net.Conn](1), ctx: context.Background(), maxCap: 1}
	peer, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest("POST", "https://localhost/stream", strings.NewReader("x"))
	req = req.WithContext(context.WithValue(peer, connectionKey{}, physical))
	done := make(chan struct{})
	go func() { p.handleStream(httptest.NewRecorder(), req); close(done) }()
	deadline := time.Now().Add(time.Second)
	for p.Active() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("no published stream")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not finish")
	}
	if p.Active() != 1 {
		t.Fatal("peer Close removed ID before control claim")
	}
	conn, err := p.OutgoingGet("00000000", time.Second)
	if err != nil || conn == nil {
		t.Fatal("delayed control claim lost", err)
	}
	conn.Close()
}
