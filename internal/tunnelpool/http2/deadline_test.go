package http2

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// Only this expectation changes when the identical fixture runs on the parent.
var expectDeadlineFailure = false

type countingListener struct {
	net.Listener
	accepts atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e == nil {
		l.accepts.Add(1)
	}
	return c, e
}

func twoStreams(t *testing.T) (*Pool, *Pool, [2]net.Conn, [2]net.Conn, *countingListener) {
	t.Helper()
	certServer := httptest.NewTLSServer(nil)
	cfg := certServer.TLS.Clone()
	certServer.Close()
	raw, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	listener := &countingListener{Listener: raw}
	server := NewServerPool(8, "", cfg, listener, time.Second*30)
	client := NewClientPool(2, 8, time.Second, time.Second, 30*time.Second, "1", "localhost", func() (string, error) { return listener.Addr().String(), nil })
	t.Cleanup(server.Close)
	t.Cleanup(client.Close)
	go server.ServerManager()
	if e = client.establishConnection(); e != nil {
		t.Fatal(e)
	}
	var cc, sc [2]net.Conn
	for i := range 2 {
		if !client.createStream() {
			t.Fatal("create stream")
		}
		id, c, e := client.IncomingGet(time.Second)
		if e != nil {
			t.Fatal(e)
		}
		cc[i] = c
		sc[i], e = server.OutgoingGet(id, time.Second)
		if e != nil {
			t.Fatal(e)
		}
	}
	if cc[0].(*StreamConn).conn != cc[1].(*StreamConn).conn || sc[0].(*StreamConn).conn != sc[1].(*StreamConn).conn || listener.accepts.Load() != 1 {
		t.Fatal("streams do not share one physical connection")
	}
	return client, server, cc, sc, listener
}

// Limits a test observation by closing its endpoints, without changing deadlines.
func transfer(from, to net.Conn, payload []byte) error {
	timer := time.AfterFunc(time.Second, func() { from.Close(); to.Close() })
	defer timer.Stop()
	written := make(chan error, 1)
	go func() {
		n, e := from.Write(payload)
		if e == nil && n != len(payload) {
			e = io.ErrShortWrite
		}
		written <- e
	}()
	got := make([]byte, len(payload))
	_, e := io.ReadFull(to, got)
	w := <-written
	if e != nil {
		return e
	}
	if w != nil {
		return w
	}
	if !bytes.Equal(payload, got) {
		return fmt.Errorf("payload differs")
	}
	return nil
}
func siblingAlive(c, s net.Conn) error {
	if e := transfer(c, s, []byte("request")); e != nil {
		return e
	}
	return transfer(s, c, []byte("response"))
}

func TestH2ReadDeadlineIsolation(t *testing.T) {
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			_, _, cc, sc, l := twoStreams(t)
			a, peer := cc[0], sc[0]
			if side == "server" {
				a, peer = peer, a
			}
			result := make(chan error, 1)
			go func() { var b [1]byte; _, e := a.Read(b[:]); result <- e }()
			if e := a.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); e != nil {
				t.Fatal(e)
			}
			var readErr error
			select {
			case readErr = <-result:
			case <-time.After(time.Second):
				t.Fatal("read deadline did not interrupt pending read")
			}
			siblingErr := siblingAlive(cc[1], sc[1])
			if expectDeadlineFailure {
				if siblingErr == nil {
					t.Fatal("expected shared-connection deadline failure")
				}
				t.Log("REPRODUCED-READ:", side, siblingErr)
				return
			}
			if !errors.Is(readErr, os.ErrDeadlineExceeded) {
				t.Fatalf("read timeout: %v", readErr)
			}
			if siblingErr != nil {
				t.Fatal("sibling failed", siblingErr)
			}
			if e := a.SetReadDeadline(time.Time{}); e != nil {
				t.Fatal(e)
			}
			if e := transfer(peer, a, []byte("resume")); e != nil {
				t.Fatal("expired read could not resume", e)
			}
			if l.accepts.Load() != 1 {
				t.Fatal("physical connection replaced")
			}
			t.Log("PASSED-READ:", side)
		})
	}
}

func TestH2WriteDeadlineIsolation(t *testing.T) {
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			_, _, cc, sc, l := twoStreams(t)
			a, peer := cc[0], sc[0]
			if side == "server" {
				a, peer = peer, a
			}
			type result struct {
				n   int
				err error
			}
			done := make(chan result, 1)
			// No peer reads: exceed HTTP/2 flow control and the adapter's bounded staging.
			go func() { n, e := a.Write(bytes.Repeat([]byte("x"), 16<<20)); done <- result{n, e} }()
			if e := a.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); e != nil {
				t.Fatal(e)
			}
			var r result
			select {
			case r = <-done:
			case <-time.After(3 * time.Second):
				if expectDeadlineFailure {
					a.Close()
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Fatal("close did not release old write")
					}
					t.Log("REPRODUCED-WRITE:", side, "deadline did not interrupt flow-controlled write")
					return
				}
				t.Fatal("write deadline did not interrupt blocked write")
			}
			// A stalled upload may exhaust the shared connection's flow-control
			// window. Observe the independent direction before draining A;
			// verify full duplex B after releasing that existing backpressure.
			var siblingErr error
			if side == "client" {
				siblingErr = transfer(sc[1], cc[1], []byte("response"))
			} else {
				siblingErr = transfer(cc[1], sc[1], []byte("request"))
			}
			if expectDeadlineFailure {
				if siblingErr == nil {
					t.Fatal("expected shared-connection deadline failure")
				}
				t.Log("REPRODUCED-WRITE:", side, siblingErr)
				return
			}
			if !errors.Is(r.err, os.ErrDeadlineExceeded) || r.n <= 0 || r.n >= 16<<20 {
				t.Fatalf("write timeout/count: %d %v", r.n, r.err)
			}
			if siblingErr != nil {
				t.Fatal("sibling failed", siblingErr)
			}
			if e := a.SetWriteDeadline(time.Time{}); e != nil {
				t.Fatal(e)
			}
			drained := make(chan error, 1)
			go func() { _, e := io.CopyN(io.Discard, peer, int64(r.n)); drained <- e }()
			select {
			case e := <-drained:
				if e != nil {
					t.Fatal(e)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("accepted write bytes lost")
			}
			if e := transfer(a, peer, []byte("resume")); e != nil {
				t.Fatal("expired write could not resume", e)
			}
			if l.accepts.Load() != 1 {
				t.Fatal("physical connection replaced")
			}
			if e := siblingAlive(cc[1], sc[1]); e != nil {
				t.Fatal("sibling after drain", e)
			}
			t.Log("PASSED-WRITE:", side)
		})
	}
}
