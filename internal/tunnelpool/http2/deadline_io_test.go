package http2

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestDeadlineIOExtensionAndReset(t *testing.T) {
	raw, peer := net.Pipe()
	s := newDeadlineIO(raw)
	defer s.Close()
	defer peer.Close()
	if e := s.SetDeadline(time.Now().Add(-time.Second)); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Read(make([]byte, 1)); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal(e)
	}
	if _, e := s.Write([]byte("x")); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal(e)
	}
	if e := s.SetDeadline(time.Time{}); e != nil {
		t.Fatal(e)
	}
	got := make(chan error, 1)
	go func() { _, e := s.Read(make([]byte, 1)); got <- e }()
	// Replacing a deadline must not leave an old timer that aborts the stream.
	s.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	s.SetReadDeadline(time.Now().Add(time.Second))
	select {
	case e := <-got:
		t.Fatal("old deadline fired", e)
	case <-time.After(40 * time.Millisecond):
	}
	go peer.Write([]byte("y"))
	if e := <-got; e != nil {
		t.Fatal(e)
	}
	s.Close()
	if e := s.SetDeadline(time.Time{}); e == nil {
		t.Fatal("deadline on closed stream succeeded")
	}
}

func TestDeadlineIOCloseJoinsBlockedPumps(t *testing.T) {
	raw, peer := net.Pipe()
	s := newDeadlineIO(raw)
	defer peer.Close()
	readDone, writeDone := make(chan struct{}), make(chan struct{})
	go func() { s.Read(make([]byte, 1)); close(readDone) }()
	go func() { s.Write(make([]byte, 1<<20)); close(writeDone) }()
	// A successful one-byte upstream read proves the write pump is blocked in raw I/O.
	if _, e := io.ReadFull(peer, make([]byte, 1)); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { s.Close() })
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	for _, c := range []chan struct{}{readDone, writeDone, done} {
		select {
		case <-c:
		case <-time.After(time.Second):
			t.Fatal("close did not join pumps/callers")
		}
	}
}

func TestH2CloseAndCancelIsolation(t *testing.T) {
	for _, op := range []string{"close-client", "close-server", "cancel-request"} {
		t.Run(op, func(t *testing.T) {
			_, _, cc, sc, l := twoStreams(t)
			a := cc[0]
			if op == "close-server" {
				a = sc[0]
			}
			readDone := make(chan error, 1)
			go func() { _, e := a.Read(make([]byte, 1)); readDone <- e }()
			if op == "cancel-request" {
				cc[0].(*StreamConn).ReadWriteCloser.(*deadlineIO).raw.(*http2Stream).cancel()
			} else {
				a.Close()
			}
			select {
			case e := <-readDone:
				if e == nil {
					t.Fatal("pending read returned no error")
				}
			case <-time.After(time.Second):
				t.Fatal("read not released")
			}
			if e := siblingAlive(cc[1], sc[1]); e != nil {
				t.Fatal("sibling failed", e)
			}
			if l.accepts.Load() != 1 {
				t.Fatal("physical connection replaced")
			}
		})
	}
}

func TestDeadlineIOSuccessfulWriteFinishesBeforeClose(t *testing.T) {
	raw, peer := net.Pipe()
	s := newDeadlineIO(raw)
	defer s.Close()
	defer peer.Close()
	written := make(chan error, 1)
	go func() { _, err := s.Write([]byte("ack")); written <- err }()
	select {
	case err := <-written:
		t.Fatal("successful Write returned before upstream accepted ACK", err)
	case <-time.After(20 * time.Millisecond):
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	s.Close()
	if string(buf) != "ack" {
		t.Fatal("ACK lost before immediate close")
	}
}
