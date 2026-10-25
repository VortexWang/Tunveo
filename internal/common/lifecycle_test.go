package common

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestFreshRunsDoNotShareMutableRuntime(t *testing.T) {
	parent := NewCommonPtr(NewLogger(None, false), nil)
	defer parent.Cancel()
	first, second := parent.FreshRun(), parent.FreshRun()
	defer first.Stop()
	defer second.Stop()
	if first.Ctx == second.Ctx || first.WriteChan == second.WriteChan || first.SignalChan == second.SignalChan || first.VerifyChan == second.VerifyChan {
		t.Fatal("runtime identity shared")
	}
	if first.Stats != second.Stats || first.Buffers != second.Buffers {
		t.Fatal("cumulative statistics/buffer ownership changed")
	}
	a, b := net.Pipe()
	defer b.Close()
	secondConn := second.bindRunConn(a)
	defer secondConn.Close()
	first.TargetUDPSession.Store("old", io.NopCloser(nil))
	first.Stop()
	if second.Ctx.Err() != nil {
		t.Fatal("old Stop canceled new run")
	}
	// A full old control queue must not retain a canceled writer.
	first.WriteChan = make(chan []byte)
	done := make(chan bool, 1)
	go func() { done <- first.queueWrite([]byte("stale")) }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("stale write")
		}
	case <-time.After(time.Second):
		t.Fatal("writer did not cancel")
	}
	written := make(chan error, 1)
	go func() {
		secondConn.SetWriteDeadline(time.Now().Add(time.Second))
		_, err := secondConn.Write([]byte("x"))
		written <- err
	}()
	b.SetReadDeadline(time.Now().Add(time.Second))
	var buf [1]byte
	if _, err := b.Read(buf[:]); err != nil {
		t.Fatal("old Stop closed new connection", err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	second.Stop()
	if _, err := secondConn.Write([]byte("x")); err != io.ErrClosedPipe {
		t.Fatal("new run connection leaked", err)
	}
}

func TestDrainClosedChannelTerminates(t *testing.T) {
	ch := make(chan int, 1)
	ch <- 1
	close(ch)
	done := make(chan struct{})
	go func() { Drain(ch); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("closed drain spun")
	}
}

func TestRunQueueCancellation(t *testing.T) {
	c := NewCommonPtr(NewLogger(None, false), nil)
	c.WriteChan = make(chan []byte)
	c.Cancel()
	if c.queueWrite(nil) || c.Ctx.Err() != context.Canceled {
		t.Fatal("canceled run queued data")
	}
}
