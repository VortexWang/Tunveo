package tcp

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	idlequeue "github.com/VortexWang/Tunveo/internal/tunnelpool/idle"
)

func TestPoolMatchingClaimAndCanceledGet(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Pool{idle: idlequeue.New[net.Conn](2), ctx: ctx, cancel: cancel}
	a, remoteA := net.Pipe()
	b, remoteB := net.Pipe()
	defer a.Close()
	defer b.Close()
	defer remoteA.Close()
	defer remoteB.Close()
	if !p.idle.Publish(ctx, "a", a) || !p.idle.Publish(ctx, "b", b) {
		t.Fatal("publish")
	}
	got, err := p.OutgoingGet("b", time.Second)
	if err != nil || got != b {
		t.Fatal("wrong specific connection")
	}
	id, got, err := p.IncomingGet(time.Second)
	if err != nil || id != "a" || got != a || p.Active() != 0 {
		t.Fatal("other ID's notification lost")
	}
	cancel()
	if _, err := p.OutgoingGet("missing", time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatal("get did not cancel", err)
	}
}

func TestFlushClosesOnlyIdleOwnership(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Pool{idle: idlequeue.New[net.Conn](2), ctx: ctx, cancel: cancel}
	leased, r1 := net.Pipe()
	idle, r2 := net.Pipe()
	defer leased.Close()
	defer r1.Close()
	defer r2.Close()
	p.idle.Publish(ctx, "lease", leased)
	p.idle.Publish(ctx, "idle", idle)
	got, err := p.OutgoingGet("lease", time.Second)
	if err != nil || got != leased {
		t.Fatal(err)
	}
	p.Flush()
	if p.Active() != 0 {
		t.Fatal("idle not cleared")
	}
	if _, err := idle.Write([]byte("x")); !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("idle connection not closed", err)
	}
	// A claimed connection is owned by the caller, not by Flush.
	wrote := make(chan error, 1)
	go func() {
		leased.SetWriteDeadline(time.Now().Add(time.Second))
		_, err := leased.Write([]byte("x"))
		wrote <- err
	}()
	var data [1]byte
	r1.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := r1.Read(data[:]); err != nil {
		t.Fatal("lease closed by Flush", err)
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
}
