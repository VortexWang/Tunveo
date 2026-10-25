package lifetime

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

func TestPermanentCloseOwnsLateAndLeasedResources(t *testing.T) {
	g := New()
	if !g.Start() || g.Start() {
		t.Fatal("manager started twice")
	}
	a, b := net.Pipe()
	defer b.Close()
	leased, ok := g.Bind(a, nil)
	if !ok {
		t.Fatal("bind")
	}
	var closes atomic.Int32
	g.Track(CloserFunc(func() error { closes.Add(1); return nil }))
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(g.Close)
	}
	wg.Wait()
	if closes.Load() != 1 || g.Context().Err() != context.Canceled || g.Start() {
		t.Fatal("close resurrected")
	}
	if _, err := leased.Write([]byte("x")); err != io.ErrClosedPipe {
		t.Fatal("lease not closed", err)
	}
	if _, ok := g.Track(CloserFunc(func() error { closes.Add(1); return nil })); ok || closes.Load() != 2 {
		t.Fatal("late resource leaked")
	}
}
