package quic

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/VortexWang/Tunveo/internal/common"
	quicgo "github.com/quic-go/quic-go"
)

// Use accepted real QUIC connections: closing an idle listener alone does not
// exercise quic-go's delayed closed-connection handler/socket lifetime.
func TestCloseReleasesUDPAddressWithAcceptedConnection(t *testing.T) {
	cfg, err := common.NewTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	p := NewServerPool(8, "", cfg, "127.0.0.1:0", time.Second)
	defer p.Close()
	if err = p.startListener(); err != nil {
		t.Fatal(err)
	}
	addr := p.quicListener.Load().Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	peerCh := make(chan error, 1)
	go func() {
		c, e := quicgo.DialAddr(ctx, addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{defaultALPN}}, nil)
		if e == nil {
			defer c.CloseWithError(0, "fixture")
			<-ctx.Done()
		}
		peerCh <- e
	}()
	accepted, err := p.quicListener.Load().Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.life.Track(lifetimeCloser(func() error { return accepted.CloseWithError(0, "pool closed") })); !ok {
		t.Fatal("not tracked")
	}
	start := time.Now()
	p.Close()
	if time.Since(start) > time.Second {
		t.Fatal("Close exceeded one second")
	}
	replacement, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("Close returned before UDP port release: %v", err)
	}
	replacement.Close()
	cancel()
	if err = <-peerCh; err != nil {
		t.Fatal(err)
	}
}

type lifetimeCloser func() error

func (f lifetimeCloser) Close() error { return f() }
