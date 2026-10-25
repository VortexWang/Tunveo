package quic

import (
	"context"
	"net"
	"testing"
	"time"

	idlequeue "github.com/VortexWang/Tunveo/internal/tunnelpool/idle"
	quicgo "github.com/quic-go/quic-go"
)

func TestStreamKeepsOriginalPhysicalConnection(t *testing.T) {
	original, replacement := &quicgo.Conn{}, &quicgo.Conn{}
	p := &Pool{idle: idlequeue.New[net.Conn](1), ctx: context.Background()}
	// Metadata-only zero transports: no I/O or Close is performed on these sentinels.
	owned := &StreamConn{conn: original, localAddr: &net.UDPAddr{}, remoteAddr: &net.UDPAddr{}}
	p.idle.Publish(p.ctx, "one", owned)
	p.quicConn.Store(replacement)
	got, err := p.OutgoingGet("one", time.Second)
	if err != nil || got != owned || got.(*StreamConn).conn != original {
		t.Fatal("stream rebound to latest physical connection", err)
	}
}
