// Package lifetime owns resources for one non-restartable pool lifetime.
package lifetime

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
)

type Group struct {
	mu              sync.Mutex
	ctx             context.Context
	cancel          context.CancelFunc
	started, closed bool
	resources       map[*Handle]struct{}
	done            chan struct{}
}

type Handle struct {
	group *Group
	close func() error
}

func New() *Group {
	ctx, cancel := context.WithCancel(context.Background())
	return &Group{ctx: ctx, cancel: cancel, resources: make(map[*Handle]struct{}), done: make(chan struct{})}
}
func (g *Group) Context() context.Context { return g.ctx }
func (g *Group) Start() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.started {
		return false
	}
	g.started = true
	return true
}
func (g *Group) Track(c io.Closer) (*Handle, bool) {
	h := &Handle{group: g, close: c.Close}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		c.Close()
		return nil, false
	}
	g.resources[h] = struct{}{}
	g.mu.Unlock()
	return h, true
}
func (h *Handle) Release() {
	if h == nil {
		return
	}
	h.group.mu.Lock()
	delete(h.group.resources, h)
	h.group.mu.Unlock()
}
func (g *Group) Close() {
	g.mu.Lock()
	if g.closed {
		done := g.done
		g.mu.Unlock()
		<-done
		return
	}
	g.closed = true
	all := make([]*Handle, 0, len(g.resources))
	for h := range g.resources {
		all = append(all, h)
	}
	g.resources = make(map[*Handle]struct{})
	g.mu.Unlock()
	g.cancel()
	var wg sync.WaitGroup
	for _, h := range all {
		wg.Go(func() { h.close() })
	}
	wg.Wait()
	close(g.done)
}

type CloserFunc func() error

func (f CloserFunc) Close() error { return f() }

type Conn struct {
	net.Conn
	handle *Handle
	once   sync.Once
	err    error
}

// Bind tracks a connection through both idle and leased ownership. abort can
// interrupt a protocol close handshake; nil uses the connection's ordinary Close.
func (g *Group) Bind(c net.Conn, abort func() error) (net.Conn, bool) {
	if abort == nil {
		abort = c.Close
	}
	h, ok := g.Track(CloserFunc(abort))
	if !ok {
		return nil, false
	}
	return &Conn{Conn: c, handle: h}, true
}
func (c *Conn) Close() error {
	c.once.Do(func() { defer c.handle.Release(); c.err = c.Conn.Close() })
	return c.err
}
func (c *Conn) ConnectionState() tls.ConnectionState {
	if t, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return t.ConnectionState()
	}
	return tls.ConnectionState{}
}
