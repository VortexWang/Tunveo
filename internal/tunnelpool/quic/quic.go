package quic

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	idlequeue "github.com/VortexWang/Tunveo/internal/tunnelpool/idle"
	"github.com/VortexWang/Tunveo/internal/tunnelpool/lifetime"

	quic "github.com/quic-go/quic-go"
)

const (
	defaultMinCap           = 1
	defaultMaxCap           = 1
	defaultMinIvl           = 1 * time.Second
	defaultMaxIvl           = 1 * time.Second
	idReadTimeout           = 1 * time.Minute
	idRetryInterval         = 50 * time.Millisecond
	acceptRetryInterval     = 50 * time.Millisecond
	intervalAdjustStep      = 100 * time.Millisecond
	capacityAdjustLowRatio  = 0.2
	capacityAdjustHighRatio = 0.8
	intervalLowThreshold    = 0.2
	intervalHighThreshold   = 0.8
	defaultALPN             = "np-quic"
)

type Pool struct {
	life         *lifetime.Group
	idle         *idlequeue.Queue[net.Conn]
	tlsCode      string
	hostname     string
	clientIP     string
	tlsConfig    *tls.Config
	addrResolver func() (string, error)
	listenAddr   string
	quicConn     atomic.Pointer[quic.Conn]
	quicListener atomic.Pointer[quic.Listener]
	first        atomic.Bool
	errCount     atomic.Int32
	capacity     atomic.Int32
	minCap       int
	maxCap       int
	interval     atomic.Int64
	minIvl       time.Duration
	maxIvl       time.Duration
	keepAlive    time.Duration
	ctx          context.Context
	cancel       context.CancelFunc
}

type StreamConn struct {
	*quic.Stream
	conn       *quic.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (s *StreamConn) Close() error { s.Stream.CancelRead(0); return s.Stream.Close() }

func (s *StreamConn) LocalAddr() net.Addr {
	return s.localAddr
}

func (s *StreamConn) RemoteAddr() net.Addr {
	return s.remoteAddr
}

func (s *StreamConn) SetDeadline(t time.Time) error {
	if err := s.Stream.SetReadDeadline(t); err != nil {
		return err
	}
	return s.Stream.SetWriteDeadline(t)
}

func (s *StreamConn) ConnectionState() tls.ConnectionState {
	return s.conn.ConnectionState().TLS
}

func buildTLSConfig(tlsCode, hostname string) *tls.Config {
	var tlsConfig *tls.Config
	switch tlsCode {
	case "0", "1":
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{defaultALPN},
			MinVersion:         tls.VersionTLS13,
		}
	case "2":
		tlsConfig = &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         hostname,
			NextProtos:         []string{defaultALPN},
			MinVersion:         tls.VersionTLS13,
		}
	}
	return tlsConfig
}

func buildQUICConfig(keepAlive time.Duration, maxStreams int) *quic.Config {
	return &quic.Config{
		KeepAlivePeriod:    keepAlive,
		MaxIdleTimeout:     keepAlive * 3,
		MaxIncomingStreams: int64(maxStreams),
	}
}

func NewClientPool(
	minCap, maxCap int,
	minIvl, maxIvl time.Duration,
	keepAlive time.Duration,
	tlsCode string,
	hostname string,
	addrResolver func() (string, error),
) *Pool {
	if minCap <= 0 {
		minCap = defaultMinCap
	}
	if maxCap <= 0 {
		maxCap = defaultMaxCap
	}
	if minCap > maxCap {
		minCap, maxCap = maxCap, minCap
	}

	if minIvl <= 0 {
		minIvl = defaultMinIvl
	}
	if maxIvl <= 0 {
		maxIvl = defaultMaxIvl
	}
	if minIvl > maxIvl {
		minIvl, maxIvl = maxIvl, minIvl
	}

	pool := &Pool{
		idle:         idlequeue.New[net.Conn](maxCap),
		tlsCode:      tlsCode,
		hostname:     hostname,
		addrResolver: addrResolver,
		minCap:       minCap,
		maxCap:       maxCap,
		minIvl:       minIvl,
		maxIvl:       maxIvl,
		keepAlive:    keepAlive,
	}
	pool.capacity.Store(int32(minCap))
	pool.interval.Store(int64(minIvl))
	pool.life = lifetime.New()
	pool.ctx, pool.cancel = pool.life.Context(), pool.life.Close
	return pool
}

func NewServerPool(
	maxCap int,
	clientIP string,
	tlsConfig *tls.Config,
	listenAddr string,
	keepAlive time.Duration,
) *Pool {
	if maxCap <= 0 {
		maxCap = defaultMaxCap
	}
	if listenAddr == "" {
		return nil
	}

	pool := &Pool{
		idle:       idlequeue.New[net.Conn](maxCap),
		clientIP:   clientIP,
		tlsConfig:  tlsConfig,
		listenAddr: listenAddr,
		maxCap:     maxCap,
		keepAlive:  keepAlive,
	}
	pool.life = lifetime.New()
	pool.ctx, pool.cancel = pool.life.Context(), pool.life.Close
	return pool
}

func (p *Pool) createStream() bool {
	attempt := p.idle.Begin(p.ctx)
	defer attempt.End()
	if attempt.Context.Err() != nil {
		return false
	}
	conn := p.quicConn.Load()
	if conn == nil {
		return false
	}

	stream, err := conn.OpenStreamSync(attempt.Context)
	if err != nil {
		p.quicConn.CompareAndSwap(conn, nil)
		return false
	}

	attempt.Watch(func() { stream.CancelRead(0); stream.CancelWrite(0) })
	if _, err := stream.Write([]byte{0x00}); err != nil {
		stream.Close()
		p.quicConn.CompareAndSwap(conn, nil)
		return false
	}

	var id string

	stream.SetReadDeadline(time.Now().Add(idReadTimeout))
	buf := make([]byte, 4)
	n, err := io.ReadFull(stream, buf)
	if err != nil || n != 4 {
		stream.Close()
		p.quicConn.CompareAndSwap(conn, nil)
		return false
	}
	id = hex.EncodeToString(buf)
	stream.SetReadDeadline(time.Time{})

	owned := &StreamConn{Stream: stream, conn: conn, localAddr: conn.LocalAddr(), remoteAddr: conn.RemoteAddr()}
	if !p.idle.Commit(attempt, id, owned) {
		stream.Close()
		return false
	}
	return true
}

func (p *Pool) handleStream(stream *quic.Stream, conn *quic.Conn) {
	attempt := p.idle.Begin(p.ctx)
	defer attempt.End()
	attempt.Watch(func() { stream.CancelRead(0); stream.CancelWrite(0) })
	var streamClosed bool
	defer func() {
		if !streamClosed {
			(*stream).Close()
		}
	}()

	if p.Active() >= p.maxCap {
		return
	}

	handshake := make([]byte, 1)
	if _, err := (*stream).Read(handshake); err != nil {
		return
	}

	rawID, id, err := p.generateID()
	if err != nil {
		return
	}

	if p.idle.Contains(id) {
		return
	}

	if _, err := (*stream).Write(rawID); err != nil {
		return
	}

	owned := &StreamConn{Stream: stream, conn: conn, localAddr: conn.LocalAddr(), remoteAddr: conn.RemoteAddr()}
	if !p.idle.Commit(attempt, id, owned) {
		return
	}
	streamClosed = true
}

func (p *Pool) establishConnection() error {
	conn := p.quicConn.Load()
	if conn != nil {
		if conn.Context().Err() == nil {
			return nil
		}
		p.quicConn.CompareAndSwap(conn, nil)
	}

	targetAddr, err := p.addrResolver()
	if err != nil {
		return fmt.Errorf("establishConnection: address resolution failed: %w", err)
	}

	tlsConfig := buildTLSConfig(p.tlsCode, p.hostname)
	quicConfig := buildQUICConfig(p.keepAlive, p.maxCap)

	newConn, err := quic.DialAddr(p.ctx, targetAddr, tlsConfig, quicConfig)
	if err != nil {
		return err
	}

	handle, ok := p.life.Track(lifetime.CloserFunc(func() error { return newConn.CloseWithError(0, "pool closed") }))
	if !ok {
		return context.Canceled
	}
	context.AfterFunc(newConn.Context(), handle.Release)
	p.quicConn.Store(newConn)
	return nil
}

func (p *Pool) startListener() error {
	if p.quicListener.Load() != nil {
		return nil
	}
	if p.tlsConfig == nil {
		return fmt.Errorf("startListener: server mode requires TLS config")
	}

	clonedTLS := p.tlsConfig.Clone()
	clonedTLS.NextProtos = []string{defaultALPN}
	clonedTLS.MinVersion = tls.VersionTLS13

	quicConfig := buildQUICConfig(p.keepAlive, p.maxCap)
	// Own both layers explicitly. A convenience ListenAddr listener may keep
	// its UDP transport alive while closed connection IDs drain. Pool.Close
	// must release the address before a replacement endpoint starts.
	packet, err := net.ListenPacket("udp", p.listenAddr)
	if err != nil {
		return fmt.Errorf("startListener: %w", err)
	}
	transport := &quic.Transport{Conn: packet}
	newListener, err := transport.Listen(clonedTLS, quicConfig)
	if err != nil {
		transport.Close()
		packet.Close()
		return fmt.Errorf("startListener: %w", err)
	}
	closeTransport := lifetime.CloserFunc(func() error {
		// Transport.Close joins its packet reader but does not close a supplied
		// PacketConn. Keep that final socket close in the same owned resource.
		newListener.Close()
		err := transport.Close()
		packet.Close()
		return err
	})
	if _, ok := p.life.Track(closeTransport); !ok {
		return context.Canceled
	}
	p.quicListener.Store(newListener)
	return nil
}

func (p *Pool) ClientManager() {
	if !p.life.Start() {
		return
	}

	for p.ctx.Err() == nil {
		p.adjustInterval()
		capacity := int(p.capacity.Load())
		need := capacity - p.idle.Len()
		created := 0

		if need > 0 {
			if err := p.establishConnection(); err != nil {
				time.Sleep(acceptRetryInterval)
				continue
			}

			var wg sync.WaitGroup
			results := make(chan int, need)
			for range need {
				wg.Go(func() {
					if p.createStream() {
						results <- 1
					}
				})
			}
			wg.Wait()
			close(results)
			for r := range results {
				created += r
			}
		}

		p.adjustCapacity(created)

		select {
		case <-p.ctx.Done():
			return
		case <-time.After(time.Duration(p.interval.Load())):
		}
	}
}

func (p *Pool) ServerManager() {
	if !p.life.Start() {
		return
	}

	if err := p.startListener(); err != nil {
		return
	}

	for p.ctx.Err() == nil {
		listener := p.quicListener.Load()
		if listener == nil {
			return
		}

		conn, err := listener.Accept(p.ctx)
		if err != nil {
			if p.ctx.Err() != nil {
				return
			}
			select {
			case <-p.ctx.Done():
				return
			case <-time.After(acceptRetryInterval):
			}
			continue
		}

		if p.clientIP != "" {
			remoteAddr := conn.RemoteAddr().(*net.UDPAddr)
			if remoteAddr.IP.String() != p.clientIP {
				conn.CloseWithError(0, "unauthorized IP")
				continue
			}
		}

		handle, ok := p.life.Track(lifetime.CloserFunc(func() error { return conn.CloseWithError(0, "pool closed") }))
		if !ok {
			return
		}
		context.AfterFunc(conn.Context(), handle.Release)
		p.quicConn.Store(conn)

		go func(c *quic.Conn) {
			for p.ctx.Err() == nil {
				stream, err := (*c).AcceptStream(p.ctx)
				if err != nil {
					return
				}
				go p.handleStream(stream, c)
			}
		}(conn)
	}
}

func (p *Pool) OutgoingGet(id string, timeout time.Duration) (net.Conn, error) {
	attempt := p.idle.Begin(p.ctx)
	defer attempt.End()
	ctx, cancel := context.WithTimeout(attempt.Context, timeout)
	defer cancel()
	conn, err := p.idle.TakeIDAttempt(attempt, ctx, id)
	if err != nil {
		return nil, fmt.Errorf("OutgoingGet: stream not found: %w", err)
	}
	return conn, nil
}
func (p *Pool) IncomingGet(timeout time.Duration) (string, net.Conn, error) {
	attempt := p.idle.Begin(p.ctx)
	defer attempt.End()
	ctx, cancel := context.WithTimeout(attempt.Context, timeout)
	defer cancel()
	id, conn, err := p.idle.TakeAttempt(attempt, ctx)
	if err != nil {
		return "", nil, fmt.Errorf("IncomingGet: insufficient streams: %w", err)
	}
	return id, conn, nil
}

func (p *Pool) Flush() {
	values := p.idle.Drain()
	var wg sync.WaitGroup
	for _, value := range values {
		wg.Go(func() {
			if value != nil {
				value.Close()
			}
		})
	}
	wg.Wait()
}

func (p *Pool) Close() { p.cancel(); p.Flush() }

func (p *Pool) Ready() bool {
	return p.ctx != nil && p.ctx.Err() == nil
}

func (p *Pool) Active() int {
	return p.idle.Len()
}

func (p *Pool) Capacity() int {
	return int(p.capacity.Load())
}

func (p *Pool) Interval() time.Duration {
	return time.Duration(p.interval.Load())
}

func (p *Pool) AddError() {
	p.errCount.Add(1)
}

func (p *Pool) ErrorCount() int {
	return int(p.errCount.Load())
}

func (p *Pool) ResetError() {
	p.errCount.Store(0)
}

func (p *Pool) adjustInterval() {
	idle := p.idle.Len()
	capacity := int(p.capacity.Load())
	interval := time.Duration(p.interval.Load())

	if idle < int(float64(capacity)*intervalLowThreshold) && interval > p.minIvl {
		newInterval := max(interval-intervalAdjustStep, p.minIvl)
		p.interval.Store(int64(newInterval))
	}

	if idle > int(float64(capacity)*intervalHighThreshold) && interval < p.maxIvl {
		newInterval := min(interval+intervalAdjustStep, p.maxIvl)
		p.interval.Store(int64(newInterval))
	}
}

func (p *Pool) adjustCapacity(created int) {
	capacity := int(p.capacity.Load())
	ratio := float64(created) / float64(capacity)

	if ratio < capacityAdjustLowRatio && capacity > p.minCap {
		p.capacity.Add(-1)
	}

	if ratio > capacityAdjustHighRatio && capacity < p.maxCap {
		p.capacity.Add(1)
	}
}

func (p *Pool) generateID() ([]byte, string, error) {
	if p.first.CompareAndSwap(false, true) {
		return []byte{0, 0, 0, 0}, "00000000", nil
	}

	rawID := make([]byte, 4)
	if _, err := rand.Read(rawID); err != nil {
		return nil, "", err
	}
	id := hex.EncodeToString(rawID)
	return rawID, id, nil
}
