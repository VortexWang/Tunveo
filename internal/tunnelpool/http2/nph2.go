package http2

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	idlequeue "github.com/VortexWang/Tunveo/internal/tunnelpool/idle"
	"github.com/VortexWang/Tunveo/internal/tunnelpool/lifetime"

	"golang.org/x/net/http2"
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
	baseListener net.Listener
	session      atomic.Pointer[h2Session]
	h2Server     *http2.Server
	listener     atomic.Pointer[net.Listener]
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

type h2Session struct {
	conn   net.Conn
	client *http2.ClientConn
}
type connectionKey struct{}

type StreamConn struct {
	io.ReadWriteCloser
	conn       net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (s *StreamConn) LocalAddr() net.Addr {
	return s.localAddr
}

func (s *StreamConn) RemoteAddr() net.Addr {
	return s.remoteAddr
}

func (s *StreamConn) SetDeadline(t time.Time) error {
	if tc, ok := s.conn.(interface{ SetDeadline(time.Time) error }); ok {
		return tc.SetDeadline(t)
	}
	return nil
}

func (s *StreamConn) SetReadDeadline(t time.Time) error {
	if tc, ok := s.conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		return tc.SetReadDeadline(t)
	}
	return nil
}

func (s *StreamConn) SetWriteDeadline(t time.Time) error {
	if tc, ok := s.conn.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return tc.SetWriteDeadline(t)
	}
	return nil
}

func (s *StreamConn) ConnectionState() tls.ConnectionState {
	if tc, ok := s.conn.(*tls.Conn); ok {
		return tc.ConnectionState()
	}
	return tls.ConnectionState{}
}

func buildTLSConfig(tlsCode, hostname string) *tls.Config {
	switch tlsCode {
	case "2":
		return &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         hostname,
			NextProtos:         []string{"h2"},
			MinVersion:         tls.VersionTLS13,
		}
	default:
		return &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
			MinVersion:         tls.VersionTLS13,
		}
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
	baseListener net.Listener,
	keepAlive time.Duration,
) *Pool {
	if maxCap <= 0 {
		maxCap = defaultMaxCap
	}
	if baseListener == nil {
		return nil
	}
	if tlsConfig == nil {
		return nil
	}

	tlsConfig = tlsConfig.Clone()
	tlsConfig.NextProtos = []string{"h2"}
	tlsConfig.MinVersion = tls.VersionTLS13

	pool := &Pool{
		idle:         idlequeue.New[net.Conn](maxCap),
		clientIP:     clientIP,
		tlsConfig:    tlsConfig,
		baseListener: baseListener,
		listenAddr:   baseListener.Addr().String(),
		maxCap:       maxCap,
		keepAlive:    keepAlive,
		h2Server: &http2.Server{
			MaxConcurrentStreams: uint32(maxCap),
			IdleTimeout:          keepAlive * 2,
		},
	}
	pool.life = lifetime.New()
	pool.ctx, pool.cancel = pool.life.Context(), pool.life.Close
	pool.life.Track(baseListener)
	return pool
}

type http2Stream struct {
	reader    io.ReadCloser
	writer    io.WriteCloser
	closeOnce sync.Once
	done      chan struct{}
	cancel    context.CancelFunc
}

func (s *http2Stream) Read(p []byte) (n int, err error) {
	return s.reader.Read(p)
}

func (s *http2Stream) Write(p []byte) (n int, err error) {
	return s.writer.Write(p)
}

func (s *http2Stream) Close() error {
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		if s.reader != nil {
			s.reader.Close()
		}
		if s.writer != nil {
			s.writer.Close()
		}
		if s.done != nil {
			close(s.done)
		}
	})
	return nil
}

func (p *Pool) createStream() bool {
	attempt := p.idle.Begin(p.ctx)
	defer attempt.End()
	if attempt.Context.Err() != nil {
		return false
	}
	session := p.session.Load()
	if session == nil {
		return false
	}
	reqReader, reqWriter := io.Pipe()
	requestCtx, requestCancel := context.WithCancel(p.ctx)
	setupCtx, setupCancel := context.WithTimeout(attempt.Context, idReadTimeout)
	defer setupCancel()
	attempt.WatchContext(setupCtx, func() { requestCancel(); reqReader.Close(); reqWriter.Close() })
	committed := false
	defer func() {
		if !committed {
			requestCancel()
			reqReader.Close()
			reqWriter.Close()
		}
	}()
	req := (&http.Request{Method: "POST", URL: &url.URL{Scheme: "https", Host: p.hostname, Path: "/stream"}, Header: http.Header{}, Body: reqReader}).WithContext(requestCtx)
	written := make(chan error, 1)
	go func() { _, err := reqWriter.Write([]byte{0}); written <- err }()
	resp, err := session.client.RoundTrip(req)
	if err != nil {
		return false
	}
	var raw [4]byte
	if _, err := io.ReadFull(resp.Body, raw[:]); err != nil {
		resp.Body.Close()
		return false
	}
	select {
	case err := <-written:
		if err != nil {
			resp.Body.Close()
			return false
		}
	case <-setupCtx.Done():
		resp.Body.Close()
		return false
	}
	stream := &http2Stream{reader: resp.Body, writer: reqWriter, cancel: requestCancel, done: make(chan struct{})}
	conn := &StreamConn{ReadWriteCloser: stream, conn: session.conn, localAddr: session.conn.LocalAddr(), remoteAddr: session.conn.RemoteAddr()}
	if !p.idle.Commit(attempt, hex.EncodeToString(raw[:]), conn) {
		stream.Close()
		return false
	}
	committed = true
	return true
}

func (p *Pool) handleStream(rw http.ResponseWriter, req *http.Request) {
	attempt := p.idle.Begin(p.ctx)
	defer attempt.End()
	attempt.Watch(func() { req.Body.Close() })
	physical, ok := req.Context().Value(connectionKey{}).(net.Conn)
	if !ok {
		return
	}
	if req.URL.Path != "/stream" || req.Method != "POST" || p.Active() >= p.maxCap {
		http.Error(rw, "not found", http.StatusNotFound)
		return
	}

	var handshake [1]byte
	if _, err := req.Body.Read(handshake[:]); err != nil {
		return
	}

	rawID, id, err := p.generateID()
	if err != nil {
		return
	}

	if p.idle.Contains(id) {
		return
	}
	if _, err := rw.Write(rawID); err != nil {
		return
	}
	if flusher, ok := rw.(http.Flusher); ok {
		flusher.Flush()
	}

	stream := &http2Stream{
		reader: req.Body,
		writer: &responseWriter{rw: rw},
		done:   make(chan struct{}),
	}

	conn := &StreamConn{ReadWriteCloser: stream, conn: physical, localAddr: physical.LocalAddr(), remoteAddr: physical.RemoteAddr()}
	if !p.idle.Commit(attempt, id, conn) {
		stream.Close()
		return
	}
	defer func() {
		// Peer cancellation can precede its control-plane claim of this ID (notably
		// fingerprint verification). Preserve the idle identity until claim/Flush;
		// its immutable transport metadata remains valid even after stream EOF.
		if p.ctx.Err() != nil {
			p.idle.RemoveIfSame(id, conn)
		}
		stream.Close()
	}()

	select {
	case <-p.ctx.Done():
	case <-req.Context().Done():
	case <-stream.done:
	}
}

type responseWriter struct {
	mu     sync.Mutex
	rw     http.ResponseWriter
	closed atomic.Bool
}

func (w *responseWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	n, err = w.rw.Write(p)
	if flusher, ok := w.rw.(http.Flusher); ok {
		flusher.Flush()
	}
	return
}

func (w *responseWriter) Close() error {
	// Abort only this HTTP/2 response stream before joining an outstanding write.
	http.NewResponseController(w.rw).SetWriteDeadline(time.Now().Add(-time.Second))
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed.Store(true)
	return nil
}

func (p *Pool) establishConnection() error {
	old := p.session.Load()
	if old != nil {
		if err := old.client.Ping(p.ctx); err == nil {
			return nil
		}
		p.session.CompareAndSwap(old, nil)
		old.conn.Close()
	}
	addr, err := p.addrResolver()
	if err != nil {
		return err
	}
	raw, err := (&net.Dialer{}).DialContext(p.ctx, "tcp", addr)
	if err != nil {
		return err
	}
	tracked, ok := p.life.Bind(raw, nil)
	if !ok {
		return context.Canceled
	}
	conn := tls.Client(tracked, buildTLSConfig(p.tlsCode, p.hostname))
	if err := conn.HandshakeContext(p.ctx); err != nil {
		conn.Close()
		return err
	}
	transport := &http2.Transport{}
	client, err := transport.NewClientConn(conn)
	if err != nil {
		conn.Close()
		return err
	}
	p.session.Store(&h2Session{conn: conn, client: client})
	return nil
}

func (p *Pool) startListener() error {
	if p.tlsConfig == nil {
		return fmt.Errorf("startListener: TLS config is required")
	}
	if p.baseListener == nil {
		return fmt.Errorf("startListener: base listener is required")
	}

	var l net.Listener = p.baseListener
	p.listener.Store(&l)
	return nil
}

func (p *Pool) ClientManager() {
	if !p.life.Start() {
		return
	}

	if p.keepAlive > 0 {
		go func() {
			ticker := time.NewTicker(p.keepAlive)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if session := p.session.Load(); session != nil {
						session.client.Ping(p.ctx)
					}
				case <-p.ctx.Done():
					return
				}
			}
		}()
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

	listener := p.listener.Load()
	if listener == nil {
		return
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.clientIP != "" {
			if host, _, _ := net.SplitHostPort(r.RemoteAddr); host != p.clientIP {
				http.Error(w, "unauthorized", http.StatusForbidden)
				return
			}
		}
		p.handleStream(w, r)
	})

	if err := http2.ConfigureServer(&http.Server{Handler: handler}, p.h2Server); err != nil {
		return
	}

	for p.ctx.Err() == nil {
		conn, err := (*listener).Accept()
		if err != nil {
			if p.ctx.Err() != nil {
				return
			}
			time.Sleep(acceptRetryInterval)
			continue
		}

		tracked, ok := p.life.Bind(conn, nil)
		if !ok {
			return
		}
		tlsConn := tls.Server(tracked, p.tlsConfig)
		if err := tlsConn.HandshakeContext(p.ctx); err != nil {
			conn.Close()
			continue
		}

		if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
			tlsConn.Close()
			continue
		}

		// Each request carries its accepted physical connection, not a mutable latest pointer.

		go func(c net.Conn) {
			defer c.Close()
			p.h2Server.ServeConn(c, &http2.ServeConnOpts{
				Context: context.WithValue(p.ctx, connectionKey{}, c),
				Handler: handler,
			})
		}(tlsConn)
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
