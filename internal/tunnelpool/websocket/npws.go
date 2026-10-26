package websocket

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	idlequeue "github.com/VortexWang/Tunveo/internal/tunnelpool/idle"
	"github.com/VortexWang/Tunveo/internal/tunnelpool/lifetime"

	"github.com/coder/websocket"
)

const (
	maxConcurrentDials      = 4
	defaultMinCap           = 1
	defaultMaxCap           = 1
	defaultMinIvl           = 1 * time.Second
	defaultMaxIvl           = 1 * time.Second
	idReadTimeout           = 1 * time.Minute
	idRetryInterval         = 50 * time.Millisecond
	intervalAdjustStep      = 100 * time.Millisecond
	capacityAdjustLowRatio  = 0.2
	capacityAdjustHighRatio = 0.8
	intervalLowThreshold    = 0.2
	intervalHighThreshold   = 0.8
	wsPath                  = "/"
)

type Pool struct {
	life       *lifetime.Group
	idle       *idlequeue.Queue[net.Conn]
	clientIP   string
	serverName string
	serverURL  string
	tlsConfig  *tls.Config
	server     *http.Server
	listener   net.Listener
	first      atomic.Bool
	errCount   atomic.Int32
	capacity   atomic.Int32
	minCap     int
	maxCap     int
	interval   atomic.Int64
	minIvl     time.Duration
	maxIvl     time.Duration
	keepAlive  time.Duration
	ctx        context.Context
	cancel     context.CancelFunc
}

type tlsConn struct {
	net.Conn
	tlsState *tls.ConnectionState
}

func (tc *tlsConn) ConnectionState() tls.ConnectionState {
	if tc.tlsState != nil {
		return *tc.tlsState
	}
	return tls.ConnectionState{}
}

// NewClientPool retains the original address-derived certificate identity.
func NewClientPool(minCap, maxCap int, minIvl, maxIvl, keepAlive time.Duration, tlsCode, serverURL string) *Pool {
	return NewClientPoolWithServerName(minCap, maxCap, minIvl, maxIvl, keepAlive, tlsCode, serverURL, "")
}

// NewClientPoolWithServerName separates the TLS identity from the dial URL.
// An empty override retains the URL host. The URL/HTTP Host is not rewritten.
func NewClientPoolWithServerName(minCap, maxCap int, minIvl, maxIvl, keepAlive time.Duration, tlsCode, serverURL, tlsServerName string) *Pool {
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

	serverName, serverPort := serverURL, ""
	if name, port, err := net.SplitHostPort(serverURL); err == nil {
		serverName, serverPort = name, port
	}

	if tlsServerName == "" {
		tlsServerName = serverName
	}

	var tlsConfig *tls.Config
	var wsScheme string
	switch tlsCode {
	case "1":
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         tlsServerName,
			MinVersion:         tls.VersionTLS13,
		}
		wsScheme = "wss"
	case "2":
		tlsConfig = &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         tlsServerName,
			MinVersion:         tls.VersionTLS13,
		}
		wsScheme = "wss"
	default:
		if serverPort == "443" {
			tlsConfig = &tls.Config{
				InsecureSkipVerify: false,
				ServerName:         tlsServerName,
				MinVersion:         tls.VersionTLS13,
			}
			wsScheme = "wss"
		} else {
			wsScheme = "ws"
		}
	}

	pool := &Pool{
		idle:       idlequeue.New[net.Conn](maxCap),
		serverName: serverName,
		serverURL:  wsScheme + "://" + serverURL + wsPath,
		tlsConfig:  tlsConfig,
		minCap:     minCap,
		maxCap:     maxCap,
		minIvl:     minIvl,
		maxIvl:     maxIvl,
		keepAlive:  keepAlive,
	}
	pool.capacity.Store(int32(minCap))
	pool.interval.Store(int64(minIvl))
	pool.life = lifetime.New()
	pool.ctx, pool.cancel = pool.life.Context(), pool.life.Close
	return pool
}

func NewServerPool(maxCap int, clientIP string, tlsConfig *tls.Config, listener net.Listener, keepAlive time.Duration) *Pool {
	if maxCap <= 0 {
		maxCap = defaultMaxCap
	}

	if listener == nil {
		return nil
	}

	pool := &Pool{
		idle:      idlequeue.New[net.Conn](maxCap),
		clientIP:  clientIP,
		tlsConfig: tlsConfig,
		listener:  listener,
		maxCap:    maxCap,
		keepAlive: keepAlive,
	}
	pool.life = lifetime.New()
	pool.ctx, pool.cancel = pool.life.Context(), pool.life.Close
	pool.life.Track(listener)
	return pool
}

func (p *Pool) createConnection() bool {
	attempt := p.idle.Begin(p.ctx)
	defer attempt.End()
	if attempt.Context.Err() != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(attempt.Context, 30*time.Second)
	defer cancel()

	var httpClient *http.Client
	if p.tlsConfig != nil {
		httpClient = &http.Client{Transport: &http.Transport{
			TLSClientConfig: p.tlsConfig,
		}}
	} else {
		httpClient = &http.Client{}
	}

	wsConn, resp, err := websocket.Dial(ctx, p.serverURL, &websocket.DialOptions{
		HTTPClient:      httpClient,
		CompressionMode: websocket.CompressionDisabled,
		Host:            p.serverName,
	})
	if err != nil {
		return false
	}
	wsConn.SetReadLimit(-1)

	var tlsState *tls.ConnectionState
	if resp != nil && resp.TLS != nil {
		tlsState = resp.TLS
	}

	conn, ok := p.life.Bind(websocket.NetConn(p.ctx, wsConn, websocket.MessageBinary), wsConn.CloseNow)
	if !ok {
		return false
	}
	attempt.Watch(func() { wsConn.CloseNow() })

	conn.SetReadDeadline(time.Now().Add(idReadTimeout))
	buf := make([]byte, 4)
	n, err := io.ReadFull(conn, buf)
	if err != nil || n != 4 {
		conn.Close()
		return false
	}
	id := hex.EncodeToString(buf)
	conn.SetReadDeadline(time.Time{})

	var wrappedConn net.Conn = conn
	if tlsState != nil {
		wrappedConn = &tlsConn{
			Conn:     conn,
			tlsState: tlsState,
		}
	}

	if !p.idle.Commit(attempt, id, wrappedConn) {
		wrappedConn.Close()
		return false
	}
	return true
}

func (p *Pool) handleConnection(w http.ResponseWriter, r *http.Request) {
	attempt := p.idle.Begin(p.ctx)
	defer attempt.End()
	if p.Active() >= p.maxCap {
		http.Error(w, "pool full", http.StatusServiceUnavailable)
		return
	}

	clientIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		clientIP = host
	}
	if p.clientIP != "" && clientIP != p.clientIP {
		http.Error(w, "unauthorized", http.StatusForbidden)
		return
	}

	wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode:    websocket.CompressionDisabled,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	wsConn.SetReadLimit(-1)

	rawID, id, err := p.generateID()
	if err != nil {
		wsConn.Close(websocket.StatusInternalError, "id generation failed")
		return
	}

	if p.idle.Contains(id) {
		wsConn.Close(websocket.StatusInternalError, "duplicate id")
		return
	}

	conn, ok := p.life.Bind(websocket.NetConn(p.ctx, wsConn, websocket.MessageBinary), wsConn.CloseNow)
	if !ok {
		return
	}
	attempt.Watch(func() { wsConn.CloseNow() })
	if _, err := conn.Write(rawID); err != nil {
		conn.Close()
		return
	}

	if !p.idle.Commit(attempt, id, conn) {
		conn.Close()
	}
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
			var wg sync.WaitGroup
			results := make(chan int, need)
			// Each WSS dial also owns HTTP/TLS and server handshake work.
			// Bound in-flight dials while still filling the full idle deficit.
			jobs := make(chan struct{}, need)
			for range need {
				jobs <- struct{}{}
			}
			close(jobs)
			for range min(need, maxConcurrentDials) {
				wg.Go(func() {
					for range jobs {
						if p.createConnection() {
							results <- 1
						}
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

	var listener net.Listener
	if p.tlsConfig != nil {
		listener = tls.NewListener(p.listener, p.tlsConfig)
	} else {
		listener = p.listener
	}

	mux := http.NewServeMux()
	mux.HandleFunc(wsPath, p.handleConnection)

	p.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       p.keepAlive,
		ErrorLog:          log.New(io.Discard, "", 0),
	}

	if _, ok := p.life.Track(p.server); !ok {
		return
	}
	if err := p.server.Serve(listener); err != nil && err != http.ErrServerClosed {
		if p.ctx.Err() == nil {
			p.errCount.Add(1)
		}
	}
}

func (p *Pool) OutgoingGet(id string, timeout time.Duration) (net.Conn, error) {
	attempt := p.idle.Begin(p.ctx)
	defer attempt.End()
	ctx, cancel := context.WithTimeout(attempt.Context, timeout)
	defer cancel()
	conn, err := p.idle.TakeIDAttempt(attempt, ctx, id)
	if err != nil {
		return nil, fmt.Errorf("OutgoingGet: connection not found: %w", err)
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
		return "", nil, fmt.Errorf("IncomingGet: insufficient connections: %w", err)
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
