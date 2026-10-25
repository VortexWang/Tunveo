package npws

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

	"github.com/coder/websocket"
)

const (
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
	conns      sync.Map
	idChan     chan string
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

func NewClientPool(minCap, maxCap int, minIvl, maxIvl, keepAlive time.Duration, tlsCode, serverURL string) *Pool {
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

	var tlsConfig *tls.Config
	var wsScheme string
	switch tlsCode {
	case "1":
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         serverName,
			MinVersion:         tls.VersionTLS13,
		}
		wsScheme = "wss"
	case "2":
		tlsConfig = &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         serverName,
			MinVersion:         tls.VersionTLS13,
		}
		wsScheme = "wss"
	default:
		if serverPort == "443" {
			tlsConfig = &tls.Config{
				InsecureSkipVerify: false,
				ServerName:         serverName,
				MinVersion:         tls.VersionTLS13,
			}
			wsScheme = "wss"
		} else {
			wsScheme = "ws"
		}
	}

	pool := &Pool{
		conns:      sync.Map{},
		idChan:     make(chan string, maxCap),
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
	pool.ctx, pool.cancel = context.WithCancel(context.Background())
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
		conns:     sync.Map{},
		idChan:    make(chan string, maxCap),
		clientIP:  clientIP,
		tlsConfig: tlsConfig,
		listener:  listener,
		maxCap:    maxCap,
		keepAlive: keepAlive,
	}
	pool.ctx, pool.cancel = context.WithCancel(context.Background())
	return pool
}

func (p *Pool) createConnection() bool {
	ctx, cancel := context.WithTimeout(p.ctx, 30*time.Second)
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

	conn := websocket.NetConn(p.ctx, wsConn, websocket.MessageBinary)

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

	p.conns.Store(id, wrappedConn)
	select {
	case p.idChan <- id:
		return true
	default:
		p.conns.Delete(id)
		wrappedConn.Close()
		return false
	}
}

func (p *Pool) handleConnection(w http.ResponseWriter, r *http.Request) {
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

	if _, exist := p.conns.Load(id); exist {
		wsConn.Close(websocket.StatusInternalError, "duplicate id")
		return
	}

	conn := websocket.NetConn(p.ctx, wsConn, websocket.MessageBinary)
	if _, err := conn.Write(rawID); err != nil {
		conn.Close()
		return
	}

	select {
	case p.idChan <- id:
		p.conns.Store(id, conn)
	default:
		conn.Close()
	}
}

func (p *Pool) ClientManager() {
	if p.cancel != nil {
		p.cancel()
	}
	p.ctx, p.cancel = context.WithCancel(context.Background())

	for p.ctx.Err() == nil {
		p.adjustInterval()
		capacity := int(p.capacity.Load())
		need := capacity - len(p.idChan)
		created := 0

		if need > 0 {
			var wg sync.WaitGroup
			results := make(chan int, need)
			for range need {
				wg.Go(func() {
					if p.createConnection() {
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
	if p.cancel != nil {
		p.cancel()
	}
	p.ctx, p.cancel = context.WithCancel(context.Background())

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

	if err := p.server.Serve(listener); err != nil && err != http.ErrServerClosed {
		if p.ctx.Err() == nil {
			p.errCount.Add(1)
		}
	}
}

func (p *Pool) OutgoingGet(id string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(p.ctx, timeout)
	defer cancel()

	for {
		if conn, ok := p.conns.LoadAndDelete(id); ok {
			select {
			case <-p.idChan:
			default:
			}
			return conn.(net.Conn), nil
		}

		select {
		case <-time.After(idRetryInterval):
		case <-ctx.Done():
			return nil, fmt.Errorf("OutgoingGet: connection not found")
		}
	}
}

func (p *Pool) IncomingGet(timeout time.Duration) (string, net.Conn, error) {
	ctx, cancel := context.WithTimeout(p.ctx, timeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return "", nil, fmt.Errorf("IncomingGet: insufficient connections")
		case id := <-p.idChan:
			if conn, ok := p.conns.LoadAndDelete(id); ok {
				return id, conn.(net.Conn), nil
			}
		}
	}
}

func (p *Pool) Flush() {
	var wg sync.WaitGroup
	p.conns.Range(func(key, value any) bool {
		wg.Go(func() {
			if value != nil {
				value.(net.Conn).Close()
			}
		})
		return true
	})
	wg.Wait()

	p.conns = sync.Map{}
	p.idChan = make(chan string, p.maxCap)
}

func (p *Pool) Close() {
	if p.cancel != nil {
		p.cancel()
	}
	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		p.server.Shutdown(ctx)
	}
	p.Flush()
}

func (p *Pool) Ready() bool {
	return p.ctx != nil
}

func (p *Pool) Active() int {
	return len(p.idChan)
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
	idle := len(p.idChan)
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
