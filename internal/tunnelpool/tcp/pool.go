package tcp

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
	life      *lifetime.Group
	idle      *idlequeue.Queue[net.Conn]
	tlsCode   string
	hostname  string
	clientIP  string
	tlsConfig *tls.Config
	dialer    func() (net.Conn, error)
	listener  net.Listener
	first     atomic.Bool
	errCount  atomic.Int32
	capacity  atomic.Int32
	minCap    int
	maxCap    int
	interval  atomic.Int64
	minIvl    time.Duration
	maxIvl    time.Duration
	keepAlive time.Duration
	ctx       context.Context
	cancel    context.CancelFunc
}

func NewClientPool(
	minCap, maxCap int,
	minIvl, maxIvl time.Duration,
	keepAlive time.Duration,
	tlsCode string,
	hostname string,
	dialer func() (net.Conn, error),
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
		idle:      idlequeue.New[net.Conn](maxCap),
		tlsCode:   tlsCode,
		hostname:  hostname,
		dialer:    dialer,
		minCap:    minCap,
		maxCap:    maxCap,
		minIvl:    minIvl,
		maxIvl:    maxIvl,
		keepAlive: keepAlive,
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
	listener net.Listener,
	keepAlive time.Duration,
) *Pool {
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
	conn, err := p.dialer()
	if err != nil {
		return false
	}

	conn.(*net.TCPConn).SetKeepAlive(true)
	conn.(*net.TCPConn).SetKeepAlivePeriod(p.keepAlive)
	tracked, ok := p.life.Bind(conn, nil)
	if !ok {
		return false
	}
	conn = tracked
	attempt.Watch(func() { tracked.Close() })

	var id string
	switch p.tlsCode {
	case "0":
	case "1":
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		})
		if err := tlsConn.HandshakeContext(attempt.Context); err != nil {
			conn.Close()
			return false
		}
		conn = tlsConn
	case "2":
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS13,
			ServerName:         p.hostname,
		})
		if err := tlsConn.HandshakeContext(attempt.Context); err != nil {
			conn.Close()
			return false
		}
		conn = tlsConn
	}

	conn.SetReadDeadline(time.Now().Add(idReadTimeout))
	buf := make([]byte, 4)
	n, err := io.ReadFull(conn, buf)
	if err != nil || n != 4 {
		conn.Close()
		return false
	}
	id = hex.EncodeToString(buf)
	conn.SetReadDeadline(time.Time{})

	if !p.idle.Commit(attempt, id, conn) {
		conn.Close()
		return false
	}
	return true
}

func (p *Pool) handleConnection(conn net.Conn) {
	attempt := p.idle.Begin(p.ctx)
	defer attempt.End()
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	if p.Active() >= p.maxCap {
		return
	}

	conn.(*net.TCPConn).SetKeepAlive(true)
	conn.(*net.TCPConn).SetKeepAlivePeriod(p.keepAlive)

	if p.clientIP != "" && conn.RemoteAddr().(*net.TCPAddr).IP.String() != p.clientIP {
		return
	}

	tracked, ok := p.life.Bind(conn, nil)
	if !ok {
		return
	}
	conn = tracked
	attempt.Watch(func() { tracked.Close() })
	if p.tlsConfig != nil {
		tlsConn := tls.Server(conn, p.tlsConfig)
		if err := tlsConn.HandshakeContext(attempt.Context); err != nil {
			return
		}
		conn = tlsConn
	}

	rawID, id, err := p.generateID()
	if err != nil {
		return
	}

	if p.idle.Contains(id) {
		return
	}

	if _, err := conn.Write(rawID); err != nil {
		return
	}

	if !p.idle.Commit(attempt, id, conn) {
		return
	}
	conn = nil
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
	if !p.life.Start() {
		return
	}

	for p.ctx.Err() == nil {
		conn, err := p.listener.Accept()
		if err != nil {
			if p.ctx.Err() != nil || err == net.ErrClosed {
				return
			}

			select {
			case <-p.ctx.Done():
				return
			case <-time.After(acceptRetryInterval):
			}
			continue
		}

		go p.handleConnection(conn)
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

func (p *Pool) Close() {
	if p.cancel != nil {
		p.cancel()
	}
	p.Flush()
}

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
