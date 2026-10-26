// Native acceptance fixtures; kept separate from the frozen lifecycle100 probe.
package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type sample struct {
	Cycle      int    `json:"cycle"`
	Goroutines int    `json:"goroutines"`
	FD         int    `json:"fd"`
	HeapAlloc  uint64 `json:"heap_alloc"`
	HeapInuse  uint64 `json:"heap_inuse"`
	Sys        uint64 `json:"sys"`
	RSS        uint64 `json:"rss"`
}
type observer struct{ verified, pending, restarts atomic.Int64 }

func capture(folder string) (*observer, func(), error) {
	f, err := os.Create(filepath.Join(folder, "engine.log.gz"))
	if err != nil {
		return nil, nil, err
	}
	compressed := gzip.NewWriter(f)
	r, w, err := os.Pipe()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	os.Stdout = w
	o := new(observer)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer r.Close()
		s := bufio.NewScanner(r)
		s.Buffer(make([]byte, 4096), 1024*1024)
		for s.Scan() {
			line := s.Text()
			fmt.Fprintln(compressed, line)
			if strings.Contains(line, "RAM cert verified with sha256 fingerprint") {
				o.verified.Add(1)
			}
			if strings.Contains(line, "Pending tunnel handshake") {
				o.pending.Add(1)
			}
			if strings.Contains(line, "Client restart") {
				o.restarts.Add(1)
			}
		}
	}()
	return o, func() { w.Close(); <-done; compressed.Close(); f.Close() }, nil
}
func waitCounter(c *atomic.Int64, wanted int64, seconds time.Duration) error {
	deadline := time.Now().Add(seconds)
	for time.Now().Before(deadline) {
		if c.Load() >= wanted {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("readiness deadline: observed %d want %d", c.Load(), wanted)
}
func measure(n int) (sample, error) {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return sample{}, err
	}
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return sample{}, err
	}
	fields := strings.Fields(string(data))
	rss, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return sample{}, err
	}
	return sample{n, runtime.NumGoroutine(), len(fds), m.HeapAlloc, m.HeapInuse, m.Sys, rss * uint64(os.Getpagesize())}, nil
}
func returned(s, b sample) bool {
	return s.Goroutines <= b.Goroutines+4 && s.FD <= b.FD+2 && s.HeapAlloc <= b.HeapAlloc+8*1024*1024
}
func settle(n int, b *sample) (sample, error) {
	deadline := time.Now().Add(5 * time.Second)
	var s sample
	for {
		var err error
		s, err = measure(n)
		if err != nil {
			return s, err
		}
		if b == nil || returned(s, *b) {
			return s, nil
		}
		if time.Now().After(deadline) {
			return s, fmt.Errorf("resource return deadline: baseline=%+v final=%+v", *b, s)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

type endpoint interface{ Stop() }

func stop(endpoints ...endpoint) (float64, error) {
	start := time.Now()
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for _, e := range endpoints {
			if e != nil {
				wg.Go(e.Stop)
			}
		}
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return time.Since(start).Seconds(), nil
	case <-time.After(5 * time.Second):
		return time.Since(start).Seconds(), fmt.Errorf("endpoint Stop deadline")
	}
}

type fixture struct {
	tcp     net.Listener
	udp     *net.UDPConn
	wg      sync.WaitGroup
	accepts sync.WaitGroup
	conns   sync.Map
	port    int
}

func newFixture() (*fixture, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		l.Close()
		return nil, err
	}
	f := &fixture{tcp: l, udp: u, port: port}
	f.accepts.Go(func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			f.conns.Store(c, true)
			f.wg.Go(func() { defer f.conns.Delete(c); defer c.Close(); io.Copy(c, c) })
		}
	})
	f.wg.Go(func() {
		b := make([]byte, 65536)
		for {
			n, a, e := u.ReadFromUDP(b)
			if e != nil {
				return
			}
			u.WriteToUDP(b[:n], a)
		}
	})
	return f, nil
}
func (f *fixture) close() {
	f.tcp.Close()
	f.udp.Close()
	f.accepts.Wait()
	f.conns.Range(func(k, v any) bool { k.(net.Conn).Close(); return true })
	f.wg.Wait()
}

// Reserve TCP and UDP for both roles concurrently. Opening and immediately
// closing two :0 listeners can return the same port twice.
func reservePorts() (front, tunnel int, release func(), err error) {
	var held []io.Closer
	release = func() {
		for _, c := range held {
			c.Close()
		}
	}
	defer func() {
		if err != nil {
			release()
		}
	}()
	for i := 0; i < 2; i++ {
		var l net.Listener
		l, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return
		}
		held = append(held, l)
		port := l.Addr().(*net.TCPAddr).Port
		var u *net.UDPConn
		u, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			return
		}
		held = append(held, u)
		if i == 0 {
			front = port
		} else {
			tunnel = port
		}
	}
	return
}
