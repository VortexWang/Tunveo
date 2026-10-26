// lifecycle100 runs the real endpoint APIs repeatedly in one process. It is an
// opt-in Linux acceptance probe, not a production entry point or a benchmark.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VortexWang/Tunveo/internal/client"
	"github.com/VortexWang/Tunveo/internal/common"
	"github.com/VortexWang/Tunveo/internal/server"
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
type exchange struct {
	Protocol string `json:"protocol"`
	Local    string `json:"local"`
	Peer     string `json:"peer"`
	Bytes    int    `json:"bytes"`
	Attempts int    `json:"attempts"`
}
type cycle struct {
	Number      int        `json:"number"`
	Duration    float64    `json:"duration_seconds"`
	StopSeconds float64    `json:"stop_seconds"`
	Exchanges   []exchange `json:"exchanges"`
	Error       string     `json:"error,omitempty"`
}
type scenario struct {
	Kind       string   `json:"kind"`
	Mode       int      `json:"mode"`
	Warmup     int      `json:"warmup"`
	WarmupRows []cycle  `json:"warmup_rows"`
	Baseline   sample   `json:"baseline"`
	Samples    []sample `json:"samples"`
	Cycles     []cycle  `json:"cycles"`
	Final      sample   `json:"final"`
	Error      string   `json:"error,omitempty"`
}
type report struct {
	Schema    int            `json:"schema_version"`
	Status    string         `json:"status"`
	Transport int            `json:"transport"`
	Requested int            `json:"requested_cycles_per_scenario"`
	Started   string         `json:"started_at"`
	Finished  string         `json:"finished_at"`
	Go        string         `json:"go_version"`
	Build     string         `json:"build_info"`
	Settings  map[string]any `json:"settings"`
	Scenarios []*scenario    `json:"scenarios"`
	Error     string         `json:"error,omitempty"`
}

type observer struct{ verified, pending, restarts atomic.Int64 }

func capture(folder string) (*observer, func(), error) {
	f, err := os.Create(filepath.Join(folder, "engine.log"))
	if err != nil {
		return nil, nil, err
	}
	r, w, err := os.Pipe()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	old := os.Stdout
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
			fmt.Fprintln(f, line)
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
	return o, func() { os.Stdout = old; w.Close(); <-done; f.Close() }, nil
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
func unusedPort() (int, error) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return 0, e
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
func echo(port int, udp bool) (exchange, error) {
	proto := "tcp"
	size := 32768
	if udp {
		proto = "udp"
		size = 512
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	// Bind before connect so an empty destination cannot become a Linux self echo.
	var c net.Conn
	var err error
	for i := 0; i < 100; i++ {
		d := net.Dialer{Timeout: 3 * time.Second}
		if udp {
			d.LocalAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
		} else {
			d.LocalAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
		}
		// Reserve a non-colliding source before the single application attempt.
		if udp {
			u, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if e != nil {
				return exchange{}, e
			}
			p := u.LocalAddr().(*net.UDPAddr).Port
			u.Close()
			if p == port {
				continue
			}
			d.LocalAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p}
		}
		c, err = d.Dial(proto, addr)
		break
	}
	if err != nil {
		return exchange{}, err
	}
	if c == nil {
		return exchange{}, fmt.Errorf("no distinct source")
	}
	defer c.Close()
	x := exchange{proto, c.LocalAddr().String(), c.RemoteAddr().String(), size, 1}
	if x.Local == x.Peer {
		return x, fmt.Errorf("self tuple rejected before send")
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	payload := make([]byte, size)
	if _, err = rand.Read(payload); err != nil {
		return x, err
	}
	if _, err = c.Write(payload); err != nil {
		return x, err
	}
	got := make([]byte, size)
	if _, err = io.ReadFull(c, got); err != nil {
		return x, err
	}
	if !bytes.Equal(payload, got) {
		return x, fmt.Errorf("payload mismatch")
	}
	return x, nil
}

type runner struct {
	o         *observer
	transport int
	fixture   *fixture
	folder    string
}

func (r *runner) urls(mode int, front, tunnel int) (*url.URL, *url.URL) {
	st, ct := front, r.fixture.port
	if mode == 2 {
		st, ct = ct, st
	}
	s, _ := url.Parse(fmt.Sprintf("server://lifecycle-fixture@127.0.0.1:%d/127.0.0.1:%d?mode=%d&type=%d&tls=1&max=8&log=info", tunnel, st, mode, r.transport))
	c, _ := url.Parse(fmt.Sprintf("client://lifecycle-fixture@127.0.0.1:%d/127.0.0.1:%d?mode=2&min=2&log=info", tunnel, ct))
	return s, c
}
func (r *runner) server(u *url.URL) (*server.Server, error) {
	s, e := server.NewServer(u, "1", nil, common.NewLogger(common.Info, false))
	if e != nil {
		return nil, e
	}
	pending := r.o.pending.Load() + 1
	go func() { err := s.Start(); fmt.Fprintln(os.Stderr, "server Start returned:", err) }()
	if e = waitCounter(&r.o.pending, pending, 5*time.Second); e != nil {
		stop(s)
		return nil, e
	}
	return s, nil
}
func (r *runner) traffic(front int) ([]exchange, error) {
	var xs []exchange
	for _, udp := range []bool{false, true} {
		x, e := echo(front, udp)
		xs = append(xs, x)
		if e != nil {
			return xs, e
		}
	}
	return xs, nil
}
func (r *runner) fresh(mode, n int) (row cycle) {
	row.Number = n
	start := time.Now()
	defer func() { row.Duration = time.Since(start).Seconds() }()
	front, e := unusedPort()
	if e != nil {
		row.Error = e.Error()
		return
	}
	tunnel, e := unusedPort()
	if e != nil {
		row.Error = e.Error()
		return
	}
	su, cu := r.urls(mode, front, tunnel)
	v := r.o.verified.Load() + 2
	s, e := r.server(su)
	if e != nil {
		row.Error = e.Error()
		return
	}
	var c *client.Client
	defer func() {
		var err error
		if c != nil {
			row.StopSeconds, err = stop(s, c)
		} else {
			row.StopSeconds, err = stop(s)
		}
		if err != nil {
			row.Error += "; " + err.Error()
		}
	}()
	c, e = client.NewClient(cu, nil, common.NewLogger(common.Info, false))
	if e != nil {
		row.Error = e.Error()
		return
	}
	go func() { err := c.Start(); fmt.Fprintln(os.Stderr, "client Start returned:", err) }()
	if e = waitCounter(&r.o.verified, v, 15*time.Second); e != nil {
		row.Error = e.Error()
		return
	}
	row.Exchanges, e = r.traffic(front)
	if e != nil {
		row.Error = e.Error()
	}
	return
}
func (r *runner) runScenario(kind string, mode, cycles, warmup int, checkpoint func(*scenario)) (out *scenario) {
	out = &scenario{Kind: kind, Mode: mode, Warmup: warmup, Samples: []sample{}, Cycles: []cycle{}}
	checkpoint(out)
	defer func() { checkpoint(out) }()
	var persistent *client.Client
	var live *server.Server
	var su *url.URL
	var front int
	// Warm caches with complete endpoints; those warm-up cycles are retained separately in engine.log.
	for i := 0; i < warmup; i++ {
		x := r.fresh(mode, -i-1)
		out.WarmupRows = append(out.WarmupRows, x)
		checkpoint(out)
		if x.Error != "" {
			out.Error = "warmup: " + x.Error
			return
		}
	}
	time.Sleep(200 * time.Millisecond)
	var baselineErr error
	out.Baseline, baselineErr = settle(0, nil)
	if baselineErr != nil {
		out.Error = baselineErr.Error()
		return
	}
	if kind == "replace-server" {
		var e error
		front, e = unusedPort()
		if e != nil {
			out.Error = e.Error()
			return
		}
		tunnel, e := unusedPort()
		if e != nil {
			out.Error = e.Error()
			return
		}
		var cu *url.URL
		su, cu = r.urls(mode, front, tunnel)
		v := r.o.verified.Load() + 2
		live, e = r.server(su)
		if e != nil {
			out.Error = e.Error()
			return
		}
		persistent, e = client.NewClient(cu, nil, common.NewLogger(common.Info, false))
		if e != nil {
			stop(live)
			out.Error = e.Error()
			return
		}
		go persistent.RunWithContext(context.Background())
		defer func() {
			_, e := stop(live, persistent)
			if e != nil {
				out.Error += "; " + e.Error()
			}
			out.Final, e = settle(len(out.Cycles), &out.Baseline)
			if e != nil {
				out.Error += "; " + e.Error()
			}
		}()
		if e = waitCounter(&r.o.verified, v, 15*time.Second); e != nil {
			out.Error = e.Error()
			return
		}
		if _, e = r.traffic(front); e != nil {
			out.Error = "initial persistent connection: " + e.Error()
			return
		}
	}
	for i := 1; i <= cycles; i++ {
		var x cycle
		if kind == "fresh-pair" {
			x = r.fresh(mode, i)
		} else {
			x.Number = i
			start := time.Now()
			v := r.o.verified.Load() + 2
			var e error
			x.StopSeconds, e = stop(live)
			if e == nil {
				var replacement *server.Server
				replacement, e = r.server(su)
				if e == nil {
					live = replacement
				}
			}
			if e == nil {
				e = waitCounter(&r.o.verified, v, 15*time.Second)
			}
			if e == nil {
				x.Exchanges, e = r.traffic(front)
			}
			if e != nil {
				x.Error = e.Error()
			}
			x.Duration = time.Since(start).Seconds()
		}
		out.Cycles = append(out.Cycles, x)
		if i%10 == 0 {
			var s sample
			var e error
			if kind == "fresh-pair" {
				s, e = settle(i, &out.Baseline)
			} else {
				s, e = measure(i)
			}
			out.Samples = append(out.Samples, s)
			if e != nil {
				x.Error = e.Error()
				out.Error = x.Error
			}
		}
		checkpoint(out)
		fmt.Fprintf(os.Stderr, "transport=%d scenario=%s mode=%d cycle=%d error=%s\n", r.transport, kind, mode, i, x.Error)
		if x.Error != "" {
			out.Error = x.Error
			break
		}
	}
	if kind == "fresh-pair" {
		var e error
		out.Final, e = settle(len(out.Cycles), &out.Baseline)
		if e != nil {
			out.Error = e.Error()
		}
	}
	return
}
func writeJSON(path string, r *report) {
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		panic(e)
	}
	if e = os.WriteFile(path+".tmp", append(b, '\n'), 0600); e != nil {
		panic(e)
	}
	if e = os.Rename(path+".tmp", path); e != nil {
		panic(e)
	}
}
func main() {
	transport := flag.Int("transport", 0, "0 TCP, 1 QUIC, 2 WebSocket, 3 HTTP/2")
	cycles := flag.Int("cycles", 100, "measured cycles per scenario/flow")
	warmup := flag.Int("warmup", 5, "complete warm-up pairs before each scenario")
	folder := flag.String("artifacts", "", "new evidence directory")
	flag.Parse()
	if *transport < 0 || *transport > 3 || *cycles < 1 || *warmup < 0 || *folder == "" {
		fmt.Fprintln(os.Stderr, "invalid settings")
		os.Exit(2)
	}
	if e := os.Mkdir(*folder, 0700); e != nil {
		panic(e)
	}
	r := &report{Schema: 1, Status: "running", Transport: *transport, Requested: *cycles, Started: time.Now().UTC().Format(time.RFC3339), Go: runtime.Version(), Settings: map[string]any{"tls": 1, "pool_min": 2, "pool_max": 8, "application_attempts": 1, "readiness_seconds": 15, "stop_seconds": 5, "return_seconds": 5, "goroutine_allowance": 4, "fd_allowance": 2, "heap_alloc_allowance": 8 * 1024 * 1024, "rss": "recorded; allocator/race RSS is not a return gate", "report_interval": common.ReportInterval.String(), "service_cooldown": common.ServiceCooldown.String()}}
	if b, ok := debug.ReadBuildInfo(); ok {
		r.Build = b.String()
	}
	path := filepath.Join(*folder, "report.json")
	checkpoint := func() { writeJSON(path, r) }
	checkpoint()
	// Independent watchdog guarantees a bounded test even if an external API blocks.
	timer := time.AfterFunc(20*time.Minute, func() { fmt.Fprintln(os.Stderr, "whole probe deadline"); os.Exit(124) })
	defer timer.Stop()
	o, finish, e := capture(*folder)
	if e != nil {
		panic(e)
	}
	f, e := newFixture()
	if e != nil {
		panic(e)
	}
	run := &runner{o, *transport, f, *folder}
	for _, kind := range []string{"fresh-pair", "replace-server"} {
		for _, mode := range []int{1, 2} {
			var active *scenario
			s := run.runScenario(kind, mode, *cycles, *warmup, func(current *scenario) {
				if active == nil {
					active = current
					r.Scenarios = append(r.Scenarios, current)
				}
				checkpoint()
			})
			checkpoint()
			if s.Error != "" {
				r.Error = s.Error
				break
			}
		}
		if r.Error != "" {
			break
		}
	}
	f.close()
	r.Finished = time.Now().UTC().Format(time.RFC3339)
	r.Status = "passed"
	if r.Error != "" {
		r.Status = "failed"
		dump, _ := os.Create(filepath.Join(*folder, "goroutines.txt"))
		if dump != nil {
			pprof.Lookup("goroutine").WriteTo(dump, 2)
			dump.Close()
		}
	}
	r.Settings["observed_verifications"] = o.verified.Load()
	r.Settings["observed_client_restarts"] = o.restarts.Load()
	checkpoint()
	finish()
	fmt.Printf("transport=%d status=%s evidence=%s\n", *transport, r.Status, path)
	if r.Status != "passed" {
		os.Exit(1)
	}
}
