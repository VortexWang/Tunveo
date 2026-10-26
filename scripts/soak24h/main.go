// soak24h keeps one real endpoint pair alive under a declared continuous load.
// It writes complete compressed exchange/engine evidence; it is not shipped.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/VortexWang/Tunveo/internal/client"
	"github.com/VortexWang/Tunveo/internal/common"
	"github.com/VortexWang/Tunveo/internal/server"
)

type event struct {
	Sequence    uint64  `json:"sequence"`
	Worker      int     `json:"worker"`
	Phase       string  `json:"phase"`
	Scheduled   float64 `json:"scheduled_seconds"`
	Protocol    string  `json:"protocol"`
	Local       string  `json:"local"`
	Peer        string  `json:"peer"`
	Bytes       int     `json:"bytes"`
	Sent        int     `json:"sent_bytes"`
	Received    int     `json:"received_bytes"`
	Attempts    int     `json:"attempts"`
	PayloadHash string  `json:"payload_sha256"`
	ReplyHash   string  `json:"reply_sha256"`
	Duration    float64 `json:"duration_seconds"`
	Error       string  `json:"error,omitempty"`
}
type counts struct {
	TCP     uint64 `json:"tcp"`
	UDP     uint64 `json:"udp"`
	Failed  uint64 `json:"failed"`
	Dropped uint64 `json:"dropped"`
}
type counters struct{ tcp, udp, failed, dropped atomic.Uint64 }

func (c *counters) snapshot() counts {
	return counts{c.tcp.Load(), c.udp.Load(), c.failed.Load(), c.dropped.Load()}
}

type point struct {
	At                float64 `json:"at_seconds"`
	Phase             string  `json:"phase"`
	Resources         sample  `json:"resources"`
	Counts            counts  `json:"counts"`
	MeasureSeconds    float64 `json:"measure_seconds"`
	CheckpointSeconds float64 `json:"checkpoint_seconds"`
	SnapshotSeconds   float64 `json:"snapshot_seconds"`
}
type schedulerTiming struct {
	MaxTickLag    float64 `json:"max_tick_lag_seconds"`
	MaxMeasure    float64 `json:"max_measure_seconds"`
	MaxCheckpoint float64 `json:"max_checkpoint_seconds"`
	MaxSnapshot   float64 `json:"max_snapshot_seconds"`
	MissedAt      float64 `json:"missed_at_seconds"`
	ExpectedSlot  uint64  `json:"expected_slot"`
	ObservedSlot  uint64  `json:"observed_slot"`
	MissedSlots   uint64  `json:"missed_slots"`
}
type result struct {
	Schema      int               `json:"schema_version"`
	Status      string            `json:"status"`
	Transport   int               `json:"transport"`
	Mode        int               `json:"mode"`
	Build       string            `json:"build_info"`
	Go          string            `json:"go_version"`
	Started     string            `json:"started_at"`
	Finished    string            `json:"finished_at"`
	Settings    map[string]any    `json:"settings"`
	Host        map[string]string `json:"host"`
	Measured    float64           `json:"measured_seconds"`
	Warmup      counts            `json:"warmup_counts"`
	Counts      counts            `json:"counts"`
	Idle        sample            `json:"idle_baseline"`
	Final       sample            `json:"after_stop"`
	Points      []point           `json:"points"`
	StopSeconds float64           `json:"stop_seconds"`
	Error       string            `json:"error,omitempty"`
	Scheduler   schedulerTiming   `json:"scheduler_timing"`
}
type audit struct {
	mu      sync.Mutex
	file    *os.File
	gz      *gzip.Writer
	encoder *json.Encoder
}

func newAudit(path string) (*audit, error) {
	f, e := os.Create(path)
	if e != nil {
		return nil, e
	}
	z := gzip.NewWriter(f)
	return &audit{file: f, gz: z, encoder: json.NewEncoder(z)}, nil
}
func (a *audit) write(e event) error { a.mu.Lock(); defer a.mu.Unlock(); return a.encoder.Encode(e) }
func (a *audit) close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	e := a.gz.Close()
	if e == nil {
		e = a.file.Sync()
	}
	c := a.file.Close()
	if e == nil {
		e = c
	}
	return e
}
func writeResult(path string, r *result) error {
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(path+".tmp", append(b, '\n'), 0600); e != nil {
		return e
	}
	return os.Rename(path+".tmp", path)
}
func exchangeOnce(conn net.Conn, protocol string) (event, error) {
	start := time.Now()
	size := 32768
	if protocol == "udp" {
		size = 512
	}
	e := event{Protocol: protocol, Local: conn.LocalAddr().String(), Peer: conn.RemoteAddr().String(), Bytes: size, Attempts: 1}
	if e.Local == e.Peer {
		return e, fmt.Errorf("self tuple rejected before send")
	}
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return e, err
	}
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		return e, err
	}
	digest := sha256.Sum256(payload)
	e.PayloadHash = fmt.Sprintf("%x", digest)
	n, err := conn.Write(payload)
	e.Sent = n
	if err == nil && n != size {
		err = io.ErrShortWrite
	}
	if err != nil {
		return e, err
	}
	got := make([]byte, size+1)
	if protocol == "udp" {
		n, err = conn.Read(got)
	} else {
		n, err = io.ReadFull(conn, got[:size])
	}
	e.Received = n
	if n > 0 {
		reply := sha256.Sum256(got[:n])
		e.ReplyHash = fmt.Sprintf("%x", reply)
	}
	e.Duration = time.Since(start).Seconds()
	if err != nil {
		return e, err
	}
	if n != size || !bytes.Equal(got[:n], payload) {
		return e, fmt.Errorf("payload mismatch or unexpected length")
	}
	return e, nil
}
func dial(front int, protocol string) (net.Conn, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	if protocol == "tcp" {
		d.LocalAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
	} else {
		d.LocalAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	}
	c, e := d.Dial(protocol, fmt.Sprintf("127.0.0.1:%d", front))
	if e != nil {
		return nil, e
	}
	if c.LocalAddr().String() == c.RemoteAddr().String() {
		c.Close()
		return nil, fmt.Errorf("colliding source rejected before send")
	}
	return c, nil
}

type job struct {
	sequence  uint64
	scheduled float64
	measured  bool
}

func runLoad(r *result, front, workers, qps int, warmup, duration, interval time.Duration, a *audit, engineDone <-chan error, interrupted <-chan os.Signal, checkpoint func() error, diagnostics *goroutineDiagnostics) error {
	queues := make([]chan job, workers)
	errs := make(chan error, workers+1)
	var wg sync.WaitGroup
	var measured, warmed counters
	started := time.Now()
	measuring := started.Add(warmup)
	deadline := measuring.Add(duration)
	for i := 0; i < workers; i++ {
		queues[i] = make(chan job, 1)
		id := i
		wg.Go(func() {
			udp, e := dial(front, "udp")
			if e != nil {
				errs <- e
				return
			}
			defer udp.Close()
			for j := range queues[id] {
				protocol := "tcp"
				if (j.sequence/uint64(workers)+uint64(id))%4 == 3 {
					protocol = "udp"
				}
				c := udp
				if protocol == "tcp" {
					c, e = dial(front, protocol)
				}
				row := event{Attempts: 1, Protocol: protocol}
				if e == nil {
					row, e = exchangeOnce(c, protocol)
				}
				if protocol == "tcp" && c != nil {
					c.Close()
				}
				row.Sequence = j.sequence
				row.Worker = id
				row.Scheduled = j.scheduled
				row.Phase = "warmup"
				counter := &warmed
				if j.measured {
					row.Phase = "measured"
					counter = &measured
				}
				if e != nil {
					row.Error = e.Error()
					counter.failed.Add(1)
				} else if protocol == "tcp" {
					counter.tcp.Add(1)
				} else {
					counter.udp.Add(1)
				}
				if err := a.write(row); err != nil {
					errs <- err
					return
				}
				if e != nil {
					errs <- e
					return
				}
			}
		})
	}
	warmInterval := min(interval, 2*time.Second)
	metrics := time.NewTicker(warmInterval)
	steadyTicker := false
	defer metrics.Stop()
	tick := time.NewTicker(time.Second / time.Duration(qps))
	defer tick.Stop()
	end := time.NewTimer(warmup + duration)
	defer end.Stop()
	var sequence uint64
	var slots uint64
	var failure error
	snapshot := func(phase string) error {
		start := time.Now()
		s, e := measure(0)
		elapsed := time.Since(start).Seconds()
		r.Scheduler.MaxMeasure = max(r.Scheduler.MaxMeasure, elapsed)
		if e != nil {
			return e
		}
		p := point{At: time.Since(started).Seconds(), Phase: phase, Resources: s,
			Counts: measured.snapshot(), MeasureSeconds: elapsed}
		r.Points = append(r.Points, p)
		if diagnostics != nil {
			if e := diagnostics.observe(p, warmup.Seconds()); e != nil {
				return e
			}
		}
		r.Counts = measured.snapshot()
		checkpointStart := time.Now()
		err := checkpoint()
		elapsed = time.Since(checkpointStart).Seconds()
		r.Points[len(r.Points)-1].CheckpointSeconds = elapsed
		r.Points[len(r.Points)-1].SnapshotSeconds = time.Since(start).Seconds()
		r.Scheduler.MaxCheckpoint = max(r.Scheduler.MaxCheckpoint, elapsed)
		r.Scheduler.MaxSnapshot = max(r.Scheduler.MaxSnapshot, r.Points[len(r.Points)-1].SnapshotSeconds)
		return err
	}
	if e := snapshot("warmup"); e != nil {
		failure = e
	}
loop:
	for failure == nil {
		select {
		case e := <-engineDone:
			failure = fmt.Errorf("endpoint exited during continuous load: %v", e)
		case <-interrupted:
			failure = fmt.Errorf("interrupted; partial duration is not accepted")
		case e := <-errs:
			failure = e
		case fired := <-tick.C:
			now := time.Now()
			r.Scheduler.MaxTickLag = max(r.Scheduler.MaxTickLag, now.Sub(fired).Seconds())
			if !now.Before(deadline) {
				break loop
			}
			due := uint64(now.Sub(started) / (time.Second / time.Duration(qps)))
			if due > slots+1 {
				r.Scheduler.MissedAt = now.Sub(started).Seconds()
				r.Scheduler.ExpectedSlot = slots + 1
				r.Scheduler.ObservedSlot = due
				r.Scheduler.MissedSlots = due - slots - 1
				if now.Before(measuring) {
					warmed.dropped.Add(due - slots - 1)
				} else {
					measured.dropped.Add(due - slots - 1)
				}
				failure = fmt.Errorf("scheduler missed declared offered-load ticks")
				break loop
			}
			slots = due
			j := job{sequence, time.Since(started).Seconds(), !now.Before(measuring)}
			id := sequence % uint64(workers)
			select {
			case queues[id] <- j:
				sequence++
			default:
				if j.measured {
					measured.dropped.Add(1)
				} else {
					warmed.dropped.Add(1)
				}
				failure = fmt.Errorf("declared load could not be scheduled without a drop")
			}
		case <-metrics.C:
			phase := "measured"
			if !time.Now().Before(measuring) && !steadyTicker {
				metrics.Reset(interval)
				steadyTicker = true
			}
			if time.Now().Before(measuring) {
				phase = "warmup"
			}
			if e := snapshot(phase); e != nil {
				failure = e
			}
		case <-end.C:
			break loop
		}
	}
	r.Measured = time.Since(measuring).Seconds()
	if r.Measured < 0 {
		r.Measured = 0
	}
	for _, q := range queues {
		close(q)
	}
	joined := make(chan struct{})
	go func() { wg.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(10 * time.Second):
		failure = fmt.Errorf("workers did not finish within cleanup deadline")
	}
	select {
	case e := <-errs:
		if failure == nil {
			failure = e
		}
	default:
	}
	select {
	case e := <-engineDone:
		if failure == nil {
			failure = fmt.Errorf("endpoint exited before teardown: %v", e)
		}
	default:
	}
	r.Counts = measured.snapshot()
	r.Warmup = warmed.snapshot()
	if e := snapshot("drained"); e != nil && failure == nil {
		failure = e
	}
	return failure
}
func main() {
	diagnosticFlag := flag.Bool("goroutine-diagnostics", false, "write bounded local goroutine stacks at warmup maxima and budget excursions")
	describe := flag.Bool("describe", false, "print build metadata without running")
	poolMin := flag.Int("pool-min", 16, "minimum idle pool")
	poolMax := flag.Int("pool-max", 64, "maximum negotiated pool")
	transport := flag.Int("transport", 0, "0 TCP,1 QUIC,2 WS,3 H2")
	mode := flag.Int("mode", 1, "server flow 1 or2")
	duration := flag.Duration("duration", 24*time.Hour, "continuous measured load; warmup excluded")
	warmup := flag.Duration("warmup", time.Minute, "loaded warmup")
	interval := flag.Duration("sample-interval", 30*time.Second, "GC resource interval")
	workers := flag.Int("workers", 2, "1..2 concurrent workers")
	qps := flag.Int("qps", 10, "aggregate offered requests/second,1..50")
	folder := flag.String("artifacts", "", "new output directory")
	flag.Parse()
	if *describe {
		info := ""
		if b, ok := debug.ReadBuildInfo(); ok {
			info = b.String()
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"build_info": info, "go_version": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH})
		return
	}
	if *poolMin < 1 || *poolMax < *poolMin || *poolMax > 4096 || *transport < 0 || *transport > 3 || (*mode != 1 && *mode != 2) || *duration < time.Second || *duration > 72*time.Hour || *warmup < time.Second || *interval < time.Second || *interval > time.Minute || *workers < 1 || *workers > 2 || *qps < 1 || *qps > 50 || *folder == "" {
		fmt.Fprintln(os.Stderr, "invalid soak settings")
		os.Exit(2)
	}
	if e := os.Mkdir(*folder, 0700); e != nil {
		panic(e)
	}
	r := &result{Schema: 1, Status: "running", Transport: *transport, Mode: *mode, Go: runtime.Version(), Started: time.Now().UTC().Format(time.RFC3339), Settings: map[string]any{"duration_seconds": duration.Seconds(), "warmup_seconds": warmup.Seconds(), "sample_interval_seconds": interval.Seconds(), "warmup_sample_interval_seconds": min(*interval, 2*time.Second).Seconds(), "workers": *workers, "qps": *qps, "tcp_ratio": .75, "udp_ratio": .25, "tls": 1, "pool_min": *poolMin, "pool_max": *poolMax, "application_attempts": 1, "report_interval": common.ReportInterval.String(), "udp_read_timeout": common.UDPReadTimeout.String(), "io_timeout_seconds": 3, "post_stop_goroutines": 4, "post_stop_fd": 2, "post_stop_heap": 8 * 1024 * 1024}, Host: map[string]string{"goarch": runtime.GOARCH, "goos": runtime.GOOS, "num_cpu": fmt.Sprint(runtime.NumCPU()), "gomaxprocs": fmt.Sprint(runtime.GOMAXPROCS(0))}, Points: []point{}}
	for key, path := range map[string]string{"cpuinfo": "/proc/cpuinfo", "meminfo": "/proc/meminfo", "cgroup_memory": "/sys/fs/cgroup/memory.max", "cgroup_cpu": "/sys/fs/cgroup/cpu.max", "os_release": "/etc/os-release"} {
		if b, e := os.ReadFile(path); e == nil {
			value := string(b)
			if key == "cpuinfo" {
				value = ""
				for _, line := range strings.Split(string(b), "\n") {
					if strings.HasPrefix(line, "model name") {
						value = line
						break
					}
				}
			}
			if key == "meminfo" {
				value = strings.Split(string(b), "\n")[0]
			}
			r.Host[key] = value
		}
	}
	if b, ok := debug.ReadBuildInfo(); ok {
		r.Build = b.String()
	}
	path := filepath.Join(*folder, "report.json")
	checkpoint := func() error { return writeResult(path, r) }
	if e := checkpoint(); e != nil {
		panic(e)
	}
	o, finish, e := capture(*folder)
	if e != nil {
		panic(e)
	}
	f, e := newFixture()
	if e != nil {
		panic(e)
	}
	a, e := newAudit(filepath.Join(*folder, "exchanges.jsonl.gz"))
	if e != nil {
		panic(e)
	}
	var diagnostics *goroutineDiagnostics
	if *diagnosticFlag {
		diagnostics = &goroutineDiagnostics{folder: *folder}
		r.Settings["goroutine_diagnostics"] = true
	}
	var s *server.Server
	var c *client.Client
	operation := func() error {
		r.Idle, e = measure(0)
		if e != nil {
			return e
		}
		front, tunnel, release, e := reservePorts()
		if e != nil {
			return e
		}
		release()
		r.Settings["front_port"] = front
		r.Settings["tunnel_port"] = tunnel
		st, ct := front, f.port
		if *mode == 2 {
			st, ct = ct, st
		}
		su, _ := url.Parse(fmt.Sprintf("server://soak-fixture@127.0.0.1:%d/127.0.0.1:%d?mode=%d&type=%d&tls=1&max=8&log=info", tunnel, st, *mode, *transport))
		cu, _ := url.Parse(fmt.Sprintf("client://soak-fixture@127.0.0.1:%d/127.0.0.1:%d?mode=2&min=2&log=info", tunnel, ct))
		sq := su.Query()
		sq.Set("max", strconv.Itoa(*poolMax))
		su.RawQuery = sq.Encode()
		cq := cu.Query()
		cq.Set("min", strconv.Itoa(*poolMin))
		cu.RawQuery = cq.Encode()
		s, e = server.NewServer(su, "1", nil, common.NewLogger(common.Info, false))
		if e != nil {
			return e
		}
		done := make(chan error, 2)
		go func() { done <- s.Start() }()
		if e = waitCounter(&o.pending, 1, 5*time.Second); e != nil {
			return e
		}
		c, e = client.NewClient(cu, nil, common.NewLogger(common.Info, false))
		if e != nil {
			return e
		}
		go func() { done <- c.Start() }()
		if e = waitCounter(&o.verified, 2, 15*time.Second); e != nil {
			return e
		}
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(signals)
		return runLoad(r, front, *workers, *qps, *warmup, *duration, *interval, a, done, signals, checkpoint, diagnostics)
	}
	failure := operation()
	var endpoints []endpoint
	if s != nil {
		endpoints = append(endpoints, s)
	}
	if c != nil {
		endpoints = append(endpoints, c)
	}
	r.StopSeconds, e = stop(endpoints...)
	if e != nil && failure == nil {
		failure = e
	}
	r.Final, e = settle(0, &r.Idle)
	if e != nil && failure == nil {
		failure = e
	}
	if diagnostics != nil {
		if e = diagnostics.capture("after-stop"); e != nil && failure == nil {
			failure = e
		}
	}
	if e = a.close(); e != nil && failure == nil {
		failure = e
	}
	f.close()
	finish()
	r.Settings["pid"] = os.Getpid()
	r.Settings["observed_verifications"] = o.verified.Load()
	r.Settings["observed_restarts"] = o.restarts.Load()
	r.Status = "passed"
	if failure != nil {
		r.Status = "failed"
		r.Error = failure.Error()
	}
	r.Finished = time.Now().UTC().Format(time.RFC3339)
	if e = checkpoint(); e != nil {
		panic(e)
	}
	fmt.Fprintf(os.Stderr, "transport=%d mode=%d status=%s measured=%.3f error=%s\n", *transport, *mode, r.Status, r.Measured, r.Error)
	if r.Status != "passed" {
		os.Exit(1)
	}
}
