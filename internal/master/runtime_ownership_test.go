package master

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConcurrentStopUsesOneGracefulWaiter(t *testing.T) {
	m := stateFixture(t)
	i, _ := m.findInstanceLocked("fixture")
	cmd := exec.Command("sh", "-c", "trap 'exit 0' TERM; printf 'ready\\n'; while :; do sleep 0.05; done")
	ready := make(chan struct{})
	writer := &readyChildWriter{ready: ready}
	cmd.Stdout = writer
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	m.dataMu.Lock()
	run := &childRun{cmd: cmd, done: make(chan struct{}), finalized: make(chan struct{})}
	i.run = run
	i.cmd = cmd
	i.Status = "running"
	m.children = 1
	m.runs.Store(run, cmd.Process)
	m.dataMu.Unlock()
	go m.MonitorInstance(i, cmd)
	<-ready
	var stops sync.WaitGroup
	for range 8 {
		stops.Go(func() { m.StopInstance(i) })
	}
	stops.Wait()
	select {
	case <-run.finalized:
	case <-time.After(time.Second):
		t.Fatal("child not finalized")
	}
	if cmd.ProcessState == nil || !cmd.ProcessState.Success() {
		t.Fatal("graceful child was killed or not reaped", cmd.ProcessState)
	}
	m.dataMu.RLock()
	defer m.dataMu.RUnlock()
	if m.children != 0 || i.run != nil || i.Status != "stopped" {
		t.Fatal("generation not retired")
	}
}

type readyChildWriter struct {
	once  sync.Once
	ready chan struct{}
}

func (w *readyChildWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("ready")) {
		w.once.Do(func() { close(w.ready) })
	}
	return len(p), nil
}
func TestStaleLogGenerationCannotMutateNewRun(t *testing.T) {
	m := stateFixture(t)
	i, _ := m.findInstanceLocked("fixture")
	old := &childRun{}
	i.run = &childRun{}
	i.TCPRX = 99
	w := NewInstanceLogWriter(i.ID, i, io.Discard, m)
	w.run = old
	w.Write([]byte("CHECK_POINT|MODE=1|PING=0ms|POOL=1|TCPS=0|UDPS=0|TCPRX=1|TCPTX=1|UDPRX=0|UDPTX=0\n"))
	if i.TCPRX != 99 {
		t.Fatal("stale run overwrote counters")
	}
}
func TestChildQuotaAndActionCoalescing(t *testing.T) {
	m := stateFixture(t)
	i, _ := m.findInstanceLocked("fixture")
	m.dataMu.Lock()
	m.children = MaxManagedChildren
	for range 1000 {
		m.queueActionLocked(i, "start")
	}
	if !i.actionWorker || i.pendingAction != "start" {
		t.Fatal("action queue not coalesced")
	}
	m.dataMu.Unlock()
	m.background.Wait()
	m.dataMu.RLock()
	defer m.dataMu.RUnlock()
	if i.run != nil || i.Status != "error" || m.children != MaxManagedChildren || i.actionWorker {
		t.Fatal("child quota or worker accounting")
	}
}
func TestImportPreflightIsAtomicAndBounded(t *testing.T) {
	for _, name := range []string{"size", "count", "invalid-suffix", "capacity"} {
		t.Run(name, func(t *testing.T) {
			m := stateFixture(t)
			path := filepath.Join(filepath.Dir(m.StatePath), ExportFileName)
			var data []byte
			valid := map[string]any{"url": "server://127.0.0.1:1/127.0.0.1:2", "restart": false}
			switch name {
			case "size":
				data = []byte("[]" + strings.Repeat(" ", MaxImportBytes))
			case "count":
				rows := make([]any, MaxImportInstances+1)
				for j := range rows {
					rows[j] = valid
				}
				data, _ = json.Marshal(rows)
			case "invalid-suffix":
				data = []byte(`[{"url":"server://127.0.0.1:1/127.0.0.1:2","restart":true},{"url":"bad://x"}]`)
			case "capacity":
				for n := 1; n < MaxManagedInstances; n++ {
					m.Instances.Store(string(rune(n+128)), &Instance{ID: string(rune(n + 128))})
				}
				data, _ = json.Marshal([]any{valid})
			}
			if e := os.WriteFile(path, data, 0600); e != nil {
				t.Fatal(e)
			}
			before := 0
			m.Instances.Range(func(_, v any) bool { before++; return true })
			m.dataMu.Lock()
			n, e := m.importLocked(context.Background())
			m.dataMu.Unlock()
			after := 0
			m.Instances.Range(func(_, v any) bool { after++; return true })
			if e == nil || n != 0 || before != after || m.children != 0 {
				t.Fatal("partial import", e, n, before, after)
			}
		})
	}
}
func TestShutdownIsSingleFlightAndRejectsActions(t *testing.T) {
	m := stateFixture(t)
	m.PeriodicDone = make(chan struct{})
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if e := m.MasterShutdown(ctx); e != nil {
				t.Error(e)
			}
		})
	}
	workers.Wait()
	i, _ := m.findInstanceLocked("fixture")
	m.ProcessInstanceAction(i, "start")
	m.dataMu.RLock()
	defer m.dataMu.RUnlock()
	if i.actionWorker || i.run != nil || !m.eventsClosed {
		t.Fatal("post-shutdown action admitted")
	}
}

func TestProcessStartRateRejectsBeforeExec(t *testing.T) {
	m := stateFixture(t)
	m.dataMu.Lock()
	defer m.dataMu.Unlock()
	i, _ := m.findInstanceLocked("fixture")
	m.startWindow = time.Now()
	m.startAttempts = MaxChildStartsPerMinute
	m.startInstanceLocked(i)
	if i.Status != "error" || i.run != nil || m.children != 0 || m.startAttempts != MaxChildStartsPerMinute {
		t.Fatal("spawn rate admission failed")
	}
}

// Fixture cleanup joins coalesced saves/actions before TempDir removal.
func (m *Master) waitForStateWork() { m.background.Wait() }
