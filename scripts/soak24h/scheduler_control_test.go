package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This template also runs unchanged on the frozen parent. It demonstrates a
// possible harness delay, not the cause of an uninstrumented historical miss.
func checkpointStallControl(t *testing.T) *result {
	t.Helper()
	f, err := newFixture()
	if err != nil {
		t.Fatal(err)
	}
	defer f.close()
	a, err := newAudit(filepath.Join(t.TempDir(), "events.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	r := &result{}
	calls := 0
	checkpoint := func() error {
		calls++
		if calls == 1 {
			time.Sleep(250 * time.Millisecond)
		}
		return nil
	}
	err = runLoad(r, f.port, 1, 10, time.Second, time.Second, time.Second,
		a, make(chan error), make(chan os.Signal), checkpoint, nil)
	if err == nil || !strings.Contains(err.Error(), "scheduler missed declared offered-load ticks") || r.Warmup.Dropped == 0 {
		t.Fatalf("controlled checkpoint stall was not rejected: error=%v dropped=%d", err, r.Warmup.Dropped)
	}
	r.Status, r.Error = "failed", err.Error()
	return r
}

func TestCheckpointStallControl(t *testing.T) {
	r := checkpointStallControl(t)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("CHECKPOINT-STALL-CONTROL:", string(b))
}
