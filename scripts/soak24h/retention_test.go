package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

func TestRetentionDoesNotRewriteLoadOrReturnSamples(t *testing.T) {
	r := &result{Points: []point{{Phase: "measured", Resources: sample{RSS: 123}}}, Final: sample{RSS: 456}, Counts: counts{TCP: 99}}
	if err := observeRetention(r, time.Millisecond, time.Millisecond, true, func() error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	if r.Points[0].Resources.RSS != 123 || r.Final.RSS != 456 || r.Counts.TCP != 99 {
		t.Fatal("diagnostics overwrote budget evidence")
	}
	if len(r.Retention) < 2 || r.Retention[0].Phase != "poststop_gc" || r.Retention[len(r.Retention)-1].Phase != "poststop_go_scavenge" || r.Retention[len(r.Retention)-1].GoScavengeSeconds <= 0 {
		t.Fatalf("missing isolated phases: %+v", r.Retention)
	}
	r = &result{}
	sentinel := errors.New("checkpoint unavailable")
	if err := observeRetention(r, time.Millisecond, time.Millisecond, true, func() error { return sentinel }, nil); !errors.Is(err, sentinel) || len(r.Retention) != 1 {
		t.Fatalf("continued after failed checkpoint: %+v %v", r.Retention, err)
	}
}

func TestGoScavengeCalibrationOnReleasedAllocation(t *testing.T) {
	held := func() sample {
		data := make([]byte, 32*1024*1024)
		for i := 0; i < len(data); i += 4096 {
			data[i] = 1
		}
		s, err := measure(0)
		if err != nil {
			t.Fatal(err)
		}
		runtime.KeepAlive(data)
		return s
	}()
	gcOnly, err := measure(0)
	if err != nil {
		t.Fatal(err)
	}
	debug.FreeOSMemory()
	scavenged, err := measure(0)
	if err != nil {
		t.Fatal(err)
	}
	if gcOnly.HeapAlloc+24*1024*1024 > held.HeapAlloc || scavenged.HeapReleased < held.HeapReleased+16*1024*1024 {
		t.Fatalf("released Go allocation was not observed: held=%+v gc=%+v scavenged=%+v", held, gcOnly, scavenged)
	}
	raw, _ := json.Marshal(map[string]sample{"held": held, "gc_only": gcOnly, "go_scavenged": scavenged})
	t.Logf("GO-SCAVENGE-CONTROL: %s", raw)
}

func TestRetentionObserverHandshakeRejectsStaleOrMissingAck(t *testing.T) {
	p := retentionPoint{At: 120.123, Phase: "poststop_gc"}
	path := filepath.Join(t.TempDir(), "ack.json")
	if err := waitRetentionObserverAck(path, p, time.Millisecond); err == nil {
		t.Fatal("missing ack accepted")
	}
	raw, _ := json.Marshal(map[string]any{"phase": p.Phase, "at_seconds": p.At - 1})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := waitRetentionObserverAck(path, p, time.Millisecond); err == nil {
		t.Fatal("stale ack accepted")
	}
	raw, _ = json.Marshal(map[string]any{"phase": p.Phase, "at_seconds": p.At})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := waitRetentionObserverAck(path, p, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	r := &result{}
	sentinel := errors.New("observer absent")
	if err := observeRetention(r, time.Millisecond, time.Millisecond, true, func() error { return nil }, func(retentionPoint) error { return sentinel }); !errors.Is(err, sentinel) || r.Retention[len(r.Retention)-1].Phase != "poststop_gc" {
		t.Fatal("scavenged before observer acknowledgment")
	}
}

func TestRetentionObservationOnlyDoesNotScavenge(t *testing.T) {
	r := &result{}
	if err := observeRetention(r, time.Millisecond, time.Millisecond, false, func() error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	for _, p := range r.Retention {
		if p.Phase != "poststop_gc" || p.GoScavengeSeconds != 0 {
			t.Fatal("observation-only mode scavenged")
		}
	}
	if len(r.Retention) == 0 {
		t.Fatal("missing observation")
	}
}
