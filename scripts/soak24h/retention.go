package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"time"
)

// These samples have their own clock and never enter Points, Final, or budgets.
// measure() retains the existing forced-GC sampling policy, so this is NOT an
// untouched natural-idle control. Go scavenging is a separate, labelled action.
type retentionPoint struct {
	At                float64 `json:"at_seconds"`
	Phase             string  `json:"phase"`
	Resources         sample  `json:"resources"`
	GoScavengeSeconds float64 `json:"go_scavenge_seconds,omitempty"`
}

func observeRetention(r *result, duration, interval time.Duration, scavenge bool, checkpoint func() error, beforeScavenge func(retentionPoint) error) error {
	start := time.Now()
	appendPoint := func(phase string, scavengeSeconds float64) error {
		s, err := measure(0)
		if err != nil {
			return err
		}
		r.Retention = append(r.Retention, retentionPoint{At: time.Since(start).Seconds(), Phase: phase, Resources: s, GoScavengeSeconds: scavengeSeconds})
		return checkpoint()
	}
	for {
		if err := appendPoint("poststop_gc", 0); err != nil {
			return err
		}
		remaining := duration - time.Since(start)
		if remaining <= 0 {
			break
		}
		time.Sleep(min(interval, remaining))
	}
	if scavenge {
		if beforeScavenge != nil {
			if err := beforeScavenge(r.Retention[len(r.Retention)-1]); err != nil {
				return err
			}
		}
		t := time.Now()
		debug.FreeOSMemory()
		if err := appendPoint("poststop_go_scavenge", time.Since(t).Seconds()); err != nil {
			return err
		}
	}
	// Both observation-only and scavenge modes expose their last checkpoint.
	time.Sleep(interval)
	return nil
}

// The final pre-scavenge checkpoint must be observed BEFORE the action, never
// reconstructed afterwards. A stale/missing acknowledgment fails closed.
func waitRetentionObserverAck(path string, point retentionPoint, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		raw, err := os.ReadFile(path)
		if err == nil {
			var ack struct {
				Phase string  `json:"phase"`
				At    float64 `json:"at_seconds"`
			}
			if json.Unmarshal(raw, &ack) == nil && ack.Phase == point.Phase && ack.At == point.At {
				return nil
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("post-stop observer acknowledgment timeout")
		}
		time.Sleep(min(5*time.Millisecond, remaining))
	}
}
