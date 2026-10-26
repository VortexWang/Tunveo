package main

import (
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

func observeRetention(r *result, duration, interval time.Duration, scavenge bool, checkpoint func() error) error {
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
		t := time.Now()
		debug.FreeOSMemory()
		if err := appendPoint("poststop_go_scavenge", time.Since(t).Seconds()); err != nil {
			return err
		}
		// Preserve a final visible checkpoint long enough for external read-only maps.
		time.Sleep(interval)
	}
	return nil
}
