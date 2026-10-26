package main

import "testing"

func TestRejectedCheckpointStallHasTimingEvidence(t *testing.T) {
	r := checkpointStallControl(t)
	s := r.Scheduler
	if s.MaxCheckpoint < .2 || s.MaxSnapshot < s.MaxCheckpoint || s.MaxTickLag < .1 || s.MissedSlots == 0 || s.ObservedSlot <= s.ExpectedSlot {
		t.Fatalf("incomplete timing evidence: %+v", s)
	}
	if len(r.Points) == 0 || r.Points[0].CheckpointSeconds < .2 || r.Points[0].Resources.HeapSys == 0 || r.Points[0].Resources.TotalAlloc == 0 {
		t.Fatalf("missing point or memory evidence: %+v", r.Points)
	}
}
