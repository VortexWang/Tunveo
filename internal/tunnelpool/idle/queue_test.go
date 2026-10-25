package idle

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMatchingTakePreservesOtherFIFOEntries(t *testing.T) {
	q := New[int](4)
	ctx := context.Background()
	for i, id := range []string{"a", "b", "c"} {
		if !q.Publish(ctx, id, i+1) {
			t.Fatal("publish")
		}
	}
	if v, err := q.TakeID(ctx, "b"); err != nil || v != 2 {
		t.Fatal("matching take", v, err)
	}
	for _, want := range []string{"a", "c"} {
		id, _, err := q.Take(ctx)
		if err != nil || id != want {
			t.Fatal("FIFO entry lost", id, err)
		}
	}
	if q.Len() != 0 {
		t.Fatal("idle count diverged")
	}
}

func TestRejectedPublishKeepsRegistryAndOwnership(t *testing.T) {
	q := New[int](1)
	ctx := context.Background()
	if !q.Publish(ctx, "one", 1) {
		t.Fatal("publish")
	}
	if q.Publish(ctx, "one", 2) || q.Publish(ctx, "two", 2) {
		t.Fatal("duplicate/full accepted")
	}
	id, v, err := q.Take(ctx)
	if err != nil || id != "one" || v != 1 {
		t.Fatal("original entry overwritten")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if q.Publish(canceled, "cancelled", 3) || q.Len() != 0 {
		t.Fatal("canceled publish retained an entry")
	}
}

func TestWaitsRespectCancellationAndDeadlines(t *testing.T) {
	q := New[int](2)
	for _, byID := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		var err error
		if byID {
			_, err = q.TakeID(ctx, "missing")
		} else {
			_, _, err = q.Take(ctx)
		}
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("missing deadline", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	q.Publish(context.Background(), "keep", 1)
	if _, _, err := q.Take(ctx); !errors.Is(err, context.Canceled) || q.Len() != 1 {
		t.Fatal("canceled getter consumed resource")
	}
}

func TestConcurrentConsumersClaimEachEntryOnce(t *testing.T) {
	const total = 128
	q := New[int](total)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	seen := make([]atomic.Int32, total)
	var wg sync.WaitGroup
	for i := range total {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := q.TakeID(ctx, fmt.Sprint(i))
			if err != nil {
				t.Error(err)
				return
			}
			seen[v].Add(1)
		}()
	}
	for i := range total {
		if !q.Publish(ctx, fmt.Sprint(i), i) {
			t.Fatal("publish")
		}
	}
	wg.Wait()
	for i := range total {
		if seen[i].Load() != 1 {
			t.Fatal("duplicate/missing ID", i)
		}
	}
	// Mix FIFO and specific-ID waiters on the same ID: exactly one may win.
	for range 32 {
		pair, cancel := context.WithCancel(context.Background())
		done := make(chan error, 2)
		go func() { _, _, err := q.Take(pair); done <- err }()
		go func() { _, err := q.TakeID(pair, "shared"); done <- err }()
		if !q.Publish(pair, "shared", 9) {
			t.Fatal("publish")
		}
		if err := <-done; err != nil {
			t.Fatal("first claimant", err)
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal("resource claimed twice", err)
		}
	}
}

func TestDrainAndHandlerCleanupDoNotDeleteReplacement(t *testing.T) {
	q := New[int](2)
	ctx := context.Background()
	q.Publish(ctx, "same", 1)
	old := q.Drain()
	if len(old) != 1 || old[0] != 1 || q.Len() != 0 {
		t.Fatal("drain")
	}
	if !q.Publish(ctx, "same", 2) {
		t.Fatal("publish replacement")
	}
	if q.RemoveIfSame("same", 1) {
		t.Fatal("stale handler removed replacement")
	}
	if !q.RemoveIfSame("same", 2) || q.Len() != 0 {
		t.Fatal("cleanup failed")
	}
	// Drain does not permanently close the registry.
	q.Publish(ctx, "after", 3)
	v, err := q.TakeID(ctx, "after")
	if err != nil || v != 3 {
		t.Fatal(err)
	}
}

func TestFlushFencesPendingPublicationAndWaiters(t *testing.T) {
	q := New[int](2)
	ctx := context.Background()
	old := q.Begin(ctx)
	defer old.End()
	q.Drain()
	if q.Commit(old, "stale", 1) {
		t.Fatal("old publication crossed Flush")
	}
	fresh := q.Begin(ctx)
	defer fresh.End()
	if !q.Commit(fresh, "fresh", 2) {
		t.Fatal("new publication")
	}
	if _, err := q.TakeIDAttempt(old, ctx, "fresh"); !errors.Is(err, context.Canceled) {
		t.Fatal("old getter consumed new generation", err)
	}
	if v, err := q.TakeIDAttempt(fresh, ctx, "fresh"); err != nil || v != 2 {
		t.Fatal("new getter lost entry", err)
	}
}

func TestCommitDetachesTemporarySetupCancellation(t *testing.T) {
	q := New[int](1)
	a := q.Begin(context.Background())
	var aborted atomic.Bool
	a.Watch(func() { aborted.Store(true) })
	if !q.Commit(a, "one", 1) {
		t.Fatal("commit")
	}
	a.End()
	if aborted.Load() {
		t.Fatal("published resource kept setup cancellation")
	}
	q.Drain()
	if aborted.Load() {
		t.Fatal("Flush canceled committed lease via setup callback")
	}
}
