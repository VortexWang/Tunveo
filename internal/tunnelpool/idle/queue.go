// Package idle keeps a pool's FIFO order and ID lookup in one atomic registry.
// It owns idle entries only. Transport shutdown and run generations belong to callers.
package idle

import (
	"container/list"
	"context"
	"sync"
)

type entry[T comparable] struct {
	id    string
	value T
}

type Queue[T comparable] struct {
	mu               sync.Mutex
	limit            int
	order            list.List
	entries          map[string]*list.Element
	changed          chan struct{}
	generation       uint64
	generationCtx    context.Context
	generationCancel context.CancelFunc
}

func New[T comparable](limit int) *Queue[T] {
	if limit < 1 {
		limit = 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Queue[T]{limit: limit, entries: make(map[string]*list.Element), changed: make(chan struct{}), generationCtx: ctx, generationCancel: cancel}
}

func (q *Queue[T]) signal() { close(q.changed); q.changed = make(chan struct{}) }

// Publish transfers ownership only on success. A canceled/full/duplicate attempt
// leaves the caller responsible for closing its resource. Nothing is visible early.
func (q *Queue[T]) Publish(ctx context.Context, id string, value T) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if ctx.Err() != nil || len(q.entries) >= q.limit {
		return false
	}
	if _, ok := q.entries[id]; ok {
		return false
	}
	q.entries[id] = q.order.PushBack(entry[T]{id, value})
	q.signal()
	return true
}

func (q *Queue[T]) take(ctx context.Context, id string, byID bool, attempt *Attempt) (string, T, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		if attempt != nil && attempt.generation != q.generation {
			var zero T
			return "", zero, context.Canceled
		}
		if err := ctx.Err(); err != nil {
			var zero T
			return "", zero, err
		}
		e := q.order.Front()
		if byID {
			e = q.entries[id]
		}
		if e != nil {
			v := e.Value.(entry[T])
			delete(q.entries, v.id)
			q.order.Remove(e)
			return v.id, v.value, nil
		}
		changed := q.changed
		q.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
		}
		q.mu.Lock()
	}
}

func (q *Queue[T]) Take(ctx context.Context) (string, T, error) { return q.take(ctx, "", false, nil) }
func (q *Queue[T]) TakeID(ctx context.Context, id string) (T, error) {
	_, v, err := q.take(ctx, id, true, nil)
	return v, err
}
func (q *Queue[T]) Len() int { q.mu.Lock(); defer q.mu.Unlock(); return len(q.entries) }
func (q *Queue[T]) Contains(id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	_, ok := q.entries[id]
	return ok
}

// RemoveIfSame lets a handler clean up its own still-idle resource without
// deleting a replacement entry or a resource already transferred to a consumer.
func (q *Queue[T]) RemoveIfSame(id string, value T) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	e := q.entries[id]
	if e == nil || e.Value.(entry[T]).value != value {
		return false
	}
	delete(q.entries, id)
	q.order.Remove(e)
	return true
}

// Drain atomically detaches idle ownership. Callers close resources after the
// lock is released; Close may block or reenter the pool. A later Publish can
// repopulate this registry: Drain is not a generation fence or a permanent close.
func (q *Queue[T]) Drain() []T {
	q.mu.Lock()
	oldCancel := q.generationCancel
	q.generation++
	q.generationCtx, q.generationCancel = context.WithCancel(context.Background())
	values := make([]T, 0, len(q.entries))
	for e := q.order.Front(); e != nil; e = e.Next() {
		values = append(values, e.Value.(entry[T]).value)
	}
	q.entries = make(map[string]*list.Element)
	q.order.Init()
	q.signal()
	q.mu.Unlock()
	oldCancel()
	return values
}

// Attempt captures a Flush generation before any asynchronous setup starts.
type Attempt struct {
	Context        context.Context
	cancel         context.CancelFunc
	stopGeneration func() bool
	stopWatch      func() bool
	generation     uint64
}

func (q *Queue[T]) Begin(parent context.Context) *Attempt {
	q.mu.Lock()
	generation, epoch := q.generation, q.generationCtx
	q.mu.Unlock()
	ctx, cancel := context.WithCancel(parent)
	return &Attempt{Context: ctx, cancel: cancel, stopGeneration: context.AfterFunc(epoch, cancel), generation: generation}
}
func (a *Attempt) End() {
	if a.stopWatch != nil {
		a.stopWatch()
	}
	a.stopGeneration()
	a.cancel()
}
func (a *Attempt) Watch(close func()) { a.stopWatch = context.AfterFunc(a.Context, close) }

// WatchContext allows setup deadlines without tying the committed stream to a
// temporary request context. Detachment happens inside the publication lock.
func (a *Attempt) WatchContext(ctx context.Context, close func()) {
	a.stopWatch = context.AfterFunc(ctx, close)
}
func (q *Queue[T]) Commit(a *Attempt, id string, value T) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if a.generation != q.generation || a.Context.Err() != nil || len(q.entries) >= q.limit {
		return false
	}
	if _, ok := q.entries[id]; ok {
		return false
	}
	if a.stopWatch != nil && !a.stopWatch() {
		return false
	}
	q.entries[id] = q.order.PushBack(entry[T]{id, value})
	q.signal()
	return true
}

func (q *Queue[T]) TakeAttempt(a *Attempt, ctx context.Context) (string, T, error) {
	return q.take(ctx, "", false, a)
}
func (q *Queue[T]) TakeIDAttempt(a *Attempt, ctx context.Context, id string) (T, error) {
	_, v, e := q.take(ctx, id, true, a)
	return v, e
}
