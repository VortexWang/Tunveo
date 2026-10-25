package master

import (
	"context"
	"errors"
	"os"
	"sync"
)

// Shutdown is single-flight. Expiring callers force-close the HTTP server and
// signal every still-tracked child; cleanup retains ownership until reaping.
func (m *Master) MasterShutdown(ctx context.Context) error {
	m.shutdownOnce.Do(func() {
		m.managementStopped.Store(true)
		m.shutdownDone = make(chan struct{})
		go func() { m.shutdownErr = m.shutdown(ctx); close(m.shutdownDone) }()
	})
	select {
	case <-m.shutdownDone:
		return m.shutdownErr
	case <-ctx.Done():
		m.killTrackedChildren()
		if m.Server != nil {
			m.Server.Close()
		}
		return ctx.Err()
	}
}
func (m *Master) killTrackedChildren() {
	m.runs.Range(func(_, v any) bool { v.(*os.Process).Kill(); return true })
}
func (m *Master) shutdown(ctx context.Context) error {
	m.dataMu.Lock()
	m.managementStopped.Store(true)
	if m.PeriodicDone != nil {
		close(m.PeriodicDone)
	}
	var instances []*Instance
	m.Instances.Range(func(_, v any) bool {
		i := v.(*Instance)
		if i.run != nil {
			instances = append(instances, i)
		}
		return true
	})
	m.dataMu.Unlock()
	m.ShutdownSSEConnections()
	apiDone := make(chan error, 1)
	go func() {
		if m.Server != nil {
			apiDone <- m.Server.Shutdown(ctx)
		} else {
			apiDone <- nil
		}
	}()
	var stops sync.WaitGroup
	for _, i := range instances {
		stops.Go(func() { m.dataMu.Lock(); defer m.dataMu.Unlock(); m.stopInstanceLocked(ctx, i) })
	}
	stopDone := make(chan struct{})
	go func() { stops.Wait(); m.background.Wait(); close(stopDone) }()
	err := waitContext(ctx, stopDone)
	if err != nil {
		m.killTrackedChildren()
	}
	// Wait completion is generation-specific; never call Process.Wait a second time.
	var runs []*childRun
	m.runs.Range(func(k, _ any) bool { runs = append(runs, k.(*childRun)); return true })
	for _, r := range runs {
		if e := waitContext(ctx, r.finalized); e != nil {
			err = errors.Join(err, e)
			break
		}
	}
	if e := <-apiDone; e != nil {
		err = errors.Join(err, e)
		if m.Server != nil {
			m.Server.Close()
		}
	}
	m.eventMu.Lock()
	if !m.eventsClosed {
		m.eventsClosed = true
		if m.NotifyChannel != nil {
			close(m.NotifyChannel)
		}
	}
	m.eventMu.Unlock()
	// Do not claim final persistence after a deadline while active work is unresolved.
	if err == nil {
		err = m.SaveState()
	}
	return err
}
