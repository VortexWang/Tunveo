package master

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
)

const (
	MaxManagedInstances   = 1024
	MaxManagedChildren    = 64
	MaxImportBytes        = 8 << 20
	MaxImportInstances    = 256
	maxManagementResponse = 16 << 20
)

// Instance fields belong to dataMu. Control handlers execute a transaction into
// a bounded response buffer; only the detached bytes reach a network writer.
// Process waits explicitly release dataMu so stdout/Wait can complete.
func cloneInstance(i *Instance) *Instance {
	if i == nil {
		return nil
	}
	c := *i
	c.Meta.Tags = make(map[string]string, len(i.Meta.Tags))
	for k, v := range i.Meta.Tags {
		c.Meta.Tags[k] = v
	}
	return &c
}
func (m *Master) snapshots() []*Instance {
	m.dataMu.RLock()
	defer m.dataMu.RUnlock()
	var out []*Instance
	m.Instances.Range(func(_, v any) bool { out = append(out, cloneInstance(v.(*Instance))); return true })
	return out
}

type controlResponse struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	overflow bool
}

func (w *controlResponse) Header() http.Header { return w.header }
func (w *controlResponse) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
}
func (w *controlResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	if w.body.Len()+len(p) > maxManagementResponse {
		w.overflow = true
		return 0, fmt.Errorf("management response exceeds limit")
	}
	return w.body.Write(p)
}
func (m *Master) serialized(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.controlOnce.Do(func() { m.controlGate = make(chan struct{}, 1) })
		select {
		case m.controlGate <- struct{}{}:
		case <-r.Context().Done():
			return
		}
		defer func() { <-m.controlGate }()
		response := &controlResponse{header: http.Header{}}
		func() {
			m.dataMu.Lock()
			defer m.dataMu.Unlock()
			if m.managementStopped.Load() {
				HTTPError(response, "Management is stopping", 503)
				return
			}
			next(response, r)
		}()
		if response.overflow {
			HTTPError(w, "Management response too large", http.StatusInsufficientStorage)
			return
		}
		for k, vs := range response.header {
			w.Header()[k] = append([]string(nil), vs...)
		}
		code := response.status
		if code == 0 {
			code = 200
		}
		w.WriteHeader(code)
		w.Write(response.body.Bytes())
	}
}

// Add/check is serialized with all REST/MCP creation and shutdown admission.
func (m *Master) registerLocked(i *Instance) error {
	if err := validateInstance(i); err != nil {
		return err
	}
	if m.managementStopped.Load() {
		return fmt.Errorf("management is stopping")
	}
	count := 0
	m.Instances.Range(func(k, v any) bool {
		if k.(string) != APIKeyID {
			count++
		}
		return true
	})
	if count >= MaxManagedInstances {
		return fmt.Errorf("managed instance limit reached")
	}
	if _, ok := m.Instances.Load(i.ID); ok {
		return fmt.Errorf("instance ID already exists")
	}
	m.Instances.Store(i.ID, i)
	return nil
}
func (m *Master) requestSaveLocked() {
	if m.managementStopped.Load() {
		return
	}
	m.savePending = true
	if m.saveRunning {
		return
	}
	m.saveRunning = true
	m.background.Add(1)
	go func() {
		defer m.background.Done()
		for {
			m.dataMu.Lock()
			if !m.savePending || m.managementStopped.Load() {
				m.saveRunning = false
				m.dataMu.Unlock()
				return
			}
			m.savePending = false
			m.dataMu.Unlock()
			if err := m.SaveState(); err != nil {
				m.Logger.Error("SaveState: %v", err)
			}
		}
	}()
}
func waitContext(ctx context.Context, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Master) pingUnlocked(ctx context.Context, target string) *TCPingResult {
	m.dataMu.Unlock()
	defer m.dataMu.Lock()
	return m.PerformTCPingContext(ctx, target)
}
