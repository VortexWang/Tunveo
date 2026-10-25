package master

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var expectStateSnapshotFailure = false

func stateFixture(t *testing.T) *Master {
	t.Helper()
	m := boundaryMaster()
	m.StatePath = filepath.Join(t.TempDir(), "state.gob")
	t.Cleanup(func() {
		if waiter, ok := any(m).(interface{ waitForStateWork() }); ok {
			waiter.waitForStateWork()
		} else {
			time.Sleep(200 * time.Millisecond)
			m.StateMu.Lock()
			m.StateMu.Unlock()
		}
	})
	m.Instances.Store(APIKeyID, &Instance{ID: APIKeyID, URL: "state-fixture-key"})
	m.Instances.Store("fixture", &Instance{ID: "fixture", Alias: "before", Type: "server", URL: "server://127.0.0.1:1/127.0.0.1:2", Status: "stopped", Meta: Meta{Tags: map[string]string{}}})
	return m
}
func statePatch(m *Master, alias string) {
	r := httptest.NewRequest("PATCH", "/api/v1/instances/fixture", strings.NewReader(fmt.Sprintf(`{"alias":%q,"meta":{"tags":{"revision":%q}}}`, alias, alias)))
	r.Header.Set("X-API-Key", "state-fixture-key")
	m.Handler().ServeHTTP(httptest.NewRecorder(), r)
}
func TestInstanceLogAndManagementSerialization(t *testing.T) {
	m := stateFixture(t)
	instance, _ := m.FindInstance("fixture")
	w := NewInstanceLogWriter("fixture", instance, io.Discard, m)
	stop := make(chan struct{})
	consumed := make(chan struct{})
	go func() {
		defer close(consumed)
		for {
			select {
			case e := <-m.NotifyChannel:
				json.Marshal(e)
			case <-stop:
				return
			}
		}
	}()
	var work sync.WaitGroup
	work.Go(func() {
		for n := range 100 {
			w.Write([]byte(fmt.Sprintf("CHECK_POINT|MODE=1|PING=1ms|POOL=2|TCPS=1|UDPS=0|TCPRX=%d|TCPTX=%d|UDPRX=0|UDPTX=0\n", n, n)))
		}
	})
	work.Go(func() {
		for n := range 100 {
			statePatch(m, fmt.Sprintf("alias-%d", n))
		}
	})
	work.Go(func() {
		for range 100 {
			r := httptest.NewRequest("GET", "/api/v1/instances", nil)
			r.Header.Set("X-API-Key", "state-fixture-key")
			m.Handler().ServeHTTP(httptest.NewRecorder(), r)
		}
	})
	work.Go(func() {
		for range 10 {
			m.SaveState()
		}
	})
	work.Wait()
	close(stop)
	<-consumed
	m.StateMu.Lock()
	m.StateMu.Unlock()
	t.Log("STATE-CONCURRENCY: finished production log, PATCH, GET, GOB, queued-event serialization")
}
func TestQueuedInstanceEventIsSnapshot(t *testing.T) {
	m := stateFixture(t)
	instance, _ := m.FindInstance("fixture")
	m.SendSSEEvent("initial", instance)
	event := <-m.NotifyChannel
	statePatch(m, "after")
	broken := event.Instance.Alias != "before"
	if expectStateSnapshotFailure {
		if !broken {
			t.Fatal("expected live event reference")
		}
		t.Log("REPRODUCED-SNAPSHOT:")
		return
	}
	if broken {
		t.Fatal("queued event changed after publication")
	}
	t.Log("PASSED-SNAPSHOT:")
	m.StateMu.Lock()
	m.StateMu.Unlock()
}
