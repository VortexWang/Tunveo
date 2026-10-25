package master

import (
	"encoding/gob"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestDetachedMetadataAndLegacyGOBFields(t *testing.T) {
	m := stateFixture(t)
	m.dataMu.Lock()
	live, _ := m.findInstanceLocked("fixture")
	live.Meta.Tags["revision"] = "before"
	live.TCPRX = 1<<63 + 7
	m.sendSSEEventLocked("initial", live)
	m.dataMu.Unlock()
	event := <-m.NotifyChannel
	snapshot, _ := m.FindInstance("fixture")
	snapshot.Meta.Tags["revision"] = "changed outside registry"
	m.dataMu.RLock()
	if live.Meta.Tags["revision"] != "before" || event.Instance.Meta.Tags["revision"] != "before" {
		t.Fatal("metadata alias escaped")
	}
	m.dataMu.RUnlock()
	if e := m.SaveState(); e != nil {
		t.Fatal(e)
	}
	// Gob matches exported fields by name. Unexported runtime ownership does not
	// change the legacy persisted shape or round large counters through float64.
	type legacy struct {
		ID, Alias, Type, Status, URL, Config string
		Restart                              bool
		Meta                                 Meta
		TCPRX                                uint64
	}
	f, e := os.Open(m.StatePath)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	var saved map[string]*legacy
	if e = gob.NewDecoder(f).Decode(&saved); e != nil {
		t.Fatal(e)
	}
	if saved["fixture"].TCPRX != 1<<63+7 || saved["fixture"].Meta.Tags["revision"] != "before" {
		t.Fatal("legacy field compatibility")
	}
}
func TestInvalidRestoreDoesNotPartiallyAutostartOrRewrite(t *testing.T) {
	m := stateFixture(t)
	m.Instances.Clear()
	f, e := os.Create(m.StatePath)
	if e != nil {
		t.Fatal(e)
	}
	original := map[string]*Instance{"valid": {ID: "valid", Type: "server", URL: "server://127.0.0.1:1/127.0.0.1:2", Restart: true}, "invalid": {ID: "different", URL: "bad://fixture"}}
	if e = gob.NewEncoder(f).Encode(original); e != nil {
		t.Fatal(e)
	}
	f.Close()
	before, _ := os.ReadFile(m.StatePath)
	if e = m.LoadState(); e == nil {
		t.Fatal("invalid restore accepted")
	}
	after, _ := os.ReadFile(m.StatePath)
	count := 0
	m.Instances.Range(func(_, v any) bool { count++; return true })
	if string(before) != string(after) || count != 0 || m.children != 0 || len(m.autostart) != 0 {
		t.Fatal("restore had partial effects")
	}
}
func TestInvalidPatchDoesNotApplyAliasPrefix(t *testing.T) {
	m := stateFixture(t)
	r := httptest.NewRequest("PATCH", "/api/v1/instances/fixture", strings.NewReader(`{"alias":"changed","meta":{"tags":{"bad":"`+strings.Repeat("x", MaxValueLen+1)+`"}}}`))
	r.Header.Set("X-API-Key", "state-fixture-key")
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, r)
	snapshot, _ := m.FindInstance("fixture")
	if w.Code != 400 || snapshot.Alias != "before" {
		t.Fatal("partial metadata mutation")
	}
}
