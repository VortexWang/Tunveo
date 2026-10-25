package master

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VortexWang/Tunveo/internal/common"
)

func TestExplicitAPIKeyRead(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.gob")
	save := func(entries map[string]*Instance) {
		t.Helper()
		var b bytes.Buffer
		if err := gob.NewEncoder(&b).Encode(entries); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ReadAPIKey(p); err == nil {
		t.Fatal("must not create missing state")
	}
	save(map[string]*Instance{APIKeyID: {ID: APIKeyID, URL: "explicit-fixture-key"}})
	before, _ := os.ReadFile(p)
	key, err := ReadAPIKey(p)
	after, _ := os.ReadFile(p)
	if err != nil || key != "explicit-fixture-key" || !bytes.Equal(before, after) {
		t.Fatal("read changed state or key")
	}
	save(map[string]*Instance{})
	if _, err := ReadAPIKey(p); err == nil {
		t.Fatal("missing key accepted")
	}
	if err := os.WriteFile(p, []byte("malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAPIKey(p); err == nil {
		t.Fatal("corrupt state accepted")
	}
}

func TestChildLogRedaction(t *testing.T) {
	var out bytes.Buffer
	m := &Master{Common: common.NewCommon(common.NewLogger(common.None, false), nil), NotifyChannel: make(chan *InstanceEvent, 8)}
	instance := &Instance{ID: "fixture"}
	writer := NewInstanceLogWriter(instance.ID, instance, &out, m)
	data := []byte("Instance starting: server://child-secret@127.0.0.1:1/x?token=child-token\n")
	n, err := writer.Write(data)
	if err != nil || n != len(data) {
		t.Fatal("writer contract changed")
	}
	if strings.Contains(out.String(), "child-secret") || strings.Contains(out.String(), "child-token") {
		t.Fatal("child stdout leaked")
	}
	// Log SSE payload is sourced from the same sanitized line.
	select {
	case event := <-m.NotifyChannel:
		b, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("child-secret")) || bytes.Contains(b, []byte("child-token")) {
			t.Fatal("SSE log leaked")
		}
	default:
		t.Fatal("no log event")
	}
}
