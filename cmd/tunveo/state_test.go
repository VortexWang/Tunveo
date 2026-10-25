package main

import (
	"bytes"
	"encoding/gob"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VortexWang/Tunveo/internal/master"
)

func TestStateCommandIsOfflineAndDoesNotPrintCredentials(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "nodepass.gob")
	var data bytes.Buffer
	gob.NewEncoder(&data).Encode(map[string]*master.Instance{master.APIKeyID: {ID: master.APIKeyID, URL: "cli-fixture-key", Config: "cli-fixture-mid"}})
	os.WriteFile(source, data.Bytes(), 0600)
	var out bytes.Buffer
	if e := runStateCommand([]string{"inspect", "--state", source}, &out); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), "cli-fixture") {
		t.Fatal("inspection printed credentials")
	}
	target := filepath.Join(dir, "target")
	backup := filepath.Join(dir, "backup")
	if e := runStateCommand([]string{"migrate", "--source", source, "--target", target, "--backup", backup}, &out); e == nil {
		t.Fatal("offline acknowledgement missing")
	}
	if _, e := os.Stat(target); !os.IsNotExist(e) {
		t.Fatal("failed CLI created target")
	}
	if e := runStateCommand([]string{"migrate", "--offline", "--source", source, "--target", target, "--backup", backup}, &out); e != nil {
		t.Fatal(e)
	}
}
