package master

import (
	"bytes"
	"encoding/gob"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func writeOfflineFixture(t *testing.T, path string) []byte {
	t.Helper()
	saved := map[string]*Instance{APIKeyID: {ID: APIKeyID, URL: "offline-synthetic-key", Config: "offline-synthetic-mid"}, "fixture": {ID: "fixture", Type: "server", URL: "server://fixture@127.0.0.1:12345/127.0.0.1:23456", Status: "stopped", Restart: true, Meta: Meta{Tags: map[string]string{"name": "中文"}}, TCPRX: 1<<63 + 9}}
	var data bytes.Buffer
	if e := gob.NewEncoder(&data).Encode(saved); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, data.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
	return data.Bytes()
}
func TestOfflineMigrationAndRollbackAreExactAndPrivate(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "nodepass.gob")
	original := writeOfflineFixture(t, source)
	target := filepath.Join(dir, "tunveo.gob")
	backup := source + ".backup"
	report, e := TransferState("migrate", source, target, backup)
	if e != nil || !report.BackupCreated || !report.TargetCreated || report.Instances != 1 || report.RestartEnabled != 1 {
		t.Fatal(report, e)
	}
	restored := filepath.Join(dir, "rollback.gob")
	if _, e = TransferState("restore", backup, restored, ""); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{source, target, backup, restored} {
		data, e := os.ReadFile(p)
		if e != nil || !bytes.Equal(data, original) {
			t.Fatal("state changed", p, e)
		}
		if p != source {
			info, _ := os.Stat(p)
			if info.Mode().Perm() != 0600 {
				t.Fatal("copy permissions", info.Mode())
			}
		}
	}
	summary, e := InspectState(target)
	if e != nil || !summary.APIKeyPresent || !summary.MIDPresent {
		t.Fatal(summary, e)
	}
}
func TestOfflineRefusesOverwriteAndInvalidSource(t *testing.T) {
	for _, kind := range []string{"target-exists", "backup-exists", "truncated", "trailing", "missing-key", "same-path", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "source")
			valid := writeOfflineFixture(t, source)
			target := filepath.Join(dir, "target")
			backup := filepath.Join(dir, "backup")
			switch kind {
			case "target-exists":
				os.WriteFile(target, []byte("keep"), 0600)
			case "backup-exists":
				os.WriteFile(backup, []byte("keep"), 0600)
			case "truncated":
				os.WriteFile(source, valid[:len(valid)/2], 0600)
			case "trailing":
				os.WriteFile(source, append(valid, []byte("extra")...), 0600)
			case "missing-key":
				var b bytes.Buffer
				gob.NewEncoder(&b).Encode(map[string]*Instance{})
				os.WriteFile(source, b.Bytes(), 0600)
			case "same-path":
				target = source
			case "symlink":
				if e := os.Symlink(source, target); e != nil {
					t.Skip(e)
				}
			}
			before, _ := os.ReadFile(source)
			if _, e := TransferState("migrate", source, target, backup); e == nil {
				t.Fatal("unsafe migration accepted")
			}
			after, _ := os.ReadFile(source)
			if !bytes.Equal(before, after) {
				t.Fatal("source was modified")
			}
			if kind == "target-exists" {
				data, _ := os.ReadFile(target)
				if string(data) != "keep" {
					t.Fatal("target overwritten")
				}
			}
			if kind == "backup-exists" {
				data, _ := os.ReadFile(backup)
				if string(data) != "keep" {
					t.Fatal("backup overwritten")
				}
			}
		})
	}
}
func TestConcurrentStatePublicationHasOneWinner(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	writeOfflineFixture(t, source)
	target := filepath.Join(dir, "target")
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range 8 {
		wg.Go(func() {
			if _, e := TransferState("restore", source, target, ""); e == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if wins != 1 {
		t.Fatal("non-exclusive publication", wins)
	}
	if _, e := InspectState(target); e != nil {
		t.Fatal(e)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "tunveo-state-*.tmp"))
	if len(files) != 0 {
		t.Fatal("staging file leaked")
	}
}
func TestLoadRejectsTrailingStateWithoutPublishing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state")
	data := writeOfflineFixture(t, path)
	os.WriteFile(path, append(data, []byte("bad")...), 0600)
	m := boundaryMaster()
	m.StatePath = path
	if e := m.LoadState(); e == nil {
		t.Fatal("trailing corruption accepted")
	}
	count := 0
	m.Instances.Range(func(_, v any) bool { count++; return true })
	if count != 0 || len(m.autostart) != 0 {
		t.Fatal("bad state published")
	}
	if strings.Contains(func() string { _, e := InspectState(path); return e.Error() }(), "offline-synthetic-key") {
		t.Fatal("error disclosed key")
	}
}

func TestPublishedBackupSurvivesTargetFailure(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	original := writeOfflineFixture(t, source)
	target := filepath.Join(dir, "target")
	backup := filepath.Join(dir, "backup")
	report, err := transferState("migrate", source, target, backup, func(path string, data []byte) error {
		if path == target {
			return errors.New("injected target publication failure")
		}
		return publishStateCopy(path, data)
	})
	if err == nil || !report.BackupCreated || report.TargetCreated {
		t.Fatal(report, err)
	}
	saved, _ := os.ReadFile(backup)
	if !bytes.Equal(saved, original) {
		t.Fatal("verified backup lost")
	}
	if _, err = os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("failed publication left a target")
	}
}
