package main

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func diagnosticPark(ready, release chan struct{}) {
	close(ready)
	<-release
}

func TestDiagnosticCaptureContainsLiveStackAndIsBounded(t *testing.T) {
	ready, release := make(chan struct{}), make(chan struct{})
	go diagnosticPark(ready, release)
	<-ready
	defer close(release)
	d := &goroutineDiagnostics{folder: t.TempDir()}
	observe := func(at float64, phase string, count int) {
		t.Helper()
		if err := d.observe(point{At: at, Phase: phase, Resources: sample{Goroutines: count}}, 12); err != nil {
			t.Fatal(err)
		}
	}
	// Exactly the later warmup window used by the acceptance validator.
	observe(2, "warmup", 200)
	observe(6, "warmup", 29)
	observe(8, "warmup", 27)
	observe(13, "measured", 61)
	if d.serial != 2 {
		t.Fatal("incorrect baseline or threshold", d)
	}
	for range 20 {
		observe(42, "measured", 64)
	}
	if d.peaks != 8 || d.serial != 10 {
		t.Fatal("unbounded peak snapshots", d)
	}
	if err := d.capture("after-stop"); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(d.folder, "*.gz"))
	if err != nil || len(files) != 11 {
		t.Fatal(files, err)
	}
	f, err := os.Open(files[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	b, err := io.ReadAll(z)
	if err != nil || !strings.Contains(string(b), "diagnosticPark") {
		t.Fatal("live blocked stack absent", err)
	}
	info, err := f.Stat()
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("stack file must be private", err)
	}
}

func TestDiagnosticCaptureFailureIsReturned(t *testing.T) {
	d := &goroutineDiagnostics{folder: filepath.Join(t.TempDir(), "absent")}
	if err := d.capture("warmup"); err == nil {
		t.Fatal("missing evidence silently accepted")
	}
}
