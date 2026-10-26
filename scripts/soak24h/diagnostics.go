package main

import (
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
)

// Synchronous, opt-in snapshots add no sampling goroutine or network listener.
// Counts are measured before profiling; these are adjacent observations, not
// an atomic census. Limit peak captures so a long failed run cannot fill disk.
type goroutineDiagnostics struct {
	folder      string
	warmMax     int
	measuredMax int
	highs       int
	peaks       int
	serial      int
}

func (d *goroutineDiagnostics) capture(label string) error {
	d.serial++
	path := filepath.Join(d.folder, fmt.Sprintf("goroutines-%02d-%s.txt.gz", d.serial, label))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	z := gzip.NewWriter(f)
	err = pprof.Lookup("goroutine").WriteTo(z, 2)
	if e := z.Close(); err == nil {
		err = e
	}
	if e := f.Close(); err == nil {
		err = e
	}
	return err
}

func (d *goroutineDiagnostics) observe(p point, warmupSeconds float64) error {
	if p.Phase == "warmup" && p.At >= warmupSeconds/2 {
		// Capture new warmup maxima, capped independently of measured peaks.
		if p.Resources.Goroutines > d.warmMax {
			d.warmMax = p.Resources.Goroutines
			if d.serial < 8 {
				return d.capture("warmup")
			}
		}
	} else if p.Phase == "measured" {
		newHigh := p.Resources.Goroutines > d.measuredMax
		d.measuredMax = max(d.measuredMax, p.Resources.Goroutines)
		if p.Resources.Goroutines > d.warmMax+32 && d.peaks < 8 {
			d.peaks++
			return d.capture("over-budget")
		}
		if newHigh && d.highs < 8 {
			d.highs++
			return d.capture("measured-high")
		}
	}
	return nil
}
