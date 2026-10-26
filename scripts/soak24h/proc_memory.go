package main

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

// Optional diagnostic only: statm RSS remains the acceptance measurement.
// Keep the source text so aggregates can be independently re-parsed.
type procMemory struct {
	Bytes       map[string]uint64 `json:"bytes,omitempty"`
	Raw         string            `json:"smaps_rollup_raw,omitempty"`
	Error       string            `json:"error,omitempty"`
	ReadSeconds float64           `json:"read_seconds"`
}

func parseRollup(raw string) (map[string]uint64, error) {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) < 2 || !strings.HasSuffix(strings.TrimSpace(lines[0]), "[rollup]") {
		return nil, fmt.Errorf("missing smaps_rollup header")
	}
	values := make(map[string]uint64)
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) != 3 || !strings.HasSuffix(f[0], ":") || f[2] != "kB" {
			return nil, fmt.Errorf("invalid smaps_rollup field: %q", line)
		}
		key := strings.TrimSuffix(f[0], ":")
		if _, exists := values[key]; exists {
			return nil, fmt.Errorf("duplicate smaps_rollup field: %s", key)
		}
		n, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil || n > math.MaxUint64/1024 {
			return nil, fmt.Errorf("invalid smaps_rollup size: %q", line)
		}
		values[key] = n * 1024
	}
	for _, key := range []string{"Rss", "Pss", "Anonymous", "Private_Dirty", "Private_Clean", "Shared_Dirty", "Shared_Clean", "Swap"} {
		if _, ok := values[key]; !ok {
			return nil, fmt.Errorf("missing smaps_rollup field: %s", key)
		}
	}
	return values, nil
}

func readProcMemory() (p procMemory) {
	start := time.Now()
	defer func() { p.ReadSeconds = time.Since(start).Seconds() }()
	raw, err := os.ReadFile("/proc/self/smaps_rollup")
	if err != nil {
		p.Error = err.Error()
		return
	}
	p.Raw = string(raw)
	p.Bytes, err = parseRollup(p.Raw)
	if err != nil {
		p.Error = err.Error()
	}
	return
}
