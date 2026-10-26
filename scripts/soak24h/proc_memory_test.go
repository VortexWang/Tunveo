package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestRollupRejectsUntrustworthyEvidence(t *testing.T) {
	raw := "1000-2000 ---p 00000000 00:00 0 [rollup]\n"
	for _, key := range []string{"Rss", "Pss", "Anonymous", "Private_Dirty", "Private_Clean", "Shared_Dirty", "Shared_Clean", "Swap"} {
		raw += fmt.Sprintf("%s: 17 kB\n", key)
	}
	v, err := parseRollup(raw)
	if err != nil || v["Rss"] != 17*1024 {
		t.Fatalf("conversion: %v %v", v, err)
	}
	for name, bad := range map[string]string{
		"header":    strings.Replace(raw, "[rollup]", "[heap]", 1),
		"unit":      strings.Replace(raw, "17 kB", "17 MB", 1),
		"overflow":  strings.Replace(raw, "17 kB", "18014398509481984 kB", 1),
		"negative":  strings.Replace(raw, "17 kB", "-1 kB", 1),
		"missing":   strings.Replace(raw, "Rss: 17 kB\n", "", 1),
		"duplicate": raw + "Rss: 17 kB\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRollup(bad); err == nil {
				t.Fatal("accepted corrupt evidence")
			}
		})
	}
}
