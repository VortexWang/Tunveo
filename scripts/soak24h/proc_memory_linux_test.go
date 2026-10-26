//go:build linux

package main

import (
	"syscall"
	"testing"
)

// Touch an explicitly anonymous mapping; this establishes page semantics, not
// attribution of tunnel or race allocations. Keep it mapped until both reads.
func TestRollupObservesTouchedAnonymousMapping(t *testing.T) {
	before := readProcMemory()
	if before.Error != "" {
		t.Fatal(before.Error)
	}
	const size = 16 * 1024 * 1024
	data, err := syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Munmap(data)
	for i := 0; i < len(data); i += syscall.Getpagesize() {
		data[i] = 1
	}
	after := readProcMemory()
	if after.Error != "" {
		t.Fatal(after.Error)
	}
	for _, key := range []string{"Rss", "Anonymous", "Private_Dirty"} {
		// Leave room for unrelated concurrent runtime page reclamation.
		if int64(after.Bytes[key])-int64(before.Bytes[key]) < size-4*1024*1024 {
			t.Fatalf("%s did not observe touched mapping: before=%d after=%d", key, before.Bytes[key], after.Bytes[key])
		}
	}
	t.Logf("OS-MEMORY-CONTROL before=%+v after=%+v", before.Bytes, after.Bytes)
}
