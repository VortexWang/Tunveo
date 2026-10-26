// Controlled allocation fixture only; never used for traffic acceptance.
package main

import (
	"bufio"
	"encoding/json"
	"os"
	"runtime"
	"runtime/debug"
	"unsafe"
)

func main() {
	input := bufio.NewReader(os.Stdin)
	output := json.NewEncoder(os.Stdout)
	info, _ := debug.ReadBuildInfo()
	stage := func(name string, address uintptr, size int) {
		runtime.GC()
		output.Encode(map[string]any{"stage": name, "address": uint64(address), "size": size, "go_version": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "build_info": info.String()})
		if _, err := input.ReadString('\n'); err != nil {
			panic(err)
		}
	}
	stage("baseline", 0, 0)
	data := make([]uint64, 4*1024*1024)
	for i := range data {
		data[i] = uint64(i)
	}
	stage("touched", uintptr(unsafe.Pointer(&data[0])), len(data)*8)
	runtime.KeepAlive(data)
}
