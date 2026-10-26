package main

import (
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func pipeFDs(t *testing.T) int {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name()))
		if err == nil && strings.HasPrefix(link, "pipe:") {
			n++
		}
	}
	return n
}
func TestFixturePipeFDIsolation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux splice fixture proof")
	}
	for _, mode := range []string{"raw", "fixture"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFixturePipeFDChild$", "-test.v")
		cmd.Env = append(os.Environ(), "TUNVEO_FD_CHILD="+mode, "GORACE=atexit_sleep_ms=0")
		out, err := cmd.CombinedOutput()
		t.Logf("mode=%s\n%s", mode, out)
		if err != nil {
			t.Fatalf("fixture FD isolation: %s: %v", mode, err)
		}
	}
}
func TestFixturePipeFDChild(t *testing.T) {
	mode := os.Getenv("TUNVEO_FD_CHILD")
	if mode == "" {
		t.Skip("subprocess-only native fixture")
	}
	var port int
	var closeFixture func()
	if mode == "fixture" {
		f, err := newFixture()
		if err != nil {
			t.Fatal(err)
		}
		port = f.port
		closeFixture = f.close
	} else {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port = l.Addr().(*net.TCPAddr).Port
		var wg sync.WaitGroup
		var readers sync.WaitGroup
		wg.Go(func() {
			for {
				c, e := l.Accept()
				if e != nil {
					return
				}
				readers.Go(func() { defer c.Close(); io.Copy(c, c) })
			}
		})
		closeFixture = func() { l.Close(); wg.Wait(); readers.Wait() }
	}
	baseline := pipeFDs(t)
	var clients []net.Conn
	defer func() {
		for _, c := range clients {
			c.Close()
		}
		closeFixture()
	}()
	for range 4 {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
		c.SetDeadline(time.Now().Add(time.Second))
		data := bytes.Repeat([]byte{0x43}, 32768)
		if _, err = c.Write(data); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(data))
		if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(data, got) {
			t.Fatal("native echo failed", err)
		}
	}
	actual := pipeFDs(t)
	if mode == "raw" {
		if actual < baseline+8 {
			t.Fatalf("expected leased splice pipes: baseline=%d actual=%d", baseline, actual)
		}
		t.Logf("RAW-SPLICE-PIPES baseline=%d actual=%d", baseline, actual)
	} else {
		if actual > baseline {
			t.Fatalf("FIXTURE-PIPE-CONTAMINATION baseline=%d actual=%d", baseline, actual)
		}
		t.Logf("FIXTURE-NO-PIPE-INCREASE baseline=%d actual=%d", baseline, actual)
	}
}
