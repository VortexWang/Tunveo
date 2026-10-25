package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/VortexWang/Tunveo/internal/common"
)

func TestStopCancelsPendingHandshakeAndRejectsReuse(t *testing.T) {
	entered := make(chan struct{})
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }))
	defer remote.Close()
	u, _ := url.Parse("client://fixture@" + strings.TrimPrefix(remote.URL, "https://") + "/127.0.0.1:1?mode=2")
	c, err := NewClient(u, nil, common.NewLogger(common.None, false))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Start() }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("no handshake")
	}
	stopped := make(chan struct{})
	go func() { c.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop left handshake blocked")
	}
	if err := <-done; err == nil {
		t.Fatal("expected canceled handshake")
	}
	if err := c.Start(); err == nil {
		t.Fatal("endpoint reused")
	}
}

func TestControllerStopBeforeRunCannotResurrect(t *testing.T) {
	u, _ := url.Parse("client://127.0.0.1:0/127.0.0.1:1?mode=1")
	c, err := NewClient(u, nil, common.NewLogger(common.None, false))
	if err != nil {
		t.Fatal(err)
	}
	c.Stop()
	done := make(chan struct{})
	go func() { c.RunWithContext(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stopped controller restarted")
	}
}
