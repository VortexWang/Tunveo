package tcp

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func setupLifecyclePair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	l, e := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	a, e := net.DialTCP("tcp", nil, l.Addr().(*net.TCPAddr))
	if e != nil {
		t.Fatal(e)
	}
	b, e := l.AcceptTCP()
	if e != nil {
		a.Close()
		t.Fatal(e)
	}
	return a, b
}
func TestFlushFencesDelayedConnection(t *testing.T) {
	raw, peer := setupLifecyclePair(t)
	defer peer.Close()
	called := make(chan struct{})
	var once sync.Once
	p := NewClientPool(1, 1, time.Second, time.Second, time.Second, "0", "none", func() (net.Conn, error) { once.Do(func() { close(called) }); return raw, nil })
	defer p.Close()
	done := make(chan bool, 1)
	go func() { done <- p.createConnection() }()
	<-called
	p.Flush()
	peer.SetWriteDeadline(time.Now().Add(time.Second))
	peer.Write([]byte{1, 2, 3, 4})
	select {
	case published := <-done:
		if expectLifecycleFailure {
			if !published || p.Active() != 1 {
				t.Fatal("old late publication not reproduced")
			}
			t.Log("REPRODUCED-FLUSH: pre-Flush task published into post-Flush idle registry")
		} else {
			if published || p.Active() != 0 {
				t.Fatal("stale task survived Flush")
			}
			t.Log("PASSED-FLUSH: pre-Flush setup rejected")
		}
	case <-time.After(time.Second):
		t.Fatal("producer did not finish")
	}
}
func TestClosedPoolCannotRestartManager(t *testing.T) {
	called := make(chan struct{})
	var once sync.Once
	p := NewClientPool(1, 1, time.Second, time.Second, time.Second, "0", "none", func() (net.Conn, error) { once.Do(func() { close(called) }); return nil, errors.New("fixture") })
	p.Close()
	done := make(chan struct{})
	go func() { defer close(done); p.ClientManager() }()
	if expectLifecycleFailure {
		select {
		case <-called:
			t.Log("REPRODUCED-RESTART: manager resurrected a closed pool")
		case <-done:
			t.Fatal("expected old manager restart")
		case <-time.After(time.Second):
			t.Fatal("no result")
		}
		p.cancel()
		<-done
	} else {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("closed manager blocked")
		}
		select {
		case <-called:
			t.Fatal("closed pool dialed")
		default:
		}
		t.Log("PASSED-RESTART: closed manager stayed stopped")
	}
}
func TestCloseInterruptsPendingIDRead(t *testing.T) {
	raw, peer := setupLifecyclePair(t)
	defer peer.Close()
	called := make(chan struct{})
	var once sync.Once
	p := NewClientPool(1, 1, time.Second, time.Second, time.Second, "0", "none", func() (net.Conn, error) { once.Do(func() { close(called) }); return raw, nil })
	done := make(chan bool, 1)
	go func() { done <- p.createConnection() }()
	<-called
	p.Close()
	if expectLifecycleFailure {
		select {
		case <-done:
			t.Fatal("expected pending old read")
		case <-time.After(30 * time.Millisecond):
			t.Log("REPRODUCED-CLOSE: pending setup remained blocked after Close")
		}
		peer.Close()
		<-done
	} else {
		select {
		case published := <-done:
			if published {
				t.Fatal("closed pool published")
			}
			t.Log("PASSED-CLOSE: Close interrupted setup")
		case <-time.After(time.Second):
			t.Fatal("Close did not interrupt ID read")
		}
	}
}

var expectLifecycleFailure = false
