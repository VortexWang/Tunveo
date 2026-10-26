package main

import (
	"io"
	"net"
	"testing"
)

type address string

func (a address) Network() string { return "fixture" }
func (a address) String() string  { return string(a) }

type namedPipe struct{ net.Conn }

func (c namedPipe) LocalAddr() net.Addr  { return address("local") }
func (c namedPipe) RemoteAddr() net.Addr { return address("peer") }
func TestExchangeAuditsActualBytesAndRejectsCorruption(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		a, b := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer b.Close()
			payload := make([]byte, 32768)
			if _, e := io.ReadFull(b, payload); e != nil {
				return
			}
			if corrupt {
				payload[0] ^= 1
			}
			b.Write(payload)
		}()
		row, err := exchangeOnce(namedPipe{a}, "tcp")
		a.Close()
		<-done
		if corrupt {
			if err == nil {
				t.Fatal("corrupt echo accepted")
			}
		} else {
			if err != nil || row.Sent != 32768 || row.Received != 32768 || row.PayloadHash != row.ReplyHash || row.Attempts != 1 {
				t.Fatalf("bad audit: %+v %v", row, err)
			}
		}
	}
}
func TestSelfTupleRejectedBeforeApplicationWrite(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	// net.Pipe deliberately has the same LocalAddr and RemoteAddr.
	row, err := exchangeOnce(a, "tcp")
	if err == nil || row.Sent != 0 || row.Received != 0 {
		t.Fatal("self tuple was used", err)
	}
}
