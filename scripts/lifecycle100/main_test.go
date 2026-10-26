package main

import (
	"fmt"
	"net"
	"testing"
)

func TestReservationsKeepFourDistinctSocketsUntilHandoff(t *testing.T) {
	for range 100 {
		front, tunnel, release, err := reservePorts()
		if err != nil {
			t.Fatal(err)
		}
		if front == tunnel {
			release()
			t.Fatal("roles share port")
		}
		for _, p := range []int{front, tunnel} {
			for _, network := range []string{"tcp", "udp"} {
				addr := fmt.Sprintf("127.0.0.1:%d", p)
				if network == "tcp" {
					l, e := net.Listen(network, addr)
					if e == nil {
						l.Close()
						release()
						t.Fatal("TCP reservation absent")
					}
				} else {
					l, e := net.ListenPacket(network, addr)
					if e == nil {
						l.Close()
						release()
						t.Fatal("UDP reservation absent")
					}
				}
			}
		}
		release()
		for _, p := range []int{front, tunnel} {
			u, e := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", p))
			if e != nil {
				t.Fatal("reservation leaked", e)
			}
			u.Close()
		}
	}
}
