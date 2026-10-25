package server

import (
	"net"
	"testing"

	"github.com/VortexWang/Tunveo/internal/common"
)

func TestHTTP2MissingTLSReturnsErrorBeforeStartingManager(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	s := &Server{Common: common.NewCommonPtr(common.NewLogger(common.None, false), nil)}
	s.PoolType = "3"
	s.TunnelListener = listener
	s.InitContext()
	defer s.Cancel()
	if err := s.InitTunnelPool(); err == nil {
		t.Fatal("HTTP/2 without TLS material must return an error")
	}
	if s.TunnelPool != nil {
		t.Fatal("invalid HTTP/2 pool was published")
	}
}
