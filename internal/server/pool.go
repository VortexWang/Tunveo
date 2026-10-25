// pool.go initialises the server-side tunnel connection pool after a successful
// handshake. The selected backend accepts or serves TCP, QUIC, WebSocket, or
// HTTP/2 tunnel connections while presenting the same TransportPool interface to
// the tunnel data paths.
package server

import (
	"context"
	"fmt"

	"github.com/VortexWang/Tunveo/internal/common"
	nph2 "github.com/VortexWang/Tunveo/internal/tunnelpool/http2"
	"github.com/VortexWang/Tunveo/internal/tunnelpool/quic"
	pool "github.com/VortexWang/Tunveo/internal/tunnelpool/tcp"
	npws "github.com/VortexWang/Tunveo/internal/tunnelpool/websocket"
)

// InitTunnelPool creates and initializes the server-side pool selected by PoolType.
// PoolType values are:
//   - "0": TCP pool
//   - "1": QUIC pool
//   - "2": WebSocket pool
//   - "3": HTTP/2 pool
//
// All implementations are adapted to common.TransportPool, so the rest of the
// server does not need to know which transport backend was negotiated.
func (s *Server) InitTunnelPool() error {
	switch s.PoolType {
	case "0":
		tcpPool := pool.NewServerPool(
			s.MaxPoolCapacity,
			s.ClientIP,
			s.TLSConfig,
			s.TunnelListener,
			common.ReportInterval)
		context.AfterFunc(s.Ctx, tcpPool.Close)
		go tcpPool.ServerManager()
		s.TunnelPool = tcpPool
	case "1":
		quicPool := quic.NewServerPool(
			s.MaxPoolCapacity,
			s.ClientIP,
			s.TLSConfig,
			s.TunnelUDPAddr.String(),
			common.ReportInterval)
		context.AfterFunc(s.Ctx, quicPool.Close)
		go quicPool.ServerManager()
		s.TunnelPool = quicPool
	case "2":
		websocketPool := npws.NewServerPool(
			s.MaxPoolCapacity,
			"",
			s.TLSConfig,
			s.TunnelListener,
			common.ReportInterval)
		context.AfterFunc(s.Ctx, websocketPool.Close)
		go websocketPool.ServerManager()
		s.TunnelPool = websocketPool
	case "3":
		http2Pool := nph2.NewServerPool(
			s.MaxPoolCapacity,
			s.ClientIP,
			s.TLSConfig,
			s.TunnelListener,
			common.ReportInterval)
		if http2Pool == nil {
			return fmt.Errorf("InitTunnelPool: HTTP/2 requires a listener and TLS configuration")
		}
		context.AfterFunc(s.Ctx, http2Pool.Close)
		go http2Pool.ServerManager()
		s.TunnelPool = http2Pool
	default:
		return fmt.Errorf("InitTunnelPool: unknown pool type: %s", s.PoolType)
	}
	return nil
}
