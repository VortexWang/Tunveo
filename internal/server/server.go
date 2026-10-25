// Package server implements the tunveo tunnel server. It listens for
// inbound tunnel connections, manages a connection pool, and forwards traffic
// between the tunnel side and the configured target address(es).
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/VortexWang/Tunveo/internal/common"
)

// Server wraps common.Common, adding server-specific startup and run logic.
// It manages inbound tunnel connections from clients, maintains a connection pool,
// and forwards traffic between the tunnel and configured target addresses.
// Supports both single-connection and pool-based tunnel modes.
type Server struct {
	*common.Common
	guard sync.Mutex
	mode  int
	done  chan struct{}
}

// NewServer constructs a Server from a parsed URL, TLS code, optional TLS
// configuration, and a logger. It initializes the embedded Common struct, stores
// the TLS code for client handshake negotiation, parses all URL parameters into
// configuration fields, and sets up the rate limiter if configured.
// The returned server is ready to call Run() or Start().
// Returns an error if configuration parsing fails.
func NewServer(parsedURL *url.URL, tlsCode string, tlsConfig *tls.Config, logger *common.Logger) (*Server, error) {
	server := &Server{Common: common.NewCommonPtr(logger, tlsConfig), done: make(chan struct{})}
	server.ParsedURL = parsedURL
	server.TLSCode = tlsCode

	if err := server.InitConfig(); err != nil {
		return nil, fmt.Errorf("NewServer: initConfig failed: %w", err)
	}
	server.InitRateLimiter()
	return server, nil
}

// Run is the top-level entry point for a server instance. It performs the following:
//   - Logs startup parameters (tunnel address, target, mode, pool capacity, etc.)
//   - Installs OS signal handlers (SIGINT, SIGTERM) for graceful shutdown
//   - Continuously calls Start() and restarts on failure with ServiceCooldown delay
//   - Performs graceful shutdown cleanup when interrupted (closing listeners, flushing pools)
//
// This method blocks until an OS signal is received.
func (s *Server) Run() {
	logInfo := func(prefix string) {
		s.Logger.Info("%v: server://%v@%v/%v?dns=%v&lbs=%v&max=%v&mode=%v&type=%v&dial=%v&read=%v&rate=%v&slot=%v&proxy=%v&block=%v&notcp=%v&noudp=%v",
			prefix, "[REDACTED]", s.TunnelTCPAddr, s.GetTargetAddrsString(), s.DNSCacheTTL, s.LBStrategy, s.MaxPoolCapacity,
			s.RunMode, s.PoolType, s.DialerIP, s.ReadTimeout, s.RateLimit/125000, s.SlotLimit,
			s.ProxyProtocol, s.BlockProtocol, s.DisableTCP, s.DisableUDP)
	}
	logInfo("Server started")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s.RunWithContext(ctx)
	s.Logger.Info("Server shutdown complete")
}

// Start consumes this single-use runtime and determines the run mode based on the
// configured RunMode:
//   - mode "0" (auto): attempts single mode first; falls back to tunnel mode if target listener fails
//   - mode "1" (single): opens a target listener and enters single-connection mode
//   - mode "2" (tunnel): enters pool mode without opening a target listener
//
// The flow direction is set based on mode:
//   - single mode (mode "1"): DataFlow = "-" (server forwards from tunnel to target)
//   - tunnel mode (mode "2"): DataFlow = "+" (server forwards from target to tunnel)
//
// After mode setup, it opens the tunnel listener, performs handshake, initializes
// the pool, and enters TunnelControl. Returns the first error encountered.
func (s *Server) Start() error {
	if !s.claim(1) {
		return fmt.Errorf("Start: endpoint is single-use; construct a fresh endpoint")
	}
	defer func() { s.Common.Stop(); close(s.done) }()
	if err := s.Ctx.Err(); err != nil {
		return err
	}

	if err := s.InitTunnelListener(); err != nil {
		return fmt.Errorf("Start: initTunnelListener failed: %w", err)
	}

	if s.TunnelUDPConn != nil {
		s.TunnelUDPConn.Close()
	}

	switch s.RunMode {
	case "1":
		if err := s.InitTargetListener(); err != nil {
			return fmt.Errorf("Start: initTargetListener failed: %w", err)
		}
		s.DataFlow = "-"
	case "2":
		s.DataFlow = "+"
	default:
		if err := s.InitTargetListener(); err == nil {
			s.RunMode = "1"
			s.DataFlow = "-"
		} else {
			s.RunMode = "2"
			s.DataFlow = "+"
		}
	}

	s.Logger.Info("Pending tunnel handshake...")
	s.HandshakeStart = time.Now()
	if err := s.TunnelHandshake(); err != nil {
		return fmt.Errorf("Start: tunnelHandshake failed: %w", err)
	}

	if err := s.InitTunnelPool(); err != nil {
		return fmt.Errorf("Start: initTunnelPool failed: %w", err)
	}

	s.Logger.Info("Getting tunnel pool ready...")
	if err := s.SetControlConn(); err != nil {
		return fmt.Errorf("Start: setControlConn failed: %w", err)
	}

	if s.DataFlow == "-" {
		go s.TunnelLoop()
	}

	if err := s.TunnelControl(); err != nil {
		return fmt.Errorf("Start: tunnelControl failed: %w", err)
	}
	return nil
}

func (s *Server) claim(mode int) bool {
	s.guard.Lock()
	defer s.guard.Unlock()
	if s.mode != 0 {
		return false
	}
	if s.done == nil {
		s.done = make(chan struct{})
	}
	s.mode = mode
	return true
}

// RunWithContext keeps automatic retries but never reuses a runtime identity.
// Old workers retain only their canceled run, not the next run's live fields.
func (s *Server) RunWithContext(parent context.Context) {
	if !s.claim(2) {
		return
	}
	defer func() { s.Common.Stop(); close(s.done) }()
	if s.Ctx.Err() != nil || parent.Err() != nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stopParent := context.AfterFunc(s.Ctx, cancel)
	defer stopParent()
	for ctx.Err() == nil {
		run := &Server{Common: s.Common.FreshRun(), done: make(chan struct{})}
		stopRun := context.AfterFunc(ctx, run.Cancel)
		err := run.Start()
		stopRun()
		if ctx.Err() != nil {
			return
		}
		if err != nil && err != io.EOF {
			s.Logger.Error("Server error: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(common.ServiceCooldown):
		}
		s.Logger.Info("Server restart")
	}
}

// Stop cancels first, then waits for Start/RunWithContext to finish their own
// teardown. It never reads resources while setup is still assigning them.
func (s *Server) Stop() {
	s.Cancel()
	s.guard.Lock()
	mode := s.mode
	s.guard.Unlock()
	if mode == 0 {
		s.Common.Stop()
		return
	}
	<-s.done
}
