// Command repro_tls_verify is a bounded regression for TLS-mode-1 verification.
// It uses real TLS/TCP pools. Control messages are delivered only after the two
// initiators finish, a valid network schedule that must not cancel a tunnel.
// The unmodified baseline exits 1; this is deliberately not an expected pass.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VortexWang/Tunveo/internal/common"
	tcp "github.com/VortexWang/Tunveo/internal/tunnelpool/tcp"
)

func run() (map[string]any, error) {
	// Only the fixture's timeout changes; engine source and binaries are untouched.
	common.PoolGetTimeout = 100 * time.Millisecond
	cfg, err := common.NewTLSConfig()
	if err != nil {
		return nil, err
	}
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	serverPool := tcp.NewServerPool(2, "127.0.0.1", cfg, listener, time.Second)
	second := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(second) })
	var dials atomic.Int32
	clientPool := tcp.NewClientPool(2, 2, 10*time.Millisecond, 10*time.Millisecond, time.Second, "1", "none", func() (net.Conn, error) {
		n := dials.Add(1)
		if n > 2 {
			return nil, fmt.Errorf("fixture permits exactly two TCP connections")
		}
		if n == 2 {
			<-second
		}
		return net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	})
	go serverPool.ServerManager()
	go clientPool.ClientManager()
	defer clientPool.Close()
	defer serverPool.Close()
	wait := func(predicate func() bool) error {
		deadline := time.Now().Add(3 * time.Second)
		for !predicate() {
			if time.Now().After(deadline) {
				return fmt.Errorf("fixture pool readiness timeout")
			}
			time.Sleep(time.Millisecond)
		}
		return nil
	}
	if err := wait(func() bool { return serverPool.Active() == 1 && clientPool.Active() == 1 }); err != nil {
		return nil, err
	}
	sc, err := serverPool.OutgoingGet("00000000", time.Second)
	if err != nil {
		return nil, err
	}
	defer sc.Close()
	cc, err := clientPool.OutgoingGet("00000000", time.Second)
	if err != nil {
		return nil, err
	}
	defer cc.Close()
	release.Do(func() { close(second) })
	if err := wait(func() bool { return serverPool.Active() == 1 && clientPool.Active() == 1 }); err != nil {
		return nil, err
	}
	logger := common.NewLogger(common.None, false)
	server := common.NewCommon(logger, cfg)
	client := common.NewCommon(logger, nil)
	server.CoreType, client.CoreType = "server", "client"
	server.TLSCode, client.TLSCode = "1", "1"
	server.TunnelKey, client.TunnelKey = "fixture-only", "fixture-only"
	server.ControlConn, client.ControlConn = sc, cc
	server.TunnelPool, client.TunnelPool = serverPool, clientPool
	server.Ctx, server.Cancel = context.WithCancel(context.Background())
	defer server.Cancel()
	client.Ctx, client.Cancel = context.WithCancel(context.Background())
	defer client.Cancel()
	// Buffered gates stand in for the data-loop consumers; they do not affect
	// connection ownership or control-message contents.
	server.VerifyChan, client.VerifyChan = make(chan struct{}, 2), make(chan struct{}, 2)
	server.IncomingVerify()
	client.IncomingVerify()
	drain := func(endpoint *common.Common) ([]common.Signal, error) {
		var signals []common.Signal
		for {
			select {
			case raw := <-endpoint.WriteChan:
				decoded, err := endpoint.Decode(raw)
				if err != nil {
					return nil, err
				}
				var signal common.Signal
				if err := json.Unmarshal(decoded, &signal); err != nil {
					return nil, err
				}
				signals = append(signals, signal)
			default:
				return signals, nil
			}
		}
	}
	fromServer, err := drain(&server)
	if err != nil {
		return nil, err
	}
	fromClient, err := drain(&client)
	if err != nil {
		return nil, err
	}
	var wg sync.WaitGroup
	for _, signal := range fromServer {
		wg.Add(1)
		go func(s common.Signal) { defer wg.Done(); client.OutgoingVerify(s) }(signal)
	}
	for _, signal := range fromClient {
		wg.Add(1)
		go func(s common.Signal) { defer wg.Done(); server.OutgoingVerify(s) }(signal)
	}
	wg.Wait()
	ids := func(signals []common.Signal) []string {
		var out []string
		for _, s := range signals {
			out = append(out, s.PoolConnID)
		}
		return out
	}
	report := map[string]any{"fixture": "real TLS/TCP pools; two connections: control plus one verification slot", "pool_get_timeout_ms": 100, "server_verification_ids": ids(fromServer), "client_verification_ids": ids(fromClient), "server_canceled": server.Ctx.Err() != nil, "client_canceled": client.Ctx.Err() != nil, "verification_gates": len(server.VerifyChan) + len(client.VerifyChan)}
	if server.Ctx.Err() != nil || client.Ctx.Err() != nil || len(server.VerifyChan)+len(client.VerifyChan) == 0 {
		return report, fmt.Errorf("TLS verification must complete without cancelling either peer under delayed signal delivery")
	}
	return report, nil
}

func main() {
	// This outer watchdog also bounds fixture setup, TLS shutdown and unforeseen
	// blocking operations. A watchdog exit is a fixture error, not a reproduction.
	timer := time.AfterFunc(10*time.Second, func() { fmt.Fprintln(os.Stderr, "fixture watchdog expired"); os.Exit(2) })
	defer timer.Stop()
	report, err := run()
	if report == nil {
		report = map[string]any{"fixture_error": fmt.Sprint(err)}
	}
	if err != nil {
		report["error"] = err.Error()
	}
	json.NewEncoder(os.Stdout).Encode(report)
	if err != nil {
		os.Exit(1)
	}
}
