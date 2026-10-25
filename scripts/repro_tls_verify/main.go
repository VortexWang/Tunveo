// Command repro_tls_verify is a bounded regression for TLS-mode-1 verification.
// It uses real TLS/TCP pools. Control messages are delivered only after the two
// initiators finish, a valid network schedule that must not cancel a tunnel.
// Both negotiated flow directions must finish, with one initiating side and
// one correlated acknowledgement, without consuming the same connection twice.
package main

import (
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

func run(flow string) (map[string]any, error) {
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
	server.DataFlow, client.DataFlow = flow, flow
	server.TLSVerifyMode, client.TLSVerifyMode = common.TLSVerifyFlowV1, common.TLSVerifyFlowV1
	server.TLSCode, client.TLSCode = "1", "1"
	server.TunnelKey, client.TunnelKey = "fixture-only", "fixture-only"
	server.ControlConn, client.ControlConn = sc, cc
	server.TunnelPool, client.TunnelPool = serverPool, clientPool
	server.InitContext()
	client.InitContext()
	defer server.Cancel()
	defer client.Cancel()
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
	// Deliver the initial requests, then the correlated acknowledgements. No
	// control message is delivered before both initiation attempts return.
	serverMessages, clientMessages := fromServer, fromClient
	ackCount := 0
	for range 4 {
		for _, signal := range serverMessages {
			if signal.VerifyAck {
				ackCount++
			}
			client.OutgoingVerify(signal)
		}
		for _, signal := range clientMessages {
			if signal.VerifyAck {
				ackCount++
			}
			server.OutgoingVerify(signal)
		}
		serverMessages, err = drain(&server)
		if err != nil {
			return nil, err
		}
		clientMessages, err = drain(&client)
		if err != nil {
			return nil, err
		}
		if len(serverMessages)+len(clientMessages) == 0 {
			break
		}
	}
	ids := func(signals []common.Signal) []string {
		var out []string
		for _, s := range signals {
			out = append(out, s.PoolConnID)
		}
		return out
	}
	report := map[string]any{"fixture": "real TLS/TCP pools; two connections: control plus one verification slot", "flow": flow, "acknowledgements": ackCount, "pool_get_timeout_ms": 100, "server_verification_ids": ids(fromServer), "client_verification_ids": ids(fromClient), "server_canceled": server.Ctx.Err() != nil, "client_canceled": client.Ctx.Err() != nil, "verification_gates": len(server.VerifyChan) + len(client.VerifyChan)}
	if server.Ctx.Err() != nil || client.Ctx.Err() != nil || len(server.VerifyChan) != 1 || len(client.VerifyChan) != 1 || ackCount != 1 {
		return report, fmt.Errorf("TLS verification must complete without cancelling either peer under delayed signal delivery")
	}
	return report, nil
}

func main() {
	// This outer watchdog also bounds fixture setup, TLS shutdown and unforeseen
	// blocking operations. A watchdog exit is a fixture error, not a reproduction.
	timer := time.AfterFunc(10*time.Second, func() { fmt.Fprintln(os.Stderr, "fixture watchdog expired"); os.Exit(2) })
	defer timer.Stop()
	var reports []map[string]any
	failed := false
	for _, flow := range []string{"-", "+"} {
		report, err := run(flow)
		if report == nil {
			report = map[string]any{"fixture_error": fmt.Sprint(err)}
		}
		if err != nil {
			report["error"] = err.Error()
			failed = true
		}
		reports = append(reports, report)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"flows": reports, "passed": !failed})
	if failed {
		os.Exit(1)
	}
}
