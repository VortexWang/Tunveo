package common

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

type verificationPool struct {
	mu                       sync.Mutex
	connections              map[string]net.Conn
	order                    []string
	incomingIDs, outgoingIDs []string
}

func (p *verificationPool) IncomingGet(time.Duration) (string, net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, id := range p.order {
		if conn, ok := p.connections[id]; ok {
			delete(p.connections, id)
			p.incomingIDs = append(p.incomingIDs, id)
			return id, conn, nil
		}
	}
	return "", nil, fmt.Errorf("empty fixture pool")
}
func (p *verificationPool) OutgoingGet(id string, _ time.Duration) (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.outgoingIDs = append(p.outgoingIDs, id)
	conn, ok := p.connections[id]
	if !ok {
		return nil, fmt.Errorf("ID already consumed: %s", id)
	}
	delete(p.connections, id)
	return conn, nil
}
func (p *verificationPool) counts() (int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.incomingIDs), len(p.outgoingIDs)
}
func (p *verificationPool) Ready() bool             { return true }
func (p *verificationPool) Active() int             { p.mu.Lock(); defer p.mu.Unlock(); return len(p.connections) }
func (p *verificationPool) Capacity() int           { return len(p.order) }
func (p *verificationPool) Interval() time.Duration { return time.Millisecond }
func (p *verificationPool) Flush()                  {}
func (p *verificationPool) Close()                  {}
func (p *verificationPool) AddError()               {}
func (p *verificationPool) ErrorCount() int         { return 0 }
func (p *verificationPool) ResetError()             {}

type verificationTLSConn struct {
	net.Conn
	certificate []byte
}

func (c verificationTLSConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: c.certificate}}}
}

func verificationEndpoints(t *testing.T, flow, mode string, ids ...string) (*Common, *Common) {
	t.Helper()
	cfg, err := NewTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	sp := &verificationPool{connections: map[string]net.Conn{}, order: ids}
	cp := &verificationPool{connections: map[string]net.Conn{}, order: ids}
	for _, id := range ids {
		left, right := net.Pipe()
		t.Cleanup(func() { left.Close(); right.Close() })
		sp.connections[id] = left
		cp.connections[id] = verificationTLSConn{right, cfg.Certificates[0].Certificate[0]}
	}
	logger := NewLogger(None, false)
	server, client := NewCommon(logger, cfg), NewCommon(logger, nil)
	left, right := net.Pipe()
	t.Cleanup(func() { left.Close(); right.Close() })
	server.CoreType, client.CoreType = "server", "client"
	server.DataFlow, client.DataFlow = flow, flow
	server.TLSCode, client.TLSCode = "1", "1"
	server.TLSVerifyMode, client.TLSVerifyMode = mode, mode
	server.TunnelKey, client.TunnelKey = "fixture-only", "fixture-only"
	server.TunnelPool, client.TunnelPool = sp, cp
	server.ControlConn, client.ControlConn = left, right
	server.WriteChan, client.WriteChan = make(chan []byte, 8), make(chan []byte, 8)
	server.InitContext()
	client.InitContext()
	t.Cleanup(server.Cancel)
	t.Cleanup(client.Cancel)
	return &server, &client
}
func verificationSignal(t *testing.T, c *Common) Signal {
	t.Helper()
	select {
	case raw := <-c.WriteChan:
		decoded, err := c.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		var signal Signal
		if err := json.Unmarshal(decoded, &signal); err != nil {
			t.Fatal(err)
		}
		return signal
	case <-time.After(time.Second):
		t.Fatal("verification signal deadline")
		return Signal{}
	}
}
func verificationRoles(server, client *Common) (*Common, *Common) {
	if server.verificationInitiator() {
		return server, client
	}
	return client, server
}
func assertVerificationAlive(t *testing.T, endpoints ...*Common) {
	t.Helper()
	for _, c := range endpoints {
		if c.Ctx.Err() != nil {
			t.Fatalf("%s canceled unexpectedly", c.CoreType)
		}
	}
}

func TestTLSVerificationRolesAndAcknowledgement(t *testing.T) {
	for _, flow := range []string{"-", "+"} {
		t.Run(flow, func(t *testing.T) {
			server, client := verificationEndpoints(t, flow, TLSVerifyFlowV1, "00000001")
			initiator, receiver := verificationRoles(server, client)
			// Delay all message delivery until both local initiation attempts return.
			server.IncomingVerify()
			client.IncomingVerify()
			request := verificationSignal(t, initiator)
			if request.VerifyAck || len(receiver.WriteChan) != 0 {
				t.Fatal("both peers initiated verification")
			}
			receiver.OutgoingVerify(request)
			ack := verificationSignal(t, receiver)
			if !ack.VerifyAck || ack.PoolConnID != request.PoolConnID {
				t.Fatal("missing correlated acknowledgement")
			}
			if len(initiator.VerifyChan) != 0 {
				t.Fatal("initiator completed before acknowledgement")
			}
			if len(receiver.VerifyChan) != 1 {
				t.Fatal("business gate did not open after validation")
			}
			// Replayed identical requests must not consume another connection.
			receiver.OutgoingVerify(request)
			initiator.OutgoingVerify(ack)
			var wg sync.WaitGroup
			for range 20 {
				wg.Add(1)
				go func() { defer wg.Done(); initiator.OutgoingVerify(ack) }()
			}
			wg.Wait()
			assertVerificationAlive(t, server, client)
			if len(server.VerifyChan) != 1 || len(client.VerifyChan) != 1 {
				t.Fatal("completion was lost or duplicated")
			}
			in, out := initiator.TunnelPool.(*verificationPool).counts()
			if in != 1 || out != 0 {
				t.Fatalf("initiator ownership: incoming=%d outgoing=%d", in, out)
			}
			in, out = receiver.TunnelPool.(*verificationPool).counts()
			if in != 0 || out != 1 {
				t.Fatalf("receiver ownership: incoming=%d outgoing=%d", in, out)
			}
		})
	}
}

func TestTLSVerificationRejectsUnmatchedAcknowledgement(t *testing.T) {
	for _, variant := range []string{"before-request", "wrong-id", "wrong-fingerprint", "legacy"} {
		t.Run(variant, func(t *testing.T) {
			server, client := verificationEndpoints(t, "-", TLSVerifyFlowV1, "00000001")
			initiator, _ := verificationRoles(server, client)
			ack := Signal{ActionType: "verify", PoolConnID: "00000001", Fingerprint: "unsolicited", VerifyAck: true}
			if variant != "before-request" {
				initiator.IncomingVerify()
				request := verificationSignal(t, initiator)
				ack.PoolConnID, ack.Fingerprint = request.PoolConnID, request.Fingerprint
				switch variant {
				case "wrong-id":
					ack.PoolConnID = "ffffffff"
				case "wrong-fingerprint":
					ack.Fingerprint = "bad"
				case "legacy":
					initiator.TLSVerifyMode = TLSVerifyLegacy
				}
			}
			initiator.OutgoingVerify(ack)
			if initiator.Ctx.Err() == nil || len(initiator.VerifyChan) != 0 {
				t.Fatal("unmatched acknowledgement opened verification gate")
			}
		})
	}
}

func TestTLSVerificationRejectsInvalidCertificateAndConnection(t *testing.T) {
	for _, variant := range []string{"fingerprint", "no-local-cert", "no-tls-state", "no-peer-cert", "control-id", "conflicting-request"} {
		t.Run(variant, func(t *testing.T) {
			flow := "-"
			if variant == "no-tls-state" || variant == "no-peer-cert" {
				flow = "+"
			}
			server, client := verificationEndpoints(t, flow, TLSVerifyFlowV1, "00000001")
			initiator, receiver := verificationRoles(server, client)
			initiator.IncomingVerify()
			request := verificationSignal(t, initiator)
			switch variant {
			case "fingerprint":
				request.Fingerprint = "bad"
			case "no-local-cert":
				receiver.TLSConfig = nil
			case "no-tls-state":
				left, right := net.Pipe()
				t.Cleanup(func() { left.Close(); right.Close() })
				receiver.TunnelPool.(*verificationPool).connections[request.PoolConnID] = right
			case "no-peer-cert":
				left, right := net.Pipe()
				t.Cleanup(func() { left.Close(); right.Close() })
				receiver.TunnelPool.(*verificationPool).connections[request.PoolConnID] = tls.Client(right, &tls.Config{InsecureSkipVerify: true})
			case "control-id":
				request.PoolConnID = "00000000"
			case "conflicting-request":
				receiver.verification.requestID = "ffffffff"
				receiver.verification.requestFingerprint = request.Fingerprint
			}
			receiver.OutgoingVerify(request)
			if receiver.Ctx.Err() == nil || len(receiver.VerifyChan) != 0 {
				t.Fatal("invalid certificate/request was accepted")
			}
		})
	}
}

func TestTLSVerificationLegacyRequestsAreSequenced(t *testing.T) {
	for _, flow := range []string{"-", "+"} {
		for _, updatedRole := range []string{"server", "client"} {
			t.Run(flow+updatedRole, func(t *testing.T) {
				server, client := verificationEndpoints(t, flow, TLSVerifyLegacy, "00000001", "00000002")
				updated, legacy := server, client
				if updatedRole == "client" {
					updated, legacy = client, server
				}
				done := make(chan struct{})
				go func() { updated.IncomingVerify(); close(done) }()
				// Model the old peer's destructive IncomingGet before it sends its request.
				id, conn, err := legacy.TunnelPool.IncomingGet(time.Second)
				if err != nil {
					t.Fatal(err)
				}
				fingerprint, err := legacy.verificationFingerprint(conn)
				conn.Close()
				if err != nil {
					t.Fatal(err)
				}
				updated.OutgoingVerify(Signal{ActionType: "verify", PoolConnID: id, Fingerprint: fingerprint})
				request := verificationSignal(t, updated)
				if request.VerifyAck || request.PoolConnID == id {
					t.Fatal("updated peer reused legacy-owned ID")
				}
				legacy.OutgoingVerify(request)
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("legacy initiation blocked")
				}
				assertVerificationAlive(t, updated, legacy)
				if len(updated.VerifyChan) != 1 || len(legacy.VerifyChan) != 1 {
					t.Fatal("legacy business verification gate did not open")
				}
				if len(updated.WriteChan) != 0 || len(legacy.WriteChan) != 0 {
					t.Fatal("acknowledgement was sent to legacy peer")
				}
			})
		}
	}
}

func TestTLSVerificationCancellationAndOldRun(t *testing.T) {
	server, client := verificationEndpoints(t, "-", TLSVerifyLegacy, "00000001")
	done := make(chan struct{})
	go func() { client.IncomingVerify(); close(done) }()
	client.Cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled legacy wait leaked")
	}
	old := server.verification
	server.InitContext()
	t.Cleanup(server.Cancel)
	server.verificationComplete(old, "unused")
	server.outgoingVerify(old, Signal{ActionType: "verify", VerifyAck: true})
	if server.Ctx.Err() != nil || len(server.VerifyChan) != 0 {
		t.Fatal("old run affected new run")
	}
}

func TestTLSVerificationAcknowledgementDeadline(t *testing.T) {
	server, client := verificationEndpoints(t, "-", TLSVerifyFlowV1, "00000001")
	initiator, _ := verificationRoles(server, client)
	initiator.verification.waitTimeout = 20 * time.Millisecond
	initiator.IncomingVerify()
	verificationSignal(t, initiator)
	select {
	case <-initiator.Ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("missing acknowledgement did not cancel tunnel")
	}
	if len(initiator.VerifyChan) != 0 {
		t.Fatal("timeout opened gate")
	}
}

func TestTLSVerificationWriteCancellation(t *testing.T) {
	server, client := verificationEndpoints(t, "-", TLSVerifyFlowV1, "00000001")
	initiator, _ := verificationRoles(server, client)
	initiator.WriteChan = make(chan []byte)
	done := make(chan struct{})
	go func() { initiator.IncomingVerify(); close(done) }()
	deadline := time.Now().Add(time.Second)
	for {
		in, _ := initiator.TunnelPool.(*verificationPool).counts()
		if in == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture did not claim connection")
		}
		time.Sleep(time.Millisecond)
	}
	initiator.Cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled write leaked")
	}
	if len(initiator.VerifyChan) != 0 {
		t.Fatal("canceled write opened gate")
	}
}
