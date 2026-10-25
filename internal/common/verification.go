package common

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// Verification capability values are exchanged only in the HTTPS handshake.
const (
	TLSVerifyFlowV1 = "flow-v1"
	TLSVerifyLegacy = "legacy"
	TLSVerifyHeader = "X-Tunveo-Verification"
)

// State belongs to one run. Cancellation/late acknowledgements from an old run
// cannot signal the new run's gate or cancel its context.
type tlsVerificationState struct {
	ctx                           context.Context
	cancel                        context.CancelFunc
	gate                          chan struct{}
	peerVerified                  chan struct{}
	completed                     chan struct{}
	waitTimeout                   time.Duration
	peerOnce                      sync.Once
	startOnce                     sync.Once
	completeOnce                  sync.Once
	mu                            sync.Mutex
	pendingID, pendingFingerprint string
	requestID, requestFingerprint string
}

func newTLSVerificationState(ctx context.Context, cancel context.CancelFunc, gate chan struct{}) *tlsVerificationState {
	return &tlsVerificationState{ctx: ctx, cancel: cancel, gate: gate, peerVerified: make(chan struct{}), completed: make(chan struct{}), waitTimeout: PoolGetTimeout + ReportInterval}
}

// The side without the incoming business listener owns verification initiation:
// client for flow '-', server for flow '+'. This is independent of transport.
func (c *Common) verificationInitiator() bool {
	return c.CoreType == "client" && c.DataFlow == "-" || c.CoreType == "server" && c.DataFlow == "+"
}

func (c *Common) verificationState() *tlsVerificationState {
	state := c.verification
	if state == nil {
		c.Logger.Error("TLS verification: run context is not initialized")
		if c.Cancel != nil {
			c.Cancel()
		}
	}
	return state
}

func (c *Common) verificationFailure(state *tlsVerificationState, reason string) {
	if state.ctx.Err() != nil {
		return
	}
	c.Logger.Error("TLS verification failed: %v", reason)
	state.cancel()
}

func (c *Common) verificationComplete(state *tlsVerificationState, fingerprint string) {
	if state.ctx.Err() != nil {
		return
	}
	state.completeOnce.Do(func() {
		if state.ctx.Err() != nil {
			return
		}
		c.Logger.Info("TLS code-1: RAM cert verified with sha256 fingerprint: %v", fingerprint)
		select {
		case state.gate <- struct{}{}:
			close(state.completed)
		case <-state.ctx.Done():
		}
	})
}

func (c *Common) sendVerification(state *tlsVerificationState, signal Signal, writes chan []byte) bool {
	if state.ctx.Err() != nil {
		return false
	}
	raw, err := json.Marshal(signal)
	if err != nil {
		c.verificationFailure(state, err.Error())
		return false
	}
	select {
	case writes <- c.Encode(raw):
		return true
	case <-state.ctx.Done():
		return false
	}
}

// IncomingVerify uses one elected initiator after flow-v1 negotiation. With a
// legacy peer, either role first processes the peer's unsolicited request, then
// selects a different ID for the legacy reciprocal verification.
func (c *Common) IncomingVerify() {
	c.incomingVerify(c.verificationState())
}

func (c *Common) incomingVerify(state *tlsVerificationState) {
	if state == nil || state.ctx.Err() != nil {
		return
	}
	if c.CoreType != "server" && c.CoreType != "client" {
		c.verificationFailure(state, "unknown endpoint role")
		return
	}
	if c.DataFlow != "-" && c.DataFlow != "+" {
		c.verificationFailure(state, "unknown data flow")
		return
	}
	if c.TLSVerifyMode == TLSVerifyFlowV1 && !c.verificationInitiator() {
		return
	}
	pool, writes, control := c.TunnelPool, c.WriteChan, c.ControlConn
	state.startOnce.Do(func() {
		if c.TLSVerifyMode != TLSVerifyFlowV1 {
			timer := time.NewTimer(state.waitTimeout)
			defer timer.Stop()
			select {
			case <-state.peerVerified:
			case <-state.ctx.Done():
				return
			case <-timer.C:
				c.verificationFailure(state, "legacy peer did not initiate verification before deadline")
				return
			}
		}
		if state.ctx.Err() != nil {
			return
		}
		if pool == nil || control == nil {
			c.verificationFailure(state, "missing pool/control connection")
			return
		}
		// A bounded pool operation replaces the old unbounded readiness polling loop.
		id, conn, err := pool.IncomingGet(PoolGetTimeout)
		if err != nil {
			c.verificationFailure(state, fmt.Sprintf("IncomingGet: %v", err))
			return
		}
		defer conn.Close()
		if state.ctx.Err() != nil {
			return
		}
		fingerprint, err := c.verificationFingerprint(conn)
		if err != nil {
			c.verificationFailure(state, err.Error())
			return
		}
		state.mu.Lock()
		state.pendingID, state.pendingFingerprint = id, fingerprint
		state.mu.Unlock()
		if c.sendVerification(state, Signal{ActionType: "verify", PoolConnID: id, Fingerprint: fingerprint}, writes) {
			c.Logger.Debug("TLS code-1: verify signal: cid %v -> %v", id, control.RemoteAddr())
			if c.TLSVerifyMode == TLSVerifyFlowV1 {
				go func() {
					timer := time.NewTimer(state.waitTimeout)
					defer timer.Stop()
					select {
					case <-state.completed:
					case <-state.ctx.Done():
					case <-timer.C:
						c.verificationFailure(state, "verification acknowledgement deadline exceeded")
					}
				}()
			}
		}
	})
}

func (c *Common) verificationFingerprint(conn net.Conn) (string, error) {
	switch c.CoreType {
	case "server":
		if c.TLSConfig != nil && len(c.TLSConfig.Certificates) > 0 && len(c.TLSConfig.Certificates[0].Certificate) > 0 {
			return c.FormatCertFingerprint(c.TLSConfig.Certificates[0].Certificate[0]), nil
		}
		return "", fmt.Errorf("no local certificate")
	case "client":
		tlsConn, ok := conn.(interface{ ConnectionState() tls.ConnectionState })
		if !ok {
			return "", fmt.Errorf("connection does not expose TLS state")
		}
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			return "", fmt.Errorf("no peer certificate")
		}
		return c.FormatCertFingerprint(state.PeerCertificates[0].Raw), nil
	default:
		return "", fmt.Errorf("unknown endpoint role")
	}
}

func (c *Common) acceptVerificationAck(state *tlsVerificationState, signal Signal) {
	if c.TLSVerifyMode != TLSVerifyFlowV1 || !c.verificationInitiator() {
		c.verificationFailure(state, "unexpected verification acknowledgement")
		return
	}
	state.mu.Lock()
	valid := state.pendingID != "" && signal.PoolConnID == state.pendingID && signal.Fingerprint == state.pendingFingerprint
	state.mu.Unlock()
	if !valid {
		c.verificationFailure(state, "verification acknowledgement does not match pending request")
		return
	}
	c.verificationComplete(state, signal.Fingerprint)
}

// OutgoingVerify consumes a request's connection at most once. Acknowledgements
// never consume a pool connection and are accepted only for a negotiated,
// matching local request. Legacy verify messages retain their original format.
func (c *Common) OutgoingVerify(signal Signal) {
	c.outgoingVerify(c.verificationState(), signal)
}

func (c *Common) outgoingVerify(state *tlsVerificationState, signal Signal) {
	if state == nil || state.ctx.Err() != nil {
		return
	}
	if signal.VerifyAck {
		c.acceptVerificationAck(state, signal)
		return
	}
	if signal.PoolConnID == "" || signal.PoolConnID == "00000000" || signal.Fingerprint == "" {
		c.verificationFailure(state, "missing fingerprint or invalid verification connection ID")
		return
	}
	if c.TLSVerifyMode == TLSVerifyFlowV1 {
		if c.verificationInitiator() {
			c.verificationFailure(state, "verification request sent to elected initiator")
			return
		}
		state.mu.Lock()
		duplicate := state.requestID != ""
		same := state.requestID == signal.PoolConnID && state.requestFingerprint == signal.Fingerprint
		if !duplicate {
			state.requestID, state.requestFingerprint = signal.PoolConnID, signal.Fingerprint
		}
		state.mu.Unlock()
		if duplicate {
			if !same {
				c.verificationFailure(state, "conflicting verification request")
			}
			return
		}
	}
	pool, writes, control := c.TunnelPool, c.WriteChan, c.ControlConn
	if pool == nil || control == nil {
		c.verificationFailure(state, "missing pool/control connection")
		return
	}
	c.Logger.Debug("TLS verify signal: cid %v <- %v", signal.PoolConnID, control.RemoteAddr())
	conn, err := pool.OutgoingGet(signal.PoolConnID, PoolGetTimeout)
	if err != nil {
		c.verificationFailure(state, fmt.Sprintf("OutgoingGet: %v", err))
		return
	}
	defer conn.Close()
	if state.ctx.Err() != nil {
		return
	}
	fingerprint, err := c.verificationFingerprint(conn)
	if err != nil {
		c.verificationFailure(state, err.Error())
		return
	}
	if fingerprint != signal.Fingerprint {
		c.verificationFailure(state, "certificate fingerprint mismatch")
		return
	}
	if state.ctx.Err() != nil {
		return
	}
	// Safe to release legacy initiation only after the remote-owned ID was removed
	// and its certificate checked; replacement connections have different IDs.
	state.peerOnce.Do(func() { close(state.peerVerified) })
	if c.TLSVerifyMode == TLSVerifyFlowV1 && !c.sendVerification(state, Signal{ActionType: "verify", PoolConnID: signal.PoolConnID, Fingerprint: fingerprint, VerifyAck: true}, writes) {
		return
	}
	c.verificationComplete(state, fingerprint)
}
