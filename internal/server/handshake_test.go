package server

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/VortexWang/Tunveo/internal/common"
)

func TestTLSVerificationReplyIsFlushedAndNegotiated(t *testing.T) {
	for _, offer := range []string{common.TLSVerifyFlowV1, "", "unknown"} {
		t.Run("offer="+offer, func(t *testing.T) {
			for range 10 {
				cfg, err := common.NewTLSConfig()
				if err != nil {
					t.Fatal(err)
				}
				listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
				if err != nil {
					t.Fatal(err)
				}
				s := &Server{Common: common.NewCommonPtr(common.NewLogger(common.None, false), cfg)}
				s.CoreType = "server"
				s.DataFlow = "-"
				s.TLSCode = "1"
				s.PoolType = "2"
				s.TunnelKey = "fixture-only"
				s.MaxPoolCapacity = 8
				s.TunnelListener = listener
				s.TunnelTCPAddr = listener.Addr().(*net.TCPAddr)
				s.InitContext()
				finished := make(chan error, 1)
				go func() { finished <- s.TunnelHandshake() }()
				transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
				client := &http.Client{Transport: transport, Timeout: time.Second}
				req, _ := http.NewRequest(http.MethodGet, "https://"+listener.Addr().String()+"/", nil)
				req.Header.Set("Authorization", "Bearer "+s.GenerateAuthToken())
				req.Header.Set(common.TLSVerifyHeader, offer)
				resp, err := client.Do(req)
				if err != nil {
					s.Cancel()
					listener.Close()
					transport.CloseIdleConnections()
					t.Fatal(err)
				}
				var payload struct {
					Verification string `json:"verify"`
					Flow         string `json:"flow"`
				}
				decodeErr := json.NewDecoder(resp.Body).Decode(&payload)
				resp.Body.Close()
				transport.CloseIdleConnections()
				select {
				case err := <-finished:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					s.Cancel()
					t.Fatal("handshake did not finish")
				}
				s.Cancel()
				s.TunnelListener.Close()
				if decodeErr != nil {
					t.Fatalf("truncated capability response: %v", decodeErr)
				}
				want := common.TLSVerifyLegacy
				if offer == common.TLSVerifyFlowV1 {
					want = common.TLSVerifyFlowV1
				}
				if payload.Verification != want || s.TLSVerifyMode != want || payload.Flow != "-" {
					t.Fatalf("negotiation mismatch: %+v state=%s", payload, s.TLSVerifyMode)
				}
			}
		})
	}
}
