package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/VortexWang/Tunveo/internal/common"
)

func TestTLSVerificationCapabilityNegotiation(t *testing.T) {
	for _, test := range []struct {
		name, value, want string
		invalid           bool
	}{
		{"new", common.TLSVerifyFlowV1, common.TLSVerifyFlowV1, false},
		{"old-empty", "", common.TLSVerifyLegacy, false},
		{"explicit-legacy", common.TLSVerifyLegacy, common.TLSVerifyLegacy, false},
		{"unsupported", "flow-unknown", common.TLSVerifyLegacy, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			header := make(chan string, 1)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				header <- r.Header.Get(common.TLSVerifyHeader)
				json.NewEncoder(w).Encode(map[string]any{"flow": "-", "max": 8, "tls": "1", "type": "2", "verify": test.value})
			}))
			defer server.Close()
			c := &Client{Common: common.NewCommon(common.NewLogger(common.None, false), nil)}
			c.TunnelAddr = strings.TrimPrefix(server.URL, "https://")
			c.ServerName = "none"
			c.TunnelKey = "fixture-only"
			c.TLSVerifyMode = common.TLSVerifyFlowV1
			err := c.TunnelHandshake()
			if (err != nil) != test.invalid {
				t.Fatalf("negotiation error: %v", err)
			}
			if got := <-header; got != common.TLSVerifyFlowV1 {
				t.Fatalf("missing offer header: %q", got)
			}
			if c.TLSVerifyMode != test.want {
				t.Fatalf("mode=%q want=%q", c.TLSVerifyMode, test.want)
			}
		})
	}
}
