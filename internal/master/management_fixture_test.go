package master

import (
	"context"
	"net/http"
)

func fixtureManagementHandler(m *Master) http.Handler { return m.Handler() }
func fixtureManagementPing(m *Master, ctx context.Context, target string) *TCPingResult {
	return m.PerformTCPingContext(ctx, target)
}
