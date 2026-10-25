package common

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

func TestLogRedaction(t *testing.T) {
	for _, raw := range []string{
		"server://unique-secret@127.0.0.1:123/target?mode=1&token=unique-token",
		"client://unique%2Dsecret:unique-password@[::1]:123/target#unique-fragment",
		`parse "server://unique-secret@bad%zz/target": invalid escape`,
		"master://unique-secret@127.0.0.1/api?unknown=unique-token",
	} {
		got := RedactLog("startup " + raw)
		for _, secret := range []string{"unique-secret", "unique%2Dsecret", "unique-password", "unique-token", "unique-fragment"} {
			if strings.Contains(got, secret) {
				t.Fatalf("secret survived: %s", got)
			}
		}
		if !strings.HasPrefix(got, "startup ") {
			t.Fatal("lost message context")
		}
	}
	// Exercise the actual log sink and third-party adapter, not just the helper.
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old; r.Close(); w.Close() }()
	logger := NewLogger(Debug, false)
	raw := "server://sink-secret@127.0.0.1:1/target?token=query-secret"
	logger.Info("Instance starting: %s", raw)
	logger.StdLogger().Printf("error: %s", raw)
	logger.Mu.Lock()
	logger.WriteLog(Error, "time", "ERROR", fmt.Sprintf("direct: %s", raw))
	logger.Mu.Unlock()
	w.Close()
	var out bytes.Buffer
	if _, err := io.Copy(&out, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "sink-secret") || strings.Contains(out.String(), "query-secret") {
		t.Fatal("log sink leaked")
	}
	if strings.Count(out.String(), "REDACTED") != 6 {
		t.Fatalf("wrong log output: %s", out.String())
	}
}
