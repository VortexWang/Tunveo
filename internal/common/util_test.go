package common

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestPositiveDurationEnv(t *testing.T) {
	const name = "TUNVEO_TEST_POSITIVE_INTERVAL"
	for _, tc := range []struct {
		name, raw string
		set, fail bool
		want      time.Duration
	}{
		{name: "unset", want: time.Hour},
		{name: "positive", raw: "50ms", set: true, want: 50 * time.Millisecond},
		{name: "small positive", raw: "1ns", set: true, want: time.Nanosecond},
		{name: "zero", raw: "0", set: true, fail: true},
		{name: "zero with unit", raw: "0s", set: true, fail: true},
		{name: "negative", raw: "-1s", set: true, fail: true},
		{name: "empty", set: true, fail: true},
		{name: "malformed", raw: "do-not-echo-this-value", set: true, fail: true},
		{name: "overflow", raw: "9223372036854775808ns", set: true, fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(name, tc.raw)
			if !tc.set {
				if err := os.Unsetenv(name); err != nil {
					t.Fatal(err)
				}
			}
			value, err := getPositiveDurationEnv(name, time.Hour)
			if tc.fail {
				if err == nil || value != 0 || !strings.Contains(err.Error(), name) {
					t.Fatal("invalid interval did not fail")
				}
				if tc.raw == "do-not-echo-this-value" && strings.Contains(err.Error(), tc.raw) {
					t.Fatal("error echoed input")
				}
				return
			}
			if err != nil || value != tc.want {
				t.Fatalf("value=%v err=%v", value, err)
			}
		})
	}
	// Existing timeouts must still accept zero.
	t.Setenv(name, "0s")
	if got := GetEnvAsDuration(name, time.Second); got != 0 {
		t.Fatal("zero timeout semantics changed")
	}
}

func TestInitConfigRejectsInvalidReloadBeforeAddressWork(t *testing.T) {
	old := ReloadInterval
	ReloadInterval = 0
	defer func() { ReloadInterval = old }()
	c := Common{} // A nil URL would panic if address parsing happened first.
	if err := c.InitConfig(); err == nil || !strings.Contains(err.Error(), "NP_RELOAD_INTERVAL") {
		t.Fatal("configuration accepted invalid interval")
	}
}
