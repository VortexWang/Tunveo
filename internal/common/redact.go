package common

import (
	"net/url"
	"regexp"
	"strings"
)

// URL-shaped values include parse errors as well as valid configuration URLs.
// Mask the entire query and fragment: unknown future options may carry secrets.
var logURL = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s<>]+`)

// RedactLog sanitizes URL credentials at the log/CLI error boundary. It is not
// a general-purpose scrubber for arbitrary unlabelled secrets or API responses.
func RedactLog(message string) string {
	return logURL.ReplaceAllStringFunc(message, func(raw string) string {
		// Error strings may quote/escape a malformed URL. Do not echo its raw value.
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return "[REDACTED-URL]"
		}
		if u.User != nil {
			u.User = url.User("REDACTED")
		}
		if u.RawQuery != "" || u.ForceQuery {
			u.RawQuery = "REDACTED"
			u.ForceQuery = false
		}
		if u.Fragment != "" {
			u.Fragment = "REDACTED"
			u.RawFragment = ""
		}
		// No escaped spelling of userinfo survives URL.String().
		return strings.TrimSpace(u.String())
	})
}
