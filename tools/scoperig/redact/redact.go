// Package redact removes GitHub and GHP token values from text, bodies and
// headers. Everything in the scope regression rig that could print a token
// must pass its output through this package.
package redact

import (
	"net/http"
	"regexp"
	"strings"
)

// Pattern matches any GitHub or GHP token-shaped string. Submatch 1 is the
// prefix, which is kept so redacted output still shows the token type.
var Pattern = regexp.MustCompile(`(gh[oupsrx]_|gha_|ghpr_|github_pat_)[A-Za-z0-9_]{8,}`)

const (
	replacement = "${1}[REDACTED]"
	masked      = "[REDACTED]"
)

// sensitiveHeaders have their whole value replaced, token-shaped or not.
var sensitiveHeaders = []string{"Authorization", "Cookie", "Set-Cookie"}

// String replaces each token in s with "<prefix>[REDACTED]".
func String(s string) string {
	return Pattern.ReplaceAllString(s, replacement)
}

// Bytes replaces each token in b with "<prefix>[REDACTED]". It returns a new slice.
func Bytes(b []byte) []byte {
	return Pattern.ReplaceAll(b, []byte(replacement))
}

// Header returns a redacted copy of h. Authorization, Cookie and Set-Cookie
// values become "[REDACTED]"; all other values pass through String. The input
// is not modified.
func Header(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vs := range h {
		cp := make([]string, len(vs))
		for i, v := range vs {
			if isSensitive(k) {
				cp[i] = masked
			} else {
				cp[i] = String(v)
			}
		}
		out[k] = cp
	}
	return out
}

func isSensitive(k string) bool {
	for _, s := range sensitiveHeaders {
		if strings.EqualFold(k, s) {
			return true
		}
	}
	return false
}

// Contains reports whether b still holds a token-shaped string.
func Contains(b []byte) bool {
	return Pattern.Match(b)
}
