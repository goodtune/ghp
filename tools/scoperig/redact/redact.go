// Package redact removes GitHub and GHP token values from text, bodies and
// headers. Everything in the scope regression rig that could print a token
// must pass its output through this package.
//
// Known limitations (not detected or masked today):
//   - a percent-encoded token prefix (for example "ghx%5F...");
//   - a bare base64 credential with no "Authorization" label next to it;
//   - a token whose tail is JSON \uXXXX-escaped (for example "ghx_\u0041...").
package redact

import (
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
)

// Pattern matches any GitHub or GHP token-shaped string. Submatch 1 is the
// prefix, which is kept so redacted output still shows the token type.
// It is case-sensitive: real prefixes are lower case, and a case-insensitive
// match would mangle names such as GHP_SERVER_URL.
var Pattern = regexp.MustCompile(`(gh[oupsrx]_|gha_|ghpr_|github_pat_)[A-Za-z0-9_]{8,}`)

const (
	replacement = "${1}[REDACTED]"
	masked      = "[REDACTED]"
)

var replacementBytes = []byte(replacement)

// authLine matches an Authorization header written as free text or as a
// JSON member ("Authorization": "Basic ..."), so that credentials that are
// not token-shaped (for example Basic base64) are masked. The credential
// stops at whitespace or a quote, so redacted JSON stays valid.
var authLine = regexp.MustCompile(`(?i)(authorization"?\s*:\s*"?(basic|bearer|token)\s+)[^\s"]+`)

// basicLine captures the credential of an Authorization: Basic line, free
// text or JSON-quoted. Only base64 characters (standard and URL-safe) are
// captured, so trailing punctuation (a quote, comma or full stop) does not
// stop the credential from decoding.
var basicLine = regexp.MustCompile(`(?i)authorization"?\s*:\s*"?basic\s+([A-Za-z0-9+/_=-]+)`)

// basicEncodings are tried in turn when decoding a Basic credential.
var basicEncodings = []*base64.Encoding{
	base64.StdEncoding, base64.RawStdEncoding,
	base64.URLEncoding, base64.RawURLEncoding,
}

// sensitiveHeaders have their whole value replaced, token-shaped or not.
var sensitiveHeaders = []string{"Authorization", "Cookie", "Set-Cookie"}

// String replaces each token in s with "<prefix>[REDACTED]".
func String(s string) string {
	return authLine.ReplaceAllString(Pattern.ReplaceAllString(s, replacement), replacement)
}

// Bytes replaces each token in b with "<prefix>[REDACTED]". It returns a new slice.
func Bytes(b []byte) []byte {
	return authLine.ReplaceAll(Pattern.ReplaceAll(b, replacementBytes), replacementBytes)
}

// Header returns a redacted copy of h. Authorization, Cookie and Set-Cookie
// values become "[REDACTED]"; all other values pass through String. The input
// is not modified.
func Header(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vs := range h {
		cp := make([]string, len(vs))
		sensitive := isSensitive(k)
		for i, v := range vs {
			if sensitive {
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

// Contains reports whether b still holds a token-shaped string, either in
// plain text or inside the base64 credential of an Authorization: Basic line.
func Contains(b []byte) bool {
	if Pattern.Match(b) {
		return true
	}
	for _, m := range basicLine.FindAllSubmatch(b, -1) {
		for _, enc := range basicEncodings {
			if dec, err := enc.DecodeString(string(m[1])); err == nil && Pattern.Match(dec) {
				return true
			}
		}
	}
	return false
}
