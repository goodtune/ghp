// Package redact removes GitHub and GHP token values from text, bodies and
// headers. Everything in the scope regression rig that could print a token
// must pass its output through this package.
//
// Forms handled: plain tokens; tokens written with percent-encoding
// ("%67hx_...") or JSON \uXXXX escapes in any position (escapes are decoded
// before matching, and only escapes of token characters are decoded, so
// the surrounding text keeps its encoding); Authorization Basic, Bearer and
// token credentials, free text or JSON; and bare base64 or base64url
// credentials that decode to "<user>:<token>".
//
// Known limitations (not detected or masked today):
//   - a bare base64 credential embedded mid-word, so that the encoded run
//     does not start on a 4-character boundary of the credential;
//   - a token split by other encodings (HTML entities, double
//     percent-encoding, base64 of anything but "<user>:<token>");
//   - upper-case prefixes, which are not real tokens (see Pattern).
package redact

import (
	"encoding/base64"
	"net/http"
	"regexp"
	"strconv"
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

// escapedRun matches a run of token characters in which at least one is
// written as a percent escape or a JSON \uXXXX escape. Runs are decoded
// before matching, so "%67hx_..." and "ghx_ab\u0063..." are found whole.
var escapedRun = regexp.MustCompile(`(?:[A-Za-z0-9_]|%[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4})*(?:%[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4})(?:[A-Za-z0-9_]|%[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4})*`)

// escapeAtom matches one escape inside an escapedRun.
var escapeAtom = regexp.MustCompile(`%[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}`)

// bareBase64 matches a standalone base64 or base64url run long enough to
// hold "<user>:<prefix><8 chars>".
var bareBase64 = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)

// userToken matches a decoded "<user>:<token>" credential.
var userToken = regexp.MustCompile(`\A[^:\s]*:` + Pattern.String())

// String replaces each token in s with "<prefix>[REDACTED]", and each bare
// base64 "<user>:<token>" credential with "[REDACTED]".
func String(s string) string {
	s = escapedRun.ReplaceAllStringFunc(s, func(run string) string {
		dec := decodeRun(run)
		if !Pattern.MatchString(dec) {
			return run
		}
		return Pattern.ReplaceAllString(dec, replacement)
	})
	s = authLine.ReplaceAllString(Pattern.ReplaceAllString(s, replacement), replacement)
	return bareBase64.ReplaceAllStringFunc(s, func(run string) string {
		if decodesToUserToken(run) {
			return masked
		}
		return run
	})
}

// Bytes is String for a byte slice. It returns a new slice.
func Bytes(b []byte) []byte {
	return []byte(String(string(b)))
}

// decodeRun decodes the escapes in an escapedRun that stand for token
// characters. Other escapes (a space, a slash, a newline) stay encoded, so
// the decoded text keeps its meaning and a token next to them is still
// found. Callers keep the original run unless the decoded one holds a token.
func decodeRun(run string) string {
	return escapeAtom.ReplaceAllStringFunc(run, func(e string) string {
		hex := e[1:]
		if e[0] == '\\' {
			hex = e[2:]
		}
		n, err := strconv.ParseUint(hex, 16, 32)
		if err != nil || !isTokenChar(rune(n)) {
			return e
		}
		return string(rune(n))
	})
}

func isTokenChar(r rune) bool {
	return r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// decodesToUserToken reports whether run is base64 or base64url for
// "<user>:<token>".
func decodesToUserToken(run string) bool {
	for _, enc := range basicEncodings {
		if dec, err := enc.DecodeString(run); err == nil && userToken.Match(dec) {
			return true
		}
	}
	return false
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

// Contains reports whether b still holds a token-shaped string: in plain
// text, percent- or JSON-escaped, inside the base64 credential of an
// Authorization: Basic line, or as a bare base64 "<user>:<token>".
func Contains(b []byte) bool {
	if Pattern.Match(b) {
		return true
	}
	for _, run := range escapedRun.FindAll(b, -1) {
		if Pattern.MatchString(decodeRun(string(run))) {
			return true
		}
	}
	for _, run := range bareBase64.FindAll(b, -1) {
		if decodesToUserToken(string(run)) {
			return true
		}
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
