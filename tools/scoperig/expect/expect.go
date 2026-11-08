// Package expect evaluates scenario expectations against observed
// responses and produces deterministic, redacted mismatch explanations.
package expect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goodtune/ghp/tools/scoperig/ghdebug"
	"github.com/goodtune/ghp/tools/scoperig/redact"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

// GHP denial message prefixes, copied from internal/proxy and internal/token.
const (
	MsgNotScoped             = "Token is not scoped to"
	MsgNoPermission          = "Token does not have permission"
	MsgGraphQLScopes         = "Token does not grant required GraphQL scopes"
	MsgRepoRestricted        = "Token is repository-restricted"
	MsgUnmappedFields        = "GraphQL request references unmapped fields"
	MsgSubscriptions         = "GraphQL subscriptions are not supported"
	MsgMutationUnscoped      = "GraphQL mutation could not be statically scoped"
	MsgRevoked               = "token has been revoked"
	MsgExpired               = "token has expired"
	MsgBorderPolicy          = "Token type is not permitted by the border policy"
	MsgInvalidToken          = "Invalid token"
	MsgAnonymousGit          = "Anonymous git access is not permitted"
	MsgReleaseDownloads      = "Release downloads are not permitted"
	MsgTokenResolutionFailed = "Token resolution failed"
	MsgInvalidPrefix         = "invalid token prefix"
	MsgLookupFailed          = "looking up token:"
	MsgManagementAnonymous   = "Authentication with a GHP-issued token (ghx_ or gha_) is required"
	MsgManagementNative      = "Native GitHub tokens are not accepted on the GHP management host"
	MsgRepoRestrictedNonRepo = "Token is restricted to specific repositories"
	MsgPassthroughUnmapped   = "Token is scoped;"
	MsgUnsafePath            = "Request path contains an unsafe segment or character"
	// MsgEndpointNotPermitted is matched as a substring, not a prefix: the
	// message starts "Endpoint <METHOD> <path>", and a bare "Endpoint"
	// prefix could match GitHub's own messages.
	MsgEndpointNotPermitted = " is not permitted for scoped tokens (no scope rule matches)"
	DocsURLREST             = "https://docs.github.com/rest"
	DocsURLGraphQL          = "https://docs.github.com/graphql"
)

var denialPrefixes = []string{
	MsgNotScoped, MsgNoPermission, MsgGraphQLScopes, MsgRepoRestricted,
	MsgUnmappedFields, MsgSubscriptions, MsgMutationUnscoped, MsgRevoked,
	MsgExpired, MsgBorderPolicy, MsgInvalidToken, MsgAnonymousGit,
	MsgReleaseDownloads, MsgTokenResolutionFailed, MsgInvalidPrefix,
	MsgLookupFailed, MsgManagementAnonymous, MsgManagementNative,
	MsgRepoRestrictedNonRepo, MsgPassthroughUnmapped, MsgUnsafePath,
}

// denialContains holds GHP denial messages whose fixed text is not at the
// start; a message must also start with the paired prefix.
var denialContains = []struct{ prefix, substr string }{
	{"Endpoint ", MsgEndpointNotPermitted},
}

// Observation is what an executor saw for one step.
type Observation struct {
	Status    int
	Header    http.Header // redacted
	Body      []byte      // redacted, capped 64 KiB
	GHExit    *int
	Stdout    string
	Stderr    string
	Exchanges []ghdebug.Exchange
	// RequestedAt and RespondedAt bracket the request that produced this
	// observation (zero when not recorded). expires_within is relative to
	// them.
	RequestedAt, RespondedAt time.Time
	// GHStderrTruncated is set when gh's stderr exceeded the capture cap.
	GHStderrTruncated bool
}

// Match returns nil if every set field of e holds, else one error per
// mismatch, each phrased "want X, got Y". Errors are in a fixed order and
// pass through redact.String.
func Match(e *scenario.Expect, o *Observation) []error {
	if e == nil {
		return nil
	}
	if o == nil {
		o = &Observation{}
	}
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }

	if e.Status != 0 && o.Status != e.Status {
		add("status: want %d, got %d", e.Status, o.Status)
	}
	if len(e.StatusIn) > 0 && !containsInt(e.StatusIn, o.Status) {
		add("status_in: want one of %v, got %d", e.StatusIn, o.Status)
	}
	for _, s := range e.BodyContains {
		if !bytes.Contains(o.Body, []byte(s)) {
			add("body: want contains %q, got %s", s, snippet(o.Body))
		}
	}
	for _, s := range e.BodyNotContains {
		if bytes.Contains(o.Body, []byte(s)) {
			add("body: want not contains %q, got %s", s, snippet(o.Body))
		}
	}
	// header: compares against the first value of the header only.
	for _, k := range sortedKeys(e.Header) {
		if got := o.Header.Get(k); got != e.Header[k] {
			add("header %s: want %q, got %q", k, e.Header[k], got)
		}
	}
	if len(e.HeaderNotContains) > 0 {
		lines := headerLines(o.Header)
		for _, s := range e.HeaderNotContains {
			for _, l := range lines {
				if strings.Contains(l, s) {
					add("headers: want not contains %q, got %q", s, l)
					break
				}
			}
		}
	}
	for _, k := range sortedKeys(e.JSON) {
		got, err := JSONPath(o.Body, k)
		if err != nil {
			add("json %s: want %q, got error (%v)", k, e.JSON[k], err)
		} else if got != e.JSON[k] {
			add("json %s: want %q, got %q", k, e.JSON[k], got)
		}
	}
	if e.GHPDenial != nil {
		if got := IsGHPDenialResponse(o.Status, o.Body); got != *e.GHPDenial {
			add("ghp_denial: want %t, got %t (message %q)", *e.GHPDenial, got, GHPMessage(o.Body))
		}
	}
	if e.ExitCode != nil {
		if o.GHExit == nil {
			add("exit_code: want %d, got none", *e.ExitCode)
		} else if *o.GHExit != *e.ExitCode {
			add("exit_code: want %d, got %d", *e.ExitCode, *o.GHExit)
		}
	}
	if len(e.ExitCodeIn) > 0 {
		if o.GHExit == nil {
			add("exit_code_in: want one of %v, got none", e.ExitCodeIn)
		} else if !containsInt(e.ExitCodeIn, *o.GHExit) {
			add("exit_code_in: want one of %v, got %d", e.ExitCodeIn, *o.GHExit)
		}
	}
	for _, s := range e.StdoutContains {
		if !strings.Contains(o.Stdout, s) {
			add("stdout: want contains %q, got %s", s, snippet([]byte(o.Stdout)))
		}
	}
	for _, s := range e.StderrContains {
		if !strings.Contains(o.Stderr, s) {
			add("stderr: want contains %q, got %s", s, snippet([]byte(o.Stderr)))
		}
	}
	if w := e.ExpiresWithin; w != nil {
		if msg := matchExpiresWithin(w, o); msg != "" {
			add("%s", msg)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	out := make([]error, len(errs))
	for i, s := range errs {
		out[i] = fmt.Errorf("%s", redact.String(s))
	}
	return out
}

// matchExpiresWithin checks that the timestamp at w's field lies in
// [RequestedAt+min, RespondedAt+max]. It returns "" when it holds.
func matchExpiresWithin(w *scenario.ExpiresWithin, o *Observation) string {
	path := w.FieldPath()
	lo, err := time.ParseDuration(w.Min)
	if err != nil {
		return fmt.Sprintf("expires_within %s: bad min %q: %v", path, w.Min, err)
	}
	hi, err := time.ParseDuration(w.Max)
	if err != nil {
		return fmt.Sprintf("expires_within %s: bad max %q: %v", path, w.Max, err)
	}
	if o.RequestedAt.IsZero() {
		return fmt.Sprintf("expires_within %s: no request time recorded", path)
	}
	end := o.RespondedAt
	if end.IsZero() {
		end = o.RequestedAt
	}
	raw, err := JSONPath(o.Body, path)
	if err != nil {
		return fmt.Sprintf("expires_within %s: want a timestamp, got error (%v)", path, err)
	}
	got, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return fmt.Sprintf("expires_within %s: want an RFC 3339 timestamp, got %q", path, raw)
	}
	earliest, latest := o.RequestedAt.Add(lo), end.Add(hi)
	if got.Before(earliest) || got.After(latest) {
		return fmt.Sprintf("expires_within %s: want between request+%s and response+%s (%s..%s), got %s (request+%s)",
			path, lo, hi, earliest.UTC().Format(time.RFC3339), latest.UTC().Format(time.RFC3339),
			got.UTC().Format(time.RFC3339), got.Sub(o.RequestedAt).Round(time.Second))
	}
	return ""
}

const snippetMax = 200

func snippet(b []byte) string {
	if len(b) > snippetMax {
		return strconv.Quote(string(b[:snippetMax])) + "..."
	}
	return strconv.Quote(string(b))
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// JSONPath evaluates a minimal path ("$.a.b", "$.items[0].id") against a
// JSON body. Strings are returned unquoted, numbers exactly as written in
// the body (full integer precision; no float re-formatting),
// booleans and null as literals, objects and arrays as compact JSON.
func JSONPath(body []byte, path string) (string, error) {
	if !strings.HasPrefix(path, "$") {
		return "", fmt.Errorf("path %q must start with $", path)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", fmt.Errorf("body is not JSON: %w", err)
	}
	rest := path[1:]
	for rest != "" {
		switch rest[0] {
		case '.':
			rest = rest[1:]
			end := strings.IndexAny(rest, ".[")
			if end < 0 {
				end = len(rest)
			}
			key := rest[:end]
			rest = rest[end:]
			if key == "" {
				return "", fmt.Errorf("path %q: empty key", path)
			}
			obj, ok := v.(map[string]any)
			if !ok {
				return "", fmt.Errorf("path %q: %q applied to non-object", path, key)
			}
			if v, ok = obj[key]; !ok {
				return "", fmt.Errorf("path %q: key %q not found", path, key)
			}
		case '[':
			end := strings.IndexByte(rest, ']')
			if end < 0 {
				return "", fmt.Errorf("path %q: unterminated index", path)
			}
			idx, err := strconv.Atoi(rest[1:end])
			if err != nil || idx < 0 {
				return "", fmt.Errorf("path %q: bad index %q", path, rest[1:end])
			}
			rest = rest[end+1:]
			arr, ok := v.([]any)
			if !ok {
				return "", fmt.Errorf("path %q: index applied to non-array", path)
			}
			if idx >= len(arr) {
				return "", fmt.Errorf("path %q: index %d out of range (len %d)", path, idx, len(arr))
			}
			v = arr[idx]
		default:
			return "", fmt.Errorf("path %q: unexpected %q", path, rest[:1])
		}
	}
	switch t := v.(type) {
	case string:
		return t, nil
	case json.Number:
		return t.String(), nil
	case bool:
		return strconv.FormatBool(t), nil
	case nil:
		return "null", nil
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
}

// GHPMessage returns $.message if body is a JSON object, else "".
func GHPMessage(body []byte) string {
	var m struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &m) != nil {
		return ""
	}
	return m.Message
}

// IsGHPDenial reports whether body carries a GHP-generated denial message.
func IsGHPDenial(body []byte) bool {
	msg := GHPMessage(body)
	if msg == "" {
		return false
	}
	for _, p := range denialPrefixes {
		if strings.HasPrefix(msg, p) {
			return true
		}
	}
	for _, c := range denialContains {
		if strings.HasPrefix(msg, c.prefix) && strings.Contains(msg, c.substr) {
			return true
		}
	}
	return false
}

// IsGHPDenialResponse reports whether a response is a GHP denial: a 401 or
// 403 status carrying a GHP denial message.
func IsGHPDenialResponse(status int, body []byte) bool {
	return (status == 401 || status == 403) && IsGHPDenial(body)
}

// headerLines returns "Name: value" for every value of h, sorted by name.
func headerLines(h http.Header) []string {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)
	var out []string
	for _, k := range names {
		for _, v := range h[k] {
			out = append(out, k+": "+v)
		}
	}
	return out
}
