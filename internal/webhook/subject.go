// Package webhook implements the GitHub webhook ingress: an HTTP handler that
// verifies X-Hub-Signature-256 against per-app secrets, an embedded NATS
// JetStream server that durably stores every verified delivery, an optional
// embedded ngrok tunnel that exposes the ingress publicly, and the JetStream
// iteration helpers behind the admin SSE stream (which the ghp webhooks CLI
// consumes).
package webhook

import (
	"strings"
)

// Placeholder is the subject token used when a delivery has no value for a
// position in the subject hierarchy (no action, no repository, unknown app).
const Placeholder = "_"

// SubjectParts are the values that make up a delivery's subject below the
// configured prefix. Each field is sanitised by Subject so that any value
// GitHub can send is a valid single NATS subject token.
type SubjectParts struct {
	AppRecordID string // ghp app record UUID, or "" when no app matched
	Event       string // X-GitHub-Event
	Action      string // payload "action", or ""
	Owner       string // repository.owner.login, or ""
	Repo        string // repository.name, or ""
}

// Subject builds the full publish subject
// {prefix}.{app}.{event}.{action}.{owner}.{repo} for a delivery. Every token
// is sanitised with SanitizeToken; empty values become Placeholder so the
// subject always has exactly six tokens after the prefix is accounted for,
// which keeps wildcard filters (e.g. "{prefix}.*.pull_request.>") stable.
func Subject(prefix string, p SubjectParts) string {
	return strings.Join([]string{
		prefix,
		SanitizeToken(p.AppRecordID),
		SanitizeToken(p.Event),
		SanitizeToken(p.Action),
		SanitizeToken(p.Owner),
		SanitizeToken(p.Repo),
	}, ".")
}

// SanitizeToken converts an arbitrary string into a single NATS subject
// token. NATS tokens cannot contain whitespace, '.', '*' or '>'; GitHub
// repository names may also contain '.', so every byte outside
// [A-Za-z0-9_-] is replaced with '_'. An empty input (or one that is empty
// after trimming) yields Placeholder.
func SanitizeToken(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return Placeholder
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
			b.WriteByte(c)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// ValidFilter reports whether filter is a syntactically valid NATS subject
// filter rooted under prefix: it must begin with prefix+"." (the stream only
// holds subjects below the prefix, so the bare prefix matches nothing),
// contain no whitespace or empty tokens, and use '>' only as the final
// token. Subscribers cannot escape the webhook subject space.
func ValidFilter(prefix, filter string) bool {
	if filter == "" {
		return false
	}
	if !strings.HasPrefix(filter, prefix+".") {
		return false
	}
	if strings.ContainsAny(filter, " \t\r\n") {
		return false
	}
	tokens := strings.Split(filter, ".")
	for i, tok := range tokens {
		if tok == "" {
			return false
		}
		if strings.Contains(tok, ">") && (tok != ">" || i != len(tokens)-1) {
			return false
		}
		if strings.Contains(tok, "*") && tok != "*" {
			return false
		}
	}
	return true
}
