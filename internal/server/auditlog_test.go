package server

import (
	"testing"

	otellog "go.opentelemetry.io/otel/log"

	"github.com/goodtune/ghp/internal/proxy"
)

func TestAuditLogWriterEntry(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAuditLogWriter(logger)

	aw.WriteAuditEntry(proxy.AuditLogEntry{
		Action:     "token_created",
		UserID:     "user-123",
		Username:   "alice",
		SessionID:  "session-1",
		TokenID:    "tok-abc",
		TokenType:  "proxy",
		Repository: "org/repo",
	})

	rec := exp.only(t)

	if rec.scope != "test" {
		t.Errorf("scope = %q", rec.scope)
	}
	if rec.severity != otellog.SeverityInfo {
		t.Errorf("severity = %v, want Info", rec.severity)
	}
	if rec.body != "audit event" {
		t.Errorf("body = %q, want %q", rec.body, "audit event")
	}
	if got := rec.str(t, attrGHPAuditAction); got != "token_created" {
		t.Errorf("%s = %q, want token_created", attrGHPAuditAction, got)
	}
	if got := rec.str(t, attrEndUserID); got != "user-123" {
		t.Errorf("%s = %q, want user-123", attrEndUserID, got)
	}
	if got := rec.str(t, attrGHPUserName); got != "alice" {
		t.Errorf("%s = %q, want alice", attrGHPUserName, got)
	}
	if got := rec.str(t, attrGHPSessionID); got != "session-1" {
		t.Errorf("%s = %q, want session-1", attrGHPSessionID, got)
	}
	if got := rec.str(t, attrGHPTokenID); got != "tok-abc" {
		t.Errorf("%s = %q, want tok-abc", attrGHPTokenID, got)
	}
	if got := rec.str(t, attrGHPTokenType); got != "proxy" {
		t.Errorf("%s = %q, want proxy", attrGHPTokenType, got)
	}
	if got := rec.str(t, attrGHPRepository); got != "org/repo" {
		t.Errorf("%s = %q, want org/repo", attrGHPRepository, got)
	}
}

func TestAuditLogWriterProxyRequest(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAuditLogWriter(logger)

	aw.WriteAuditEntry(proxy.AuditLogEntry{
		Action:     "proxy_request",
		UserID:     "user-456",
		Username:   "bob",
		TokenID:    "tok-xyz",
		TokenType:  "proxy",
		SessionID:  "sess-2",
		Method:     "GET",
		Path:       "/repos/org/repo/pulls",
		Repository: "org/repo",
		StatusCode: 200,
		DurationMS: 42,
	})

	rec := exp.only(t)

	if got := rec.str(t, attrHTTPRequestMethod); got != "GET" {
		t.Errorf("%s = %q, want GET", attrHTTPRequestMethod, got)
	}
	if got := rec.str(t, attrURLPath); got != "/repos/org/repo/pulls" {
		t.Errorf("%s = %q, want /repos/org/repo/pulls", attrURLPath, got)
	}
	if got := rec.int(t, attrHTTPResponseStatusCode); got != 200 {
		t.Errorf("%s = %d, want 200", attrHTTPResponseStatusCode, got)
	}
	// 42ms is recorded as 0.042 seconds under the duration convention.
	if got := rec.float(t, attrHTTPServerRequestDuration); got != 0.042 {
		t.Errorf("%s = %v, want 0.042", attrHTTPServerRequestDuration, got)
	}
	if got := rec.str(t, attrGHPRepository); got != "org/repo" {
		t.Errorf("%s = %q, want org/repo", attrGHPRepository, got)
	}
}

func TestAuditLogWriterNilLogger(t *testing.T) {
	aw := newAuditLogWriter(nil)
	// Should not panic.
	aw.WriteAuditEntry(proxy.AuditLogEntry{Action: "test"})
}
