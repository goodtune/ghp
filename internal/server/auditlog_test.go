package server

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestAuditLogWriterEntry(t *testing.T) {
	var buf bytes.Buffer
	aw := newAuditLogWriter(&buf)

	aw.writeEntry(&auditLogEntry{
		Msg:        "audit event",
		Action:     "token_created",
		UserID:     "user-123",
		Username:   "alice",
		SessionID:  "session-1",
		TokenID:    "tok-abc",
		TokenType:  "proxy",
		Repository: "org/repo",
	})

	var got auditLogEntry
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("failed to unmarshal audit log entry: %v", err)
	}
	if got.Logger != "audit" {
		t.Errorf("logger = %q, want %q", got.Logger, "audit")
	}
	if got.Level != "info" {
		t.Errorf("level = %q, want %q", got.Level, "info")
	}
	if got.Action != "token_created" {
		t.Errorf("action = %q, want %q", got.Action, "token_created")
	}
	if got.UserID != "user-123" {
		t.Errorf("user_id = %q, want %q", got.UserID, "user-123")
	}
	if got.Username != "alice" {
		t.Errorf("username = %q, want %q", got.Username, "alice")
	}
	if got.SessionID != "session-1" {
		t.Errorf("session_id = %q, want %q", got.SessionID, "session-1")
	}
	if got.TS == 0 {
		t.Error("ts should be non-zero")
	}
}

func TestAuditLogWriterProxyRequest(t *testing.T) {
	var buf bytes.Buffer
	aw := newAuditLogWriter(&buf)

	aw.writeEntry(&auditLogEntry{
		Msg:        "audit event",
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

	var got auditLogEntry
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if got.Method != "GET" {
		t.Errorf("method = %q, want GET", got.Method)
	}
	if got.Path != "/repos/org/repo/pulls" {
		t.Errorf("path = %q, want /repos/org/repo/pulls", got.Path)
	}
	if got.StatusCode != 200 {
		t.Errorf("status_code = %d, want 200", got.StatusCode)
	}
	if got.DurationMS != 42 {
		t.Errorf("duration_ms = %d, want 42", got.DurationMS)
	}
	if got.Repository != "org/repo" {
		t.Errorf("repository = %q, want org/repo", got.Repository)
	}
}

func TestAuditLogWriterNilWriter(t *testing.T) {
	aw := newAuditLogWriter(nil)
	// Should not panic.
	aw.writeEntry(&auditLogEntry{Action: "test"})
}
