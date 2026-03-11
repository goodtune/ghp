package server

import (
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/goodtune/ghp/internal/proxy"
)

// auditLogEntry is a structured JSON audit event, written to the same log
// stream as access logs but distinguished by the "audit" logger name. This
// allows log aggregators (Splunk, Elastic, etc.) to index audit events
// separately from access logs.
type auditLogEntry struct {
	Level        string          `json:"level"`
	TS           float64         `json:"ts"`
	Logger       string          `json:"logger"`
	Msg          string          `json:"msg"`
	Action       string          `json:"action"`
	UserID       string          `json:"user_id,omitempty"`
	Username     string          `json:"username,omitempty"`
	TokenID      string          `json:"token_id,omitempty"`
	TokenType    string          `json:"token_type,omitempty"`
	SessionID    string          `json:"session_id,omitempty"`
	Method       string          `json:"method,omitempty"`
	Path         string          `json:"path,omitempty"`
	Repository   string          `json:"repository,omitempty"`
	StatusCode   int             `json:"status_code,omitempty"`
	DurationMS   int             `json:"duration_ms,omitempty"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
}

// auditLogWriter provides thread-safe structured JSON audit log writing.
type auditLogWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func newAuditLogWriter(w io.Writer) *auditLogWriter {
	if w == nil {
		w = io.Discard
	}
	return &auditLogWriter{w: w}
}

// WriteAuditEntry implements proxy.AuditLogWriter.
func (a *auditLogWriter) WriteAuditEntry(entry proxy.AuditLogEntry) {
	a.writeEntry(&auditLogEntry{
		Msg:        "audit event",
		Action:     entry.Action,
		UserID:     entry.UserID,
		Username:   entry.Username,
		TokenID:    entry.TokenID,
		TokenType:  entry.TokenType,
		SessionID:  entry.SessionID,
		Method:     entry.Method,
		Path:       entry.Path,
		Repository: entry.Repository,
		StatusCode: entry.StatusCode,
		DurationMS: entry.DurationMS,
	})
}

func (a *auditLogWriter) writeEntry(entry *auditLogEntry) {
	if entry.TS == 0 {
		entry.TS = float64(time.Now().UnixNano()) / 1e9
	}
	entry.Level = "info"
	entry.Logger = "audit"
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')
	a.mu.Lock()
	defer a.mu.Unlock()
	a.w.Write(data) // best-effort; audit log write errors are non-critical
}
