package server

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/noop"

	"github.com/goodtune/ghp/internal/proxy"
)

// auditLogScope is the OpenTelemetry instrumentation scope name used for audit
// log records. Aggregators can route on this scope name in the same way they
// previously keyed on the Caddy "audit" logger name, indexing audit events
// separately from access logs.
const auditLogScope = "github.com/goodtune/ghp/audit"

// auditLogWriter emits audit events as OpenTelemetry log records.
type auditLogWriter struct {
	logger otellog.Logger
}

func newAuditLogWriter(logger otellog.Logger) *auditLogWriter {
	if logger == nil {
		logger = noop.NewLoggerProvider().Logger(auditLogScope)
	}
	return &auditLogWriter{logger: logger}
}

// WriteAuditEntry implements proxy.AuditLogWriter.
func (a *auditLogWriter) WriteAuditEntry(entry proxy.AuditLogEntry) {
	attrs := []attribute.KeyValue{
		attribute.String(attrGHPAuditAction, entry.Action),
	}
	attrs = appendNonEmpty(attrs, attrEndUserID, entry.UserID)
	attrs = appendNonEmpty(attrs, attrGHPUserName, entry.Username)
	attrs = appendNonEmpty(attrs, attrGHPTokenID, entry.TokenID)
	attrs = appendNonEmpty(attrs, attrGHPTokenType, entry.TokenType)
	attrs = appendNonEmpty(attrs, attrGHPSessionID, entry.SessionID)
	attrs = appendNonEmpty(attrs, attrHTTPRequestMethod, entry.Method)
	attrs = appendNonEmpty(attrs, attrURLPath, entry.Path)
	attrs = appendNonEmpty(attrs, attrGHPRepository, entry.Repository)
	if entry.StatusCode != 0 {
		attrs = append(attrs, attribute.Int(attrHTTPResponseStatusCode, entry.StatusCode))
	}
	if entry.DurationMS != 0 {
		attrs = append(attrs, attribute.Float64(attrHTTPServerRequestDuration, float64(entry.DurationMS)/1000))
	}

	var record otellog.Record
	record.SetBody(attribute.StringValue("audit event"))
	record.SetSeverity(otellog.SeverityInfo)
	record.SetSeverityText(otellog.SeverityInfo.String())
	record.AddAttributes(attrs...)
	a.logger.Emit(context.Background(), record)
}

func appendNonEmpty(attrs []attribute.KeyValue, key, value string) []attribute.KeyValue {
	if value == "" {
		return attrs
	}
	return append(attrs, attribute.String(key, value))
}
