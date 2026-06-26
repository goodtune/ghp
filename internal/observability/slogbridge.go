package observability

import (
	"context"
	"log/slog"
	"slices"

	otellog "go.opentelemetry.io/otel/log"
)

// slogHandler is a slog.Handler that translates slog records into
// OpenTelemetry log records and emits them through an OTel LoggerProvider.
//
// It is intentionally small and self-contained: it maps slog levels to OTel
// severities, carries attributes added via WithAttrs/WithGroup, and converts
// slog.Value kinds to OTel log values. This keeps every slog call site in the
// codebase unchanged while making OTel log records the underlying primitive.
type slogHandler struct {
	logger otellog.Logger
	level  slog.Leveler

	// attrs are the pre-formatted attributes accumulated via WithAttrs, already
	// namespaced by any active groups.
	attrs []otellog.KeyValue
	// groups is the stack of open group names; new attributes and record
	// attributes are prefixed with these (dot-joined).
	groups []string
}

// NewSlogHandler returns a slog.Handler that emits OTel log records via the
// given provider. The scope name identifies the instrumentation scope on every
// emitted record. minLevel is the minimum slog level that will be emitted.
func NewSlogHandler(provider otellog.LoggerProvider, scope string, minLevel slog.Leveler) slog.Handler {
	return &slogHandler{
		logger: provider.Logger(scope),
		level:  minLevel,
	}
}

// Enabled reports whether records at the given level should be processed.
func (h *slogHandler) Enabled(_ context.Context, level slog.Level) bool {
	min := slog.LevelInfo
	if h.level != nil {
		min = h.level.Level()
	}
	return level >= min
}

// Handle converts a slog.Record into an OTel log record and emits it.
func (h *slogHandler) Handle(ctx context.Context, r slog.Record) error {
	var rec otellog.Record
	if !r.Time.IsZero() {
		rec.SetTimestamp(r.Time)
	}
	rec.SetBody(otellog.StringValue(r.Message))
	rec.SetSeverity(severity(r.Level))
	rec.SetSeverityText(r.Level.String())

	rec.AddAttributes(h.attrs...)

	r.Attrs(func(a slog.Attr) bool {
		if kv, ok := convertAttr(h.groups, a); ok {
			rec.AddAttributes(kv)
		}
		return true
	})

	h.logger.Emit(ctx, rec)
	return nil
}

// WithAttrs returns a new handler whose records carry the given attributes.
func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	nh := h.clone()
	for _, a := range attrs {
		if kv, ok := convertAttr(h.groups, a); ok {
			nh.attrs = append(nh.attrs, kv)
		}
	}
	return nh
}

// WithGroup returns a new handler that namespaces subsequent attributes under
// the given group name.
func (h *slogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	nh := h.clone()
	nh.groups = append(nh.groups, name)
	return nh
}

func (h *slogHandler) clone() *slogHandler {
	return &slogHandler{
		logger: h.logger,
		level:  h.level,
		attrs:  slices.Clone(h.attrs),
		groups: slices.Clone(h.groups),
	}
}

// severity maps a slog.Level to the closest OTel severity.
func severity(level slog.Level) otellog.Severity {
	switch {
	case level >= slog.LevelError:
		return otellog.SeverityError
	case level >= slog.LevelWarn:
		return otellog.SeverityWarn
	case level >= slog.LevelInfo:
		return otellog.SeverityInfo
	default:
		return otellog.SeverityDebug
	}
}

// convertAttr converts a slog.Attr (honouring the active group prefix) into an
// OTel log.KeyValue. Empty attributes are dropped (ok=false). Group-valued
// attributes are flattened into a nested map.
func convertAttr(groups []string, a slog.Attr) (otellog.KeyValue, bool) {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return otellog.KeyValue{}, false
	}
	key := a.Key
	if len(groups) > 0 {
		key = joinGroups(groups, key)
	}
	return otellog.KeyValue{Key: key, Value: convertValue(a.Value)}, true
}

func joinGroups(groups []string, key string) string {
	out := ""
	for _, g := range groups {
		if g == "" {
			continue
		}
		out += g + "."
	}
	return out + key
}

// convertValue maps a slog.Value to an OTel log.Value.
func convertValue(v slog.Value) otellog.Value {
	switch v.Kind() {
	case slog.KindString:
		return otellog.StringValue(v.String())
	case slog.KindInt64:
		return otellog.Int64Value(v.Int64())
	case slog.KindUint64:
		return otellog.Int64Value(int64(v.Uint64()))
	case slog.KindFloat64:
		return otellog.Float64Value(v.Float64())
	case slog.KindBool:
		return otellog.BoolValue(v.Bool())
	case slog.KindDuration:
		return otellog.Int64Value(v.Duration().Nanoseconds())
	case slog.KindTime:
		return otellog.StringValue(v.Time().Format("2006-01-02T15:04:05.000000000Z07:00"))
	case slog.KindGroup:
		attrs := v.Group()
		kvs := make([]otellog.KeyValue, 0, len(attrs))
		for _, a := range attrs {
			if kv, ok := convertAttr(nil, a); ok {
				kvs = append(kvs, kv)
			}
		}
		return otellog.MapValue(kvs...)
	default: // slog.KindAny and anything else
		return otellog.StringValue(v.String())
	}
}
