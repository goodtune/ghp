package server

import (
	"context"
	"sync"
	"testing"

	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// captureExporter is an in-memory sdklog.Exporter used by tests to assert on the
// OpenTelemetry log records emitted by the access and audit log writers.
type captureExporter struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (e *captureExporter) Export(_ context.Context, recs []sdklog.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range recs {
		e.records = append(e.records, recs[i].Clone())
	}
	return nil
}

func (e *captureExporter) Shutdown(context.Context) error   { return nil }
func (e *captureExporter) ForceFlush(context.Context) error { return nil }

// newCaptureLogger returns an OTel logger that records every emitted record into
// the returned exporter. A simple processor is used so records are available
// synchronously after Emit returns.
func newCaptureLogger(t *testing.T) (otellog.Logger, *captureExporter) {
	t.Helper()
	exp := &captureExporter{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(exp)))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	return provider.Logger("test"), exp
}

// loggedRecord is a flattened, assertion-friendly view of a captured record.
type loggedRecord struct {
	body         string
	severity     otellog.Severity
	severityText string
	scope        string
	attrs        map[string]otellog.Value
}

// only returns the single captured record, failing if there is not exactly one.
func (e *captureExporter) only(t *testing.T) loggedRecord {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.records) != 1 {
		t.Fatalf("expected exactly 1 record, got %d", len(e.records))
	}
	return flatten(e.records[0])
}

func (e *captureExporter) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.records)
}

func flatten(r sdklog.Record) loggedRecord {
	out := loggedRecord{
		body:         r.Body().AsString(),
		severity:     r.Severity(),
		severityText: r.SeverityText(),
		scope:        r.InstrumentationScope().Name,
		attrs:        map[string]otellog.Value{},
	}
	r.WalkAttributes(func(kv otellog.KeyValue) bool {
		out.attrs[kv.Key] = kv.Value
		return true
	})
	return out
}

func (r loggedRecord) has(key string) bool {
	_, ok := r.attrs[key]
	return ok
}

func (r loggedRecord) str(t *testing.T, key string) string {
	t.Helper()
	v, ok := r.attrs[key]
	if !ok {
		t.Fatalf("attribute %q not present", key)
	}
	return v.AsString()
}

func (r loggedRecord) int(t *testing.T, key string) int64 {
	t.Helper()
	v, ok := r.attrs[key]
	if !ok {
		t.Fatalf("attribute %q not present", key)
	}
	return v.AsInt64()
}

func (r loggedRecord) float(t *testing.T, key string) float64 {
	t.Helper()
	v, ok := r.attrs[key]
	if !ok {
		t.Fatalf("attribute %q not present", key)
	}
	return v.AsFloat64()
}

// slice returns a string-header attribute (e.g. http.request.header.*) as a
// []string.
func (r loggedRecord) slice(t *testing.T, key string) []string {
	t.Helper()
	v, ok := r.attrs[key]
	if !ok {
		t.Fatalf("attribute %q not present", key)
	}
	vals := v.AsSlice()
	out := make([]string, 0, len(vals))
	for _, vv := range vals {
		out = append(out, vv.AsString())
	}
	return out
}
