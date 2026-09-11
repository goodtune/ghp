package observability

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/goodtune/ghp/internal/config"
)

// memExporter is an in-memory log exporter for asserting on emitted records.
type memExporter struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (e *memExporter) Export(_ context.Context, recs []sdklog.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range recs {
		e.records = append(e.records, recs[i].Clone())
	}
	return nil
}

func (e *memExporter) Shutdown(context.Context) error   { return nil }
func (e *memExporter) ForceFlush(context.Context) error { return nil }

func newTestLogger(t *testing.T, level slog.Leveler) (*slog.Logger, *memExporter) {
	t.Helper()
	exp := &memExporter{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(exp)))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	return slog.New(NewSlogHandler(provider, "test", level)), exp
}

func attr(r sdklog.Record, key string) (attribute.Value, bool) {
	var out attribute.Value
	var found bool
	r.WalkAttributes(func(kv attribute.KeyValue) bool {
		if string(kv.Key) == key {
			out, found = kv.Value, true
			return false
		}
		return true
	})
	return out, found
}

func TestSlogHandler_EmitsRecord(t *testing.T) {
	logger, exp := newTestLogger(t, slog.LevelInfo)

	logger.Info("hello world", "count", 3, "name", "ghp", "ok", true)

	if len(exp.records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(exp.records))
	}
	rec := exp.records[0]
	if rec.Body().AsString() != "hello world" {
		t.Errorf("body = %q", rec.Body().AsString())
	}
	if rec.Severity() != otellog.SeverityInfo {
		t.Errorf("severity = %v, want Info", rec.Severity())
	}
	if rec.InstrumentationScope().Name != "test" {
		t.Errorf("scope = %q", rec.InstrumentationScope().Name)
	}
	if v, ok := attr(rec, "count"); !ok || v.AsInt64() != 3 {
		t.Errorf("count attr = %v, ok=%v", v, ok)
	}
	if v, ok := attr(rec, "name"); !ok || v.AsString() != "ghp" {
		t.Errorf("name attr = %v, ok=%v", v, ok)
	}
	if v, ok := attr(rec, "ok"); !ok || !v.AsBool() {
		t.Errorf("ok attr = %v, ok=%v", v, ok)
	}
}

func TestSlogHandler_SeverityMapping(t *testing.T) {
	logger, exp := newTestLogger(t, slog.LevelDebug)

	logger.Debug("d")
	logger.Info("i")
	logger.Warn("w")
	logger.Error("e")

	want := []otellog.Severity{
		otellog.SeverityDebug,
		otellog.SeverityInfo,
		otellog.SeverityWarn,
		otellog.SeverityError,
	}
	if len(exp.records) != len(want) {
		t.Fatalf("got %d records, want %d", len(exp.records), len(want))
	}
	for i, w := range want {
		if got := exp.records[i].Severity(); got != w {
			t.Errorf("record %d severity = %v, want %v", i, got, w)
		}
	}
}

func TestSlogHandler_LevelFiltering(t *testing.T) {
	logger, exp := newTestLogger(t, slog.LevelWarn)

	logger.Info("dropped")
	logger.Debug("dropped")
	logger.Warn("kept")
	logger.Error("kept")

	if len(exp.records) != 2 {
		t.Fatalf("expected 2 records (warn+error), got %d", len(exp.records))
	}
}

func TestSlogHandler_WithAttrsAndGroup(t *testing.T) {
	logger, exp := newTestLogger(t, slog.LevelInfo)

	logger.With("service", "ghp").WithGroup("req").Info("msg", "method", "GET")

	if len(exp.records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(exp.records))
	}
	rec := exp.records[0]
	if v, ok := attr(rec, "service"); !ok || v.AsString() != "ghp" {
		t.Errorf("service attr = %v, ok=%v", v, ok)
	}
	// Attributes added after WithGroup are namespaced by the group name.
	if v, ok := attr(rec, "req.method"); !ok || v.AsString() != "GET" {
		t.Errorf("req.method attr = %v, ok=%v", v, ok)
	}
}

func TestSetup_FileOutputWritesRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ghp.log")

	cfg := config.Defaults()
	cfg.Logging.Output = "file"
	cfg.Logging.File.Path = path

	logging, closer, err := Setup(context.Background(), cfg, "v-test")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	logging.Logger.Info("file log line", "k", "v")
	closer()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log file: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatal("expected at least one log line")
	}
	var rec map[string]any
	if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
		t.Fatalf("log line is not valid JSON: %v\nraw: %s", err, scanner.Text())
	}
	body, _ := rec["Body"].(map[string]any)
	if body["Value"] != "file log line" {
		t.Errorf("unexpected body: %v", rec["Body"])
	}
}

func TestParseOTLPEndpoint(t *testing.T) {
	cases := []struct {
		in           string
		wantHost     string
		wantInsecure bool
	}{
		{"localhost:4317", "localhost:4317", false},
		{"http://localhost:4318", "localhost:4318", true},
		{"https://collector.example.com:4317", "collector.example.com:4317", false},
	}
	for _, c := range cases {
		host, insecure := parseOTLPEndpoint(c.in)
		if host != c.wantHost || insecure != c.wantInsecure {
			t.Errorf("parseOTLPEndpoint(%q) = (%q, %v), want (%q, %v)", c.in, host, insecure, c.wantHost, c.wantInsecure)
		}
	}
}
