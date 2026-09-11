// Package observability wires up OpenTelemetry logging for GHP.
//
// GHP treats OpenTelemetry log records as the first-class logging primitive.
// All application logging — operational messages emitted via log/slog, plus the
// HTTP access log and the audit log — flows through a single OTel
// LoggerProvider and is described using OpenTelemetry semantic conventions
// rather than the historical Caddy-style JSON field names.
//
// Records are exported to stdout (or a file) using the stdout log exporter and,
// when configured, simultaneously to an OTLP collector. The bridged *slog.Logger
// returned by Setup is installed as the slog default so that bare slog calls in
// background goroutines route through the same provider.
package observability

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutlog"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"github.com/goodtune/ghp/internal/config"
)

// Logging holds the initialised OpenTelemetry logging stack.
type Logging struct {
	// Logger is a *slog.Logger that emits OTel log records via the provider.
	// It is installed as the slog default by Setup's caller.
	Logger *slog.Logger
	// Provider is the underlying SDK LoggerProvider. Use it to obtain named
	// loggers for the access and audit log streams.
	Provider *sdklog.LoggerProvider

	shutdown func(context.Context) error
}

// Shutdown flushes and stops all exporters. It is safe to call with a context
// that carries a timeout to bound the flush.
func (l *Logging) Shutdown(ctx context.Context) error {
	if l == nil || l.shutdown == nil {
		return nil
	}
	return l.shutdown(ctx)
}

// Setup builds the OpenTelemetry logging stack from configuration.
//
// It always installs a stdout (or file) exporter so that operator-visible logs
// continue to be written to the process's standard output by default. When
// cfg.OTEL is enabled with an endpoint, an OTLP exporter is added alongside so
// records are simultaneously shipped to a collector.
//
// The returned closer releases the log file handle (when output=file) after the
// provider has been shut down; callers should defer it.
func Setup(ctx context.Context, cfg *config.Config, version string) (*Logging, func(), error) {
	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName("ghp"),
		semconv.ServiceVersion(version),
	))
	if err != nil {
		// resource.Merge only fails on schema URL conflicts; fall back to a
		// minimal resource so logging still works.
		res = resource.NewSchemaless(
			semconv.ServiceName("ghp"),
			semconv.ServiceVersion(version),
		)
	}

	opts := []sdklog.LoggerProviderOption{sdklog.WithResource(res)}

	// Console (stdout/file) exporter. A simple processor is used so records are
	// written synchronously and appear immediately — operators expect tailing a
	// log file or stdout to be live.
	w, closeWriter, err := logWriter(cfg)
	if err != nil {
		return nil, nil, err
	}
	stdoutExp, err := stdoutlog.New(stdoutlog.WithWriter(w))
	if err != nil {
		closeWriter()
		return nil, nil, fmt.Errorf("creating stdout log exporter: %w", err)
	}
	opts = append(opts, sdklog.WithProcessor(sdklog.NewSimpleProcessor(stdoutExp)))

	// Optional OTLP exporter, batched for throughput.
	if cfg.OTEL.Enabled && cfg.OTEL.Endpoint != "" {
		otlpExp, err := newOTLPExporter(ctx, cfg.OTEL)
		if err != nil {
			closeWriter()
			return nil, nil, fmt.Errorf("creating OTLP log exporter: %w", err)
		}
		opts = append(opts, sdklog.WithProcessor(sdklog.NewBatchProcessor(otlpExp)))
	}

	provider := sdklog.NewLoggerProvider(opts...)

	logging := &Logging{
		Logger:   slog.New(NewSlogHandler(provider, "github.com/goodtune/ghp", slogLevel(cfg.Logging.Level))),
		Provider: provider,
		shutdown: provider.Shutdown,
	}

	closer := func() {
		// The provider must be shut down (flushing batched OTLP records) before
		// the underlying file handle is closed.
		_ = provider.Shutdown(context.Background())
		closeWriter()
	}

	return logging, closer, nil
}

// logWriter returns the destination io.Writer for the console exporter and a
// closer for any file handle it opened.
func logWriter(cfg *config.Config) (io.Writer, func(), error) {
	if cfg.Logging.Output == "file" && cfg.Logging.File.Path != "" {
		f, err := os.OpenFile(cfg.Logging.File.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to open log file %q: %v; falling back to stdout\n", cfg.Logging.File.Path, err)
			return os.Stdout, func() {}, nil
		}
		return f, func() { _ = f.Close() }, nil
	}
	return os.Stdout, func() {}, nil
}

// newOTLPExporter constructs an OTLP log exporter for the configured transport.
func newOTLPExporter(ctx context.Context, cfg config.OTELConfig) (sdklog.Exporter, error) {
	endpoint, insecure := parseOTLPEndpoint(cfg.Endpoint)

	switch strings.ToLower(cfg.Protocol) {
	case "http", "http/protobuf":
		o := []otlploghttp.Option{otlploghttp.WithEndpoint(endpoint)}
		if insecure {
			o = append(o, otlploghttp.WithInsecure())
		}
		return otlploghttp.New(ctx, o...)
	default: // grpc
		o := []otlploggrpc.Option{otlploggrpc.WithEndpoint(endpoint)}
		if insecure {
			o = append(o, otlploggrpc.WithInsecure())
		}
		return otlploggrpc.New(ctx, o...)
	}
}

// parseOTLPEndpoint splits a configured endpoint into a host:port suitable for
// the OTLP exporter and a flag indicating whether TLS should be disabled. It
// accepts both bare host:port values and full URLs (http:// → insecure).
func parseOTLPEndpoint(endpoint string) (hostport string, insecure bool) {
	if !strings.Contains(endpoint, "://") {
		return endpoint, false
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return endpoint, false
	}
	return u.Host, u.Scheme == "http"
}

// slogLevel maps a configured level string to a slog.Level.
func slogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
