package server

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/noop"

	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/netutil"
	"github.com/goodtune/ghp/internal/proxy"
)

// responseRecorder wraps http.ResponseWriter to capture status and size.
type responseRecorder struct {
	http.ResponseWriter
	status      int
	size        int
	wroteHeader bool
}

func (r *responseRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.status = code
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(b)
	r.size += n
	return n, err
}

// Flush implements http.Flusher by delegating to the underlying writer.
func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the underlying ResponseWriter so callers can access
// optional interfaces (e.g. http.Hijacker) via httputil helpers.
func (r *responseRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// accessLogScope is the OpenTelemetry instrumentation scope name used for HTTP
// access log records. Aggregators can route on this scope name in the same way
// they previously keyed on the Caddy "http.log.access" logger name.
const accessLogScope = "github.com/goodtune/ghp/access"

// accessLogWriter emits HTTP access events as OpenTelemetry log records,
// described using HTTP semantic conventions.
type accessLogWriter struct {
	logger otellog.Logger
}

func newAccessLogWriter(logger otellog.Logger) *accessLogWriter {
	if logger == nil {
		logger = noop.NewLoggerProvider().Logger(accessLogScope)
	}
	return &accessLogWriter{logger: logger}
}

// accessLogHandler wraps an http.Handler with OpenTelemetry access logging and
// per-backend Prometheus metrics.
func accessLogHandler(backend string, next http.Handler, aw *accessLogWriter, clientIPHeader netutil.IPHeader) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}

		// Prepare mutable slots in the request context so downstream
		// handlers can inject the resolved GitHub username and user ID.
		r, slots := proxy.PrepareAccessLogSlots(r)

		next.ServeHTTP(rec, r)

		dur := time.Since(start)
		statusStr := strconv.Itoa(rec.status)

		clientIP := netutil.ClientIP(r, clientIPHeader)
		remoteIP, remotePort := splitRemoteAddr(r.RemoteAddr)
		serverHost, serverPort := splitHostPortPreserve(r.Host)

		// Prefer the GitHub username for the end-user identity so that
		// operators see a recognisable login rather than an opaque internal
		// UUID. Fall back to the internal user ID slot when the username slot
		// is empty (e.g. unauthenticated requests).
		userID := *slots.Username
		if userID == "" {
			userID = *slots.UserID
		}

		attrs := []attribute.KeyValue{
			attribute.String(attrHTTPRequestMethod, r.Method),
			attribute.String(attrURLPath, r.URL.Path),
			attribute.String(attrURLScheme, requestScheme(r)),
			attribute.Int(attrHTTPResponseStatusCode, rec.status),
			attribute.Int(attrHTTPResponseBodySize, rec.size),
			attribute.String(attrNetworkProtocolName, "http"),
			attribute.String(attrNetworkProtocolVersion, protocolVersion(r.Proto)),
			attribute.String(attrClientAddress, clientIP),
			attribute.String(attrServerAddress, serverHost),
			attribute.Float64(attrHTTPServerRequestDuration, dur.Seconds()),
			attribute.String(attrGHPBackend, backend),
		}
		if remotePort != "" && clientIP == remoteIP {
			if p, err := strconv.Atoi(remotePort); err == nil {
				attrs = append(attrs, attribute.Int(attrClientPort, p))
			}
		}
		if serverPort != "" {
			if p, err := strconv.Atoi(serverPort); err == nil {
				attrs = append(attrs, attribute.Int(attrServerPort, p))
			}
		}
		if q := r.URL.RawQuery; q != "" {
			attrs = append(attrs, attribute.String(attrURLQuery, q))
		}
		if ua := r.UserAgent(); ua != "" {
			attrs = append(attrs, attribute.String(attrUserAgentOriginal, ua))
		}
		if userID != "" {
			attrs = append(attrs, attribute.String(attrEndUserID, userID))
		}
		if *slots.CacheState != "" {
			attrs = append(attrs, attribute.String(attrGHPCacheState, *slots.CacheState))
		}
		if *slots.CacheRepo != "" {
			attrs = append(attrs, attribute.String(attrGHPCacheRepo, *slots.CacheRepo))
		}

		// Request and response headers, redacting sensitive values, captured
		// under the http.request.header.* / http.response.header.* conventions.
		attrs = append(attrs, headerAttrs(attrHTTPRequestHeaderPrefix, r.Header, redactRequestHeader)...)
		attrs = append(attrs, headerAttrs(attrHTTPResponseHeaderPrefix, rec.Header(), redactResponseHeader)...)

		severity := otellog.SeverityInfo
		if rec.status >= 500 {
			severity = otellog.SeverityError
		}

		var record otellog.Record
		record.SetTimestamp(start)
		record.SetBody(attribute.StringValue("handled request"))
		record.SetSeverity(severity)
		record.SetSeverityText(severity.String())
		record.AddAttributes(attrs...)
		aw.logger.Emit(r.Context(), record)

		metrics.HttpRequestDuration.WithLabelValues(backend, r.Method, statusStr).Observe(dur.Seconds())
		metrics.HttpRequestTotal.WithLabelValues(backend, r.Method, statusStr).Inc()
		metrics.ObserveClientRequest(clientIP, backend, *slots.TokenType, rec.status)
	})
}

// headerAttrs converts an http.Header into OTel log key-values using the
// http.{request,response}.header.<lowercase-name> convention. The redact
// function maps a lowercased header name to true when its values must be
// replaced with "REDACTED".
func headerAttrs(prefix string, h http.Header, redact func(string) bool) []attribute.KeyValue {
	if len(h) == 0 {
		return nil
	}
	out := make([]attribute.KeyValue, 0, len(h))
	for k, v := range h {
		name := strings.ToLower(k)
		var vals []attribute.Value
		if redact(name) {
			vals = []attribute.Value{attribute.StringValue("REDACTED")}
		} else {
			vals = make([]attribute.Value, 0, len(v))
			for _, vv := range v {
				vals = append(vals, attribute.StringValue(vv))
			}
		}
		out = append(out, attribute.Slice(prefix+name, vals...))
	}
	return out
}

func redactRequestHeader(name string) bool {
	switch name {
	case "authorization", "proxy-authorization", "cookie",
		"x-auth-token", "x-api-key", "x-access-token":
		return true
	default:
		return false
	}
}

func redactResponseHeader(name string) bool {
	return name == "set-cookie"
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if r.URL != nil && r.URL.Scheme != "" {
		return r.URL.Scheme
	}
	return "http"
}

// protocolVersion strips the "HTTP/" prefix from r.Proto, yielding e.g. "1.1".
func protocolVersion(proto string) string {
	return strings.TrimPrefix(proto, "HTTP/")
}

func splitRemoteAddr(addr string) (ip, port string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, ""
	}
	return host, port
}

// splitHostPortPreserve splits a Host header into host and port, returning the
// whole value as the host when no port is present.
func splitHostPortPreserve(host string) (h, port string) {
	if host == "" {
		return "", ""
	}
	hh, pp, err := net.SplitHostPort(host)
	if err != nil {
		return host, ""
	}
	return hh, pp
}
