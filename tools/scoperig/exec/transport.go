package exec

import (
	"context"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/goodtune/ghp/tools/scoperig/ghdebug"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

// TransportRetries is how many times a request that failed with a transport
// error (connection reset, HTTP/2 GOAWAY, EOF, including through a forward
// proxy) is re-sent when re-sending cannot duplicate a write. A transport
// error left after the retries is a rig error (ERROR, exit 2), never a FAIL
// or KNOWN-CHANGED: no product response was observed.
const TransportRetries = 2

// transportBackoff is the wait before retry n (1-based). A variable so
// tests can make it instant.
var transportBackoff = func(n int) time.Duration {
	return time.Duration(n) * 500 * time.Millisecond
}

// sleepCtx waits d or until ctx ends, and reports whether it waited fully.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// transportText matches the messages Go's HTTP client (and so gh) prints
// for a connection that failed below HTTP: no status was received.
var transportText = regexp.MustCompile(`(?i)connection reset by peer|server sent GOAWAY|http2: client connection lost|` +
	`unexpected EOF|": EOF\b|: EOF$|broken pipe|use of closed network connection|proxyconnect tcp|` +
	`connection refused|tls: handshake failure|TLS handshake timeout`)

// IsTransportError reports whether err is a transport failure (no HTTP
// response), as opposed to a response, a timeout of the whole request, or a
// configuration error such as an untrusted certificate.
func IsTransportError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, net.ErrClosed) {
		return true
	}
	// The HTTP/2 GOAWAY and connection-lost errors are unexported types.
	return transportText.MatchString(err.Error())
}

// ctxKeyIdempotent marks a request context as safe to re-send.
type ctxKeyIdempotent struct{}

// withIdempotent marks requests sent with ctx as idempotent even when the
// method is not (a read-only GraphQL POST).
func withIdempotent(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKeyIdempotent{}, true)
}

func isIdempotent(ctx context.Context, method string) bool {
	switch method {
	case "GET", "HEAD", "OPTIONS":
		return true
	}
	v, _ := ctx.Value(ctxKeyIdempotent{}).(bool)
	return v
}

// ghTransportFailure returns the first line of gh's stderr (debug log
// already stripped) that reports a transport error, or "".
func ghTransportFailure(stderr string) string {
	for _, l := range strings.Split(stderr, "\n") {
		if transportText.MatchString(l) {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

// ghExchangesIdempotent reports whether every request gh logged can be
// re-sent safely: GET/HEAD, or a GraphQL document with only query
// operations. A POST whose body could not be parsed as such is not.
func ghExchangesIdempotent(ex []ghdebug.Exchange) bool {
	for _, x := range ex {
		switch strings.ToUpper(x.Method) {
		case "GET", "HEAD", "OPTIONS":
			continue
		}
		if x.GraphQL == nil || !scenario.GraphQLReadOnly(x.GraphQL.Query) {
			return false
		}
	}
	return true
}
