package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"time"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/metrics"
)

// The values http.DefaultTransport uses, repeated here because the base
// transport is built from scratch (see newUpstreamTransport).
const (
	defaultMaxIdleConns          = 100
	defaultIdleConnTimeout       = 90 * time.Second
	defaultTLSHandshakeTimeout   = 10 * time.Second
	defaultExpectContinueTimeout = 1 * time.Second
	defaultDialTimeout           = 30 * time.Second
	defaultDialKeepAlive         = 30 * time.Second
)

// newUpstreamTransport returns a fresh http.Transport (no Proxy set) tuned
// by cfg. Every transport routingTransport builds starts here, so the
// upstream settings apply to each egress path while the per-proxy
// transports stay separate.
//
// It does not clone http.DefaultTransport: once the default transport has
// set up HTTP/2, a clone carries a TLS config whose ALPN list already offers
// "h2", and an HTTP/1.1-only transport would then fail with EOF when GitHub
// accepts h2. Protocols alone decides ALPN on a fresh transport.
func newUpstreamTransport(cfg config.UpstreamConfig) *http.Transport {
	t := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   defaultDialTimeout,
			KeepAlive: defaultDialKeepAlive,
		}).DialContext,
		MaxIdleConns:          defaultMaxIdleConns,
		IdleConnTimeout:       defaultIdleConnTimeout,
		TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
		ExpectContinueTimeout: defaultExpectContinueTimeout,
	}

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(cfg.HTTP2)
	t.Protocols = protocols

	if cfg.MaxIdleConnsPerHost > 0 {
		t.MaxIdleConnsPerHost = cfg.MaxIdleConnsPerHost
		if t.MaxIdleConns < cfg.MaxIdleConnsPerHost {
			t.MaxIdleConns = max(defaultMaxIdleConns, cfg.MaxIdleConnsPerHost)
		}
	}
	if cfg.MaxConnsPerHost > 0 {
		t.MaxConnsPerHost = cfg.MaxConnsPerHost
	}
	if cfg.IdleConnTimeout > 0 {
		t.IdleConnTimeout = cfg.IdleConnTimeout
	}
	if cfg.HTTP2 {
		t.HTTP2 = &http.HTTP2Config{
			MaxReadFrameSize:              cfg.HTTP2MaxReadFrameSize,
			MaxReceiveBufferPerConnection: cfg.HTTP2MaxReceiveBufferPerConnection,
			MaxReceiveBufferPerStream:     cfg.HTTP2MaxReceiveBufferPerStream,
		}
	}
	return t
}

// roundTripInstrumented sends req through next and records the upstream
// transport metrics: the connection used (opened or reused), time to the
// first response byte, and request and response body bytes. Labels are the
// negotiated protocol and the inbound vhost carried on the request context.
func roundTripInstrumented(next http.RoundTripper, req *http.Request) (*http.Response, error) {
	start := time.Now()
	vhost := metrics.VhostFromContext(req.Context())
	st := &upstreamTrace{}

	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			proto := connProtocol(info.Conn)
			st.protocol.Store(proto)
			result := metrics.UpstreamConnOpened
			if info.Reused {
				result = metrics.UpstreamConnReused
			}
			metrics.UpstreamConnectionsTotal.WithLabelValues(proto, vhost, result).Inc()
		},
		GotFirstResponseByte: func() {
			metrics.UpstreamFirstByteDuration.WithLabelValues(st.proto(), vhost).Observe(time.Since(start).Seconds())
		},
	}
	out := req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	// Only wrap a real body: the transport treats nil and http.NoBody as
	// "no body", and a wrapper would make it send an empty chunked body.
	if req.Body != nil && req.Body != http.NoBody {
		out.Body = &countingBody{ReadCloser: req.Body, add: func(n int) {
			metrics.UpstreamSentBytesTotal.WithLabelValues(st.proto(), vhost).Add(float64(n))
		}}
	}

	resp, err := next.RoundTrip(out)
	if err != nil {
		return nil, err
	}
	// A 101 response body is the upgraded connection (io.ReadWriteCloser),
	// which httputil.ReverseProxy needs unwrapped.
	if resp.Body != nil && resp.Body != http.NoBody && resp.StatusCode != http.StatusSwitchingProtocols {
		proto := metrics.UpstreamProtocolHTTP1
		if resp.ProtoMajor == 2 {
			proto = metrics.UpstreamProtocolH2
		}
		counter := metrics.UpstreamReceivedBytesTotal.WithLabelValues(proto, vhost)
		resp.Body = &countingBody{ReadCloser: resp.Body, add: func(n int) { counter.Add(float64(n)) }}
	}
	return resp, nil
}

// upstreamTrace carries the negotiated protocol from GotConn to the later
// metric callbacks of the same request.
type upstreamTrace struct {
	protocol atomic.Value // string
}

func (s *upstreamTrace) proto() string {
	if p, ok := s.protocol.Load().(string); ok {
		return p
	}
	return metrics.UpstreamProtocolUnknown
}

// connProtocol returns the protocol label for an upstream connection: the
// ALPN result for TLS (also through an HTTPS CONNECT tunnel), HTTP/1.1 for
// plain TCP.
func connProtocol(c net.Conn) string {
	if c == nil {
		return metrics.UpstreamProtocolUnknown
	}
	if tc, ok := c.(*tls.Conn); ok {
		return metrics.UpstreamProtocol(tc.ConnectionState().NegotiatedProtocol)
	}
	return metrics.UpstreamProtocolHTTP1
}

// countingBody reports the bytes read through it as they are read, so long
// transfers show up in rate() while they run.
type countingBody struct {
	io.ReadCloser
	add func(int)
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.add(n)
	}
	return n, err
}
