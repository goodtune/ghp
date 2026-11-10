package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestNewUpstreamTransport(t *testing.T) {
	stock := http.DefaultTransport.(*http.Transport)
	// Initialise the default transport's ALPN state the way any earlier
	// request through it would.
	_ = stock.Clone()
	tests := []struct {
		name         string
		cfg          config.UpstreamConfig
		wantHTTP2    bool
		wantIdle     int
		wantMaxIdle  int
		wantMaxConns int
		wantTimeout  time.Duration
		wantH2Config *http.HTTP2Config
	}{
		{
			name:        "zero values keep Go defaults, HTTP/1.1 only",
			cfg:         config.UpstreamConfig{},
			wantIdle:    0,
			wantMaxIdle: stock.MaxIdleConns,
			wantTimeout: stock.IdleConnTimeout,
		},
		{
			name:        "shipped defaults",
			cfg:         config.Defaults().Upstream,
			wantIdle:    32,
			wantMaxIdle: stock.MaxIdleConns,
			wantTimeout: 90 * time.Second,
		},
		{
			name:         "HTTP/2 tuned",
			cfg:          config.UpstreamConfig{HTTP2: true, MaxIdleConnsPerHost: 200, MaxConnsPerHost: 300, IdleConnTimeout: time.Minute, HTTP2MaxReadFrameSize: 1 << 16, HTTP2MaxReceiveBufferPerConnection: 1 << 26, HTTP2MaxReceiveBufferPerStream: 1 << 24},
			wantHTTP2:    true,
			wantIdle:     200,
			wantMaxIdle:  200,
			wantMaxConns: 300,
			wantTimeout:  time.Minute,
			wantH2Config: &http.HTTP2Config{MaxReadFrameSize: 1 << 16, MaxReceiveBufferPerConnection: 1 << 26, MaxReceiveBufferPerStream: 1 << 24},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := newUpstreamTransport(tt.cfg)
			if tr == stock {
				t.Fatal("newUpstreamTransport returned http.DefaultTransport itself")
			}
			// Regression: cloning http.DefaultTransport copied a TLS config
			// already advertising "h2", so with HTTP/2 off GitHub chose h2
			// and the HTTP/1.1-only transport failed with EOF.
			if !tt.wantHTTP2 && tr.TLSClientConfig != nil && slices.Contains(tr.TLSClientConfig.NextProtos, "h2") {
				t.Errorf("HTTP/2 disabled but TLS NextProtos = %v", tr.TLSClientConfig.NextProtos)
			}
			if tr.Proxy != nil {
				t.Error("base transport must not carry a Proxy func")
			}
			if tr.Protocols == nil || !tr.Protocols.HTTP1() || tr.Protocols.HTTP2() != tt.wantHTTP2 {
				t.Errorf("Protocols = %v, want HTTP1 and HTTP2=%v", tr.Protocols, tt.wantHTTP2)
			}
			if tr.MaxIdleConnsPerHost != tt.wantIdle {
				t.Errorf("MaxIdleConnsPerHost = %d, want %d", tr.MaxIdleConnsPerHost, tt.wantIdle)
			}
			if tr.MaxIdleConns != tt.wantMaxIdle {
				t.Errorf("MaxIdleConns = %d, want %d", tr.MaxIdleConns, tt.wantMaxIdle)
			}
			if tr.MaxConnsPerHost != tt.wantMaxConns {
				t.Errorf("MaxConnsPerHost = %d, want %d", tr.MaxConnsPerHost, tt.wantMaxConns)
			}
			if tr.IdleConnTimeout != tt.wantTimeout {
				t.Errorf("IdleConnTimeout = %v, want %v", tr.IdleConnTimeout, tt.wantTimeout)
			}
			// With HTTP/2 off the HTTP2 block is unused; only check it when set.
			if tt.wantH2Config != nil && (tr.HTTP2 == nil || tr.HTTP2.MaxReadFrameSize != tt.wantH2Config.MaxReadFrameSize ||
				tr.HTTP2.MaxReceiveBufferPerConnection != tt.wantH2Config.MaxReceiveBufferPerConnection ||
				tr.HTTP2.MaxReceiveBufferPerStream != tt.wantH2Config.MaxReceiveBufferPerStream) {
				t.Errorf("HTTP2 config = %+v, want %+v", tr.HTTP2, tt.wantH2Config)
			}
		})
	}
}

// TestRoutingTransport_UpstreamProtocol checks that the http2 switch decides
// the negotiated protocol against an HTTP/2-capable server, for the direct
// transport and for a transport built for a selected proxy.
func TestRoutingTransport_UpstreamProtocol(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	roots := srv.Client().Transport.(*http.Transport).TLSClientConfig

	for _, tt := range []struct {
		http2 bool
		want  string
	}{
		{http2: false, want: "HTTP/1.1"},
		{http2: true, want: "HTTP/2.0"},
	} {
		t.Run(tt.want, func(t *testing.T) {
			rt := newRoutingTransport(func(*http.Request) (*url.URL, error) { return nil, nil }, config.UpstreamConfig{HTTP2: tt.http2})
			base := rt.newTransport
			rt.newTransport = func() *http.Transport {
				tr := base()
				// Add only the test CA; keep whatever ALPN the transport
				// itself chose so a stray "h2" would be caught.
				if tr.TLSClientConfig == nil {
					tr.TLSClientConfig = &tls.Config{}
				}
				tr.TLSClientConfig.RootCAs = roots.RootCAs
				return tr
			}
			defer rt.CloseIdleConnections()
			resp, err := (&http.Client{Transport: rt}).Get(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if string(body) != tt.want {
				t.Errorf("served over %s, want %s", body, tt.want)
			}
			// A proxied egress path gets its own transport with the same tuning.
			p, _ := url.Parse("http://egress.invalid:3128")
			if got := rt.transportFor(p).Protocols.HTTP2(); got != tt.http2 {
				t.Errorf("proxied transport HTTP2 = %v, want %v", got, tt.http2)
			}
		})
	}
}

// TestRoutingTransport_UpstreamMetrics checks the bytes, connection and
// first-byte metrics recorded for each upstream request, per protocol.
func TestRoutingTransport_UpstreamMetrics(t *testing.T) {
	const respSize = 1000
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write(make([]byte, respSize))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	roots := srv.Client().Transport.(*http.Transport).TLSClientConfig

	for _, tt := range []struct {
		http2 bool
		proto string
	}{
		{http2: false, proto: metrics.UpstreamProtocolHTTP1},
		{http2: true, proto: metrics.UpstreamProtocolH2},
	} {
		t.Run(tt.proto, func(t *testing.T) {
			rt := newRoutingTransport(func(*http.Request) (*url.URL, error) { return nil, nil }, config.UpstreamConfig{HTTP2: tt.http2, MaxIdleConnsPerHost: 4})
			base := rt.newTransport
			rt.newTransport = func() *http.Transport {
				tr := base()
				tr.TLSClientConfig = &tls.Config{RootCAs: roots.RootCAs}
				return tr
			}
			defer rt.CloseIdleConnections()

			vhost := metrics.VhostManagement
			opened := metrics.UpstreamConnectionsTotal.WithLabelValues(tt.proto, vhost, metrics.UpstreamConnOpened)
			reused := metrics.UpstreamConnectionsTotal.WithLabelValues(tt.proto, vhost, metrics.UpstreamConnReused)
			sent := metrics.UpstreamSentBytesTotal.WithLabelValues(tt.proto, vhost)
			recv := metrics.UpstreamReceivedBytesTotal.WithLabelValues(tt.proto, vhost)
			firstByte := func() uint64 {
				var m dto.Metric
				if err := metrics.UpstreamFirstByteDuration.WithLabelValues(tt.proto, vhost).(prometheus.Metric).Write(&m); err != nil {
					t.Fatal(err)
				}
				return m.GetHistogram().GetSampleCount()
			}
			o0, r0, s0, b0, f0 := counterValue(t, opened), counterValue(t, reused), counterValue(t, sent), counterValue(t, recv), firstByte()

			ctx := metrics.WithVhost(context.Background(), vhost)
			client := &http.Client{Transport: rt}
			for i := 0; i < 2; i++ {
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader("hello"))
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				if got := resp.Proto; (got == "HTTP/2.0") != tt.http2 {
					t.Fatalf("served over %s", got)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}

			if got := counterValue(t, opened) - o0; got != 1 {
				t.Errorf("connections opened grew by %v, want 1", got)
			}
			if got := counterValue(t, reused) - r0; got != 1 {
				t.Errorf("connections reused grew by %v, want 1", got)
			}
			if got := counterValue(t, sent) - s0; got != 10 {
				t.Errorf("sent bytes grew by %v, want 10", got)
			}
			if got := counterValue(t, recv) - b0; got != 2*respSize {
				t.Errorf("received bytes grew by %v, want %d", got, 2*respSize)
			}
			if got := firstByte() - f0; got != 2 {
				t.Errorf("first byte samples grew by %d, want 2", got)
			}
		})
	}
}

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

func TestConnProtocol(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tcp, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()

	for _, tt := range []struct {
		name string
		conn net.Conn
		want string
	}{
		{name: "nil", conn: nil, want: metrics.UpstreamProtocolUnknown},
		{name: "plain tcp", conn: tcp, want: metrics.UpstreamProtocolHTTP1},
		{name: "other conn", conn: p1, want: metrics.UpstreamProtocolUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := connProtocol(tt.conn); got != tt.want {
				t.Errorf("connProtocol() = %q, want %q", got, tt.want)
			}
		})
	}
}

// A transport retry resends the body from GetBody; those bytes count too.
func TestRoundTripInstrumented_CountsGetBodyResend(t *testing.T) {
	vhost := metrics.VhostManagement
	sent := metrics.UpstreamSentBytesTotal.WithLabelValues(metrics.UpstreamProtocolUnknown, vhost)
	s0 := counterValue(t, sent)

	ctx := metrics.WithVhost(context.Background(), vhost)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.invalid/", strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.GetBody == nil {
			t.Fatal("GetBody dropped")
		}
		b, err := r.GetBody()
		if err != nil {
			return nil, err
		}
		_, _ = io.Copy(io.Discard, b)
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	if _, err := roundTripInstrumented(next, req); err != nil {
		t.Fatal(err)
	}
	if got := counterValue(t, sent) - s0; got != 10 {
		t.Errorf("sent bytes grew by %v, want 10", got)
	}
}
