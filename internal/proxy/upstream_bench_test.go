package proxy

// Upstream throughput benchmark for the routing transport.
//
// It measures bulk download throughput through routingTransport against a
// local TLS server, through a userspace "WAN link" relay that adds one-way
// delay, bounds the bytes in flight per connection and direction (a model of
// the TCP window), and can inject loss stalls (a chunk held for an RTO, with
// every later chunk on that connection queued behind it, which models TCP
// head-of-line blocking). No root and no tc/dnctl is needed.
//
// It is a benchmark, not a unit test, and is not built into the binary:
//
//	go test ./internal/proxy -run '^$' -bench BenchmarkUpstreamThroughput -benchtime 1x
//
// Tunables (environment):
//
//	GHP_BENCH_RTTS        comma-separated RTTs (default "0s,50ms,200ms")
//	GHP_BENCH_STREAMS     comma-separated concurrency (default "1,4,8")
//	GHP_BENCH_MB          MiB downloaded per stream (default 32)
//	GHP_BENCH_TCP_WINDOW  modelled per-connection TCP window in bytes (default 4194304)
//	GHP_BENCH_LOSS        probability a relay chunk is stalled for one RTO (default 0)
//	GHP_BENCH_PROFILES    comma-separated transport profiles (default all)

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/config"
)

// wanRelay forwards TCP connections to target, adding delay, a bounded
// in-flight window and optional loss stalls in each direction.
type wanRelay struct {
	ln       net.Listener
	target   string
	oneWay   time.Duration
	window   int
	loss     float64
	rto      time.Duration
	accepted atomic.Int64
	wg       sync.WaitGroup
}

func newWANRelay(tb testing.TB, target string, rtt time.Duration, window int, loss float64) *wanRelay {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("relay listen: %v", err)
	}
	rto := 200 * time.Millisecond
	if 2*rtt > rto {
		rto = 2 * rtt
	}
	r := &wanRelay{ln: ln, target: target, oneWay: rtt / 2, window: window, loss: loss, rto: rto}
	r.wg.Add(1)
	go r.serve()
	tb.Cleanup(func() {
		_ = ln.Close()
		r.wg.Wait()
	})
	return r
}

func (r *wanRelay) addr() string { return r.ln.Addr().String() }

func (r *wanRelay) serve() {
	defer r.wg.Done()
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		r.accepted.Add(1)
		u, err := net.Dial("tcp", r.target)
		if err != nil {
			_ = c.Close()
			continue
		}
		go r.pipe(c, u)
		go r.pipe(u, c)
	}
}

type relayChunk struct {
	data []byte
	due  time.Time
}

// pipe copies src to dst. Reads block once window bytes are in flight, so
// the sender sees back-pressure after one window per RTT, as with TCP.
func (r *wanRelay) pipe(src, dst net.Conn) {
	var (
		mu       sync.Mutex
		cond     = sync.NewCond(&mu)
		inflight int
		queue    = make(chan relayChunk, 1<<16)
	)
	go func() {
		defer func() { _ = dst.Close() }()
		for ch := range queue {
			if d := time.Until(ch.due); d > 0 {
				time.Sleep(d)
			}
			_, err := dst.Write(ch.data)
			mu.Lock()
			inflight -= len(ch.data)
			cond.Signal()
			mu.Unlock()
			if err != nil {
				for range queue {
				}
				return
			}
		}
	}()
	defer close(queue)
	defer func() { _ = src.Close() }()
	for {
		buf := make([]byte, 64<<10)
		n, err := src.Read(buf)
		if n > 0 {
			mu.Lock()
			for inflight > 0 && inflight+n > r.window {
				cond.Wait()
			}
			inflight += n
			mu.Unlock()
			due := time.Now().Add(r.oneWay)
			if r.loss > 0 && rand.Float64() < r.loss {
				due = due.Add(r.rto)
			}
			queue <- relayChunk{data: buf[:n], due: due}
		}
		if err != nil {
			return
		}
	}
}

// benchProfile is a transport configuration under test.
type benchProfile struct {
	name string
	cfg  config.UpstreamConfig
}

func benchProfiles() []benchProfile {
	return []benchProfile{
		// Go standard library defaults, HTTP/2 on: the pre-change transport.
		{name: "h2-stock", cfg: config.UpstreamConfig{HTTP2: true}},
		// HTTP/2 with 16 MiB per-stream and 64 MiB per-connection windows.
		{name: "h2-win16m", cfg: config.UpstreamConfig{HTTP2: true, HTTP2MaxReceiveBufferPerStream: 16 << 20, HTTP2MaxReceiveBufferPerConnection: 64 << 20}},
		// HTTP/2 with 16 KiB max read frames (the RFC minimum).
		{name: "h2-frame16k", cfg: config.UpstreamConfig{HTTP2: true, HTTP2MaxReadFrameSize: 16 << 10}},
		// HTTP/2 off, Go default idle pool (2 per host): GODEBUG=http2client=0.
		{name: "h1-stock", cfg: config.UpstreamConfig{}},
		// HTTP/2 off, 32 idle connections per host.
		{name: "h1-idle32", cfg: config.UpstreamConfig{MaxIdleConnsPerHost: 32}},
		// Whatever config.Defaults() ships.
		{name: "shipped-defaults", cfg: config.Defaults().Upstream},
	}
}

func benchEnvList(name, def string) []string {
	v := os.Getenv(name)
	if v == "" {
		v = def
	}
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func benchEnvInt(tb testing.TB, name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		tb.Fatalf("%s: %v", name, err)
	}
	return n
}

// newBenchRoutingTransport builds a direct routingTransport whose transports
// trust the test server and apply the profile.
func newBenchRoutingTransport(tb testing.TB, roots *tls.Config, p benchProfile) *routingTransport {
	tb.Helper()
	rt := newRoutingTransport(func(*http.Request) (*url.URL, error) { return nil, nil }, p.cfg)
	base := rt.newTransport
	rt.newTransport = func() *http.Transport {
		t := base()
		if t.TLSClientConfig == nil {
			t.TLSClientConfig = &tls.Config{}
		}
		t.TLSClientConfig.RootCAs = roots.RootCAs
		return t
	}
	return rt
}

func BenchmarkUpstreamThroughput(b *testing.B) {
	perStream := int64(benchEnvInt(b, "GHP_BENCH_MB", 32)) << 20
	window := benchEnvInt(b, "GHP_BENCH_TCP_WINDOW", 4<<20)
	loss, err := strconv.ParseFloat(firstNonEmpty(os.Getenv("GHP_BENCH_LOSS"), "0"), 64)
	if err != nil {
		b.Fatalf("GHP_BENCH_LOSS: %v", err)
	}
	wanted := map[string]bool{}
	for _, s := range benchEnvList("GHP_BENCH_PROFILES", "") {
		wanted[s] = true
	}

	chunk := make([]byte, 256<<10)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/warm" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(perStream, 10))
		for left := perStream; left > 0; {
			n := int64(len(chunk))
			if left < n {
				n = left
			}
			if _, err := w.Write(chunk[:n]); err != nil {
				return
			}
			left -= n
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	b.Cleanup(srv.Close)
	roots := srv.Client().Transport.(*http.Transport).TLSClientConfig

	for _, rttS := range benchEnvList("GHP_BENCH_RTTS", "0s,50ms,200ms") {
		rtt, err := time.ParseDuration(rttS)
		if err != nil {
			b.Fatalf("GHP_BENCH_RTTS: %v", err)
		}
		for _, p := range benchProfiles() {
			if len(wanted) > 0 && !wanted[p.name] {
				continue
			}
			for _, sS := range benchEnvList("GHP_BENCH_STREAMS", "1,4,8") {
				streams, err := strconv.Atoi(sS)
				if err != nil {
					b.Fatalf("GHP_BENCH_STREAMS: %v", err)
				}
				name := fmt.Sprintf("rtt=%s/loss=%g/%s/streams=%d", rtt, loss, p.name, streams)
				b.Run(name, func(b *testing.B) {
					relay := newWANRelay(b, srv.Listener.Addr().String(), rtt, window, loss)
					rt := newBenchRoutingTransport(b, roots, p)
					b.Cleanup(rt.CloseIdleConnections)
					client := &http.Client{Transport: rt}
					target := "https://" + relay.addr() + "/blob"
					// Warm the pool with one connection first: ghp is a
					// long-running service, so steady state is a pooled
					// connection, not a cold-start dial race.
					warm, err := client.Get("https://" + relay.addr() + "/warm")
					if err != nil {
						b.Fatalf("warm: %v", err)
					}
					_, _ = io.Copy(io.Discard, warm.Body)
					_ = warm.Body.Close()
					b.SetBytes(perStream * int64(streams))
					b.ResetTimer()
					start := time.Now()
					for i := 0; i < b.N; i++ {
						benchDownload(b, client, target, streams)
					}
					elapsed := time.Since(start)
					b.StopTimer()
					bits := float64(perStream*int64(streams)*int64(b.N)) * 8
					b.ReportMetric(bits/elapsed.Seconds()/1e6, "Mbit/s")
					b.ReportMetric(float64(relay.accepted.Load()), "conns")
				})
			}
		}
	}
}

func benchDownload(b *testing.B, client *http.Client, target string, streams int) {
	var wg sync.WaitGroup
	errs := make(chan error, streams)
	for s := 0; s < streams; s++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
			if err != nil {
				errs <- err
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		b.Fatalf("download: %v", err)
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
