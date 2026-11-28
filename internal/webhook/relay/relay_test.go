package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/webhook"
)

const testSecret = "relay-secret"

// fakeServer imitates a ghp server in client-ack mode: the probe answers
// 400, the stream sends a session event and then one delivery at a time,
// the next only after the previous one is acknowledged. An unacknowledged
// delivery is sent again on the next connection, as a durable redelivers.
type fakeServer struct {
	t       *testing.T
	envs    []*webhook.Envelope
	session string

	// oldServer makes the ack path unknown (as on servers before client
	// ack); probeStatus overrides the probe answers in turn.
	oldServer   bool
	oldStatus   int
	probeStatus []int
	// streamStatus answers the first stream connections with these
	// statuses instead of a stream.
	streamStatus []int
	// silentConns stream connections send the session and then nothing.
	silentConns int
	// ackStatus answers the real (non-probe) ack calls in turn: 0 accept,
	// -1 drop the connection unrecorded, -2 server ack_error (redeliver),
	// -3 record the ack but drop the answer, other values that status.
	ackStatus []int
	// maxPayload is reported by /api/webhooks/status (maxPayloadLater
	// after the first status call, when set); statusFail fails the first
	// status calls with 503.
	maxPayload      int64
	maxPayloadLater int64
	statusFail      int
	statusCalls     int
	// noCapHeader drops the client-ack capability header (a proxy or WAF
	// answering 400 in front of an older server).
	noCapHeader bool
	// evictAfter sends an evicted event on the first stream after this
	// many deliveries have been acknowledged, then closes it.
	evictAfter int
	// oldAfterFirst turns the fake into an older server (no client ack)
	// once the first stream connection has acknowledged one delivery and
	// closed. lostToOld counts deliveries such a server would have
	// acknowledged on flush.
	oldAfterFirst bool
	lostToOld     int
	// streamNoHeader omits the capability header on stream responses.
	streamNoHeader bool
	// garbageFirst sends this undecodable event on the first stream after
	// the session event (and then holds the stream open).
	garbageFirst string

	mu        sync.Mutex
	acks      []uint64
	ackCalls  int
	probes    int
	queries   []string
	streamReq int
	next      int
	ackedCh   chan uint64
}

func newFakeServer(t *testing.T, envs ...*webhook.Envelope) *fakeServer {
	return &fakeServer{t: t, envs: envs, session: strings.Repeat("5e", 32), ackedCh: make(chan uint64, 16)}
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if got := r.Header.Get("Authorization"); got != "Bearer ghpr_test" {
		f.t.Errorf("%s %s: Authorization = %q", r.Method, r.URL.Path, got)
	}
	switch r.URL.Path {
	case "/api/webhooks/status":
		f.mu.Lock()
		f.statusCalls++
		c := f.statusCalls
		f.mu.Unlock()
		if c <= f.statusFail {
			http.Error(w, `{"message":"busy"}`, http.StatusServiceUnavailable)
			return
		}
		mp := f.maxPayload
		if c > f.statusFail+1 && f.maxPayloadLater > 0 {
			mp = f.maxPayloadLater
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"enabled":true,"max_payload_bytes":%d}`, mp)
	case "/api/webhooks/stream":
		f.serveStream(w, r)
	case "/api/webhooks/stream/ack":
		f.serveAck(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeServer) serveStream(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.queries = append(f.queries, r.URL.RawQuery)
	f.streamReq++
	n := f.streamReq
	// Acks go to the newest connection, as a server session is per stream.
	acked := make(chan uint64, 16)
	f.ackedCh = acked
	f.mu.Unlock()
	if f.oldServer {
		// An older server: no session, and every delivery written counts
		// as acknowledged.
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f.mu.Lock()
		for ; f.next < len(f.envs); f.next++ {
			data, _ := json.Marshal(f.envs[f.next])
			fmt.Fprintf(w, "id: %d\nevent: issues\ndata: %s\n\n", f.envs[f.next].Sequence, data)
			f.lostToOld++
		}
		f.mu.Unlock()
		return
	}
	if n <= len(f.streamStatus) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.streamStatus[n-1])
		fmt.Fprint(w, `{"message":"scripted"}`)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	if !f.streamNoHeader {
		w.Header().Set(webhook.ClientAckHeader, "1")
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "retry: 3000\n\n: connected\n\n")
	fmt.Fprintf(w, "event: session\ndata: {\"session\":%q}\n\n", f.session)
	w.(http.Flusher).Flush()
	if n == len(f.streamStatus)+1 && f.garbageFirst != "" {
		fmt.Fprint(w, f.garbageFirst)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		return
	}
	if n-len(f.streamStatus) <= f.silentConns {
		<-r.Context().Done()
		return
	}
	for {
		f.mu.Lock()
		if f.evictAfter > 0 && n == 1 && f.next >= f.evictAfter {
			f.mu.Unlock()
			fmt.Fprint(w, "event: evicted\ndata: {\"durable\":\"relay-test\",\"by\":\"bob\"}\n\n")
			w.(http.Flusher).Flush()
			return
		}
		if f.next >= len(f.envs) {
			f.mu.Unlock()
			<-r.Context().Done()
			return
		}
		env := f.envs[f.next]
		f.mu.Unlock()
		data, _ := json.Marshal(env)
		fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", env.Sequence, env.Event, data)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			return
		case seq := <-acked:
			if seq == 0 {
				continue // redelivery of the same message
			}
			if seq != env.Sequence {
				f.t.Errorf("ack for %d while %d pending", seq, env.Sequence)
			}
			f.mu.Lock()
			f.next++
			flip := f.oldAfterFirst && n == 1
			if flip {
				f.oldServer = true
			}
			f.mu.Unlock()
			if flip {
				return // the server goes away and comes back older
			}
		}
	}
}

func (f *fakeServer) serveAck(w http.ResponseWriter, r *http.Request) {
	if !f.oldServer && !f.noCapHeader {
		w.Header().Set(webhook.ClientAckHeader, "1")
	}
	if f.oldServer {
		code := f.oldStatus
		if code == 0 {
			code = http.StatusNotFound
		}
		http.Error(w, "404 page not found", code)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Session  string `json:"session"`
		Sequence uint64 `json:"sequence"`
	}
	_ = json.Unmarshal(body, &req)
	w.Header().Set("Content-Type", "application/json")
	if req.Session == "" {
		f.mu.Lock()
		f.probes++
		p := f.probes
		f.mu.Unlock()
		code := http.StatusBadRequest
		if p <= len(f.probeStatus) {
			code = f.probeStatus[p-1]
		}
		w.WriteHeader(code)
		fmt.Fprint(w, `{"message":"invalid JSON body"}`)
		return
	}
	if req.Session != f.session {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	f.mu.Lock()
	f.ackCalls++
	c := f.ackCalls
	f.mu.Unlock()
	if c <= len(f.ackStatus) {
		switch st := f.ackStatus[c-1]; {
		case st == -2:
			// The server could not record the ack, released the stream and
			// redelivers.
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprint(w, `{"message":"Acknowledgement failed; the delivery will be redelivered","code":"ack_error"}`)
			f.mu.Lock()
			ch := f.ackedCh
			f.mu.Unlock()
			ch <- 0
			return
		case st == -1:
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		case st == 4091 || st == 4092:
			code := map[int]string{4091: "acked", 4092: "released"}[st]
			w.WriteHeader(http.StatusConflict)
			fmt.Fprintf(w, `{"message":"Sequence is not the stream's pending delivery","code":%q}`, code)
			if st == 4092 {
				f.mu.Lock()
				ch := f.ackedCh
				f.mu.Unlock()
				ch <- 0 // released: redelivered on the stream
			}
			return
		case st == -3:
			// Recorded, but the answer is lost.
			f.mu.Lock()
			f.acks = append(f.acks, req.Sequence)
			ch := f.ackedCh
			f.mu.Unlock()
			ch <- req.Sequence
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		case st != 0:
			w.WriteHeader(st)
			fmt.Fprint(w, `{"message":"scripted ack failure"}`)
			return
		}
	}
	f.mu.Lock()
	f.acks = append(f.acks, req.Sequence)
	ch := f.ackedCh
	f.mu.Unlock()
	ch <- req.Sequence
	fmt.Fprint(w, `{"message":"acknowledged"}`)
}

func (f *fakeServer) ackedSeqs() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint64(nil), f.acks...)
}

func (f *fakeServer) streamConnects() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.streamReq
}

func signedEnvelope(seq uint64, delivery, body string) *webhook.Envelope {
	env := &webhook.Envelope{
		Subject:             "github.webhooks.app.issues.opened.o.r",
		Sequence:            seq,
		Delivery:            delivery,
		Event:               "issues",
		Action:              "opened",
		HookID:              "4242",
		TargetType:          "integration",
		TargetID:            "777",
		Signature256:        webhook.Sign([]byte(testSecret), []byte(body)),
		SignatureSHA1:       "sha1=0123456789abcdef0123456789abcdef01234567",
		UserAgent:           "GitHub-Hookshot/1a2b3c",
		OriginalContentType: "application/json",
	}
	if body != "" {
		env.PayloadBase64 = []byte(body)
	}
	return env
}

type targetHit struct {
	header http.Header
	body   []byte
	path   string
}

// target verifies X-Hub-Signature-256 like a GitHub webhook receiver and
// answers with statuses in turn (the last one repeats).
type target struct {
	mu       sync.Mutex
	hits     []targetHit
	statuses []int
	redirect string
}

func (rt *target) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	rt.mu.Lock()
	rt.hits = append(rt.hits, targetHit{header: r.Header.Clone(), body: body, path: r.URL.Path})
	i := min(len(rt.hits)-1, len(rt.statuses)-1)
	status := rt.statuses[i]
	rt.mu.Unlock()
	if !webhook.VerifySignature([]byte(testSecret), body, r.Header.Get("X-Hub-Signature-256")) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	if status >= 300 && status < 400 {
		w.Header().Set("Location", rt.redirect)
	}
	w.WriteHeader(status)
}

func (rt *target) snapshot() []targetHit {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return append([]targetHit(nil), rt.hits...)
}

func fastOptions(serverURL, targetURL string) Options {
	return Options{
		ServerURL:      serverURL,
		Token:          "ghpr_test",
		Target:         targetURL,
		Durable:        "relay-test",
		From:           "all",
		Timeout:        2 * time.Second,
		Backoff:        10 * time.Millisecond,
		MaxDelay:       40 * time.Millisecond,
		ReconnectDelay: 10 * time.Millisecond,
		AckBackoff:     5 * time.Millisecond,
		AckTimeout:     2 * time.Second,
	}
}

// run starts the fake ghp server and target and runs the relay.
func run(t *testing.T, fake *fakeServer, tg *target, tweak func(*Options)) (string, error) {
	t.Helper()
	ghp := httptest.NewServer(fake)
	t.Cleanup(ghp.Close)
	tsrv := httptest.NewServer(tg)
	t.Cleanup(tsrv.Close)
	opts := fastOptions(ghp.URL, tsrv.URL+"/hook")
	if tweak != nil {
		tweak(&opts)
	}
	errOut := &syncBuffer{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err := Run(ctx, opts, errOut)
	if ctx.Err() != nil {
		t.Fatalf("relay did not finish in time\n%s", errOut.String())
	}
	return errOut.String(), err
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestRun_EndToEnd(t *testing.T) {
	body1 := "{ \"action\" : \"opened\",\n  \"z\": 1,  \"a\": [ ] }"
	body4 := `{"action":"closed",   "issue":{"number":7}}`
	noSig := signedEnvelope(2, "d-old", `{"action":"x"}`)
	noSig.Signature256 = ""
	form := signedEnvelope(3, "d-form", `{"action":"y"}`)
	form.OriginalContentType = "application/x-www-form-urlencoded"
	fake := newFakeServer(t, signedEnvelope(1, "d-one", body1), noSig, form, signedEnvelope(4, "d-four", body4))
	tg := &target{statuses: []int{http.StatusInternalServerError, http.StatusOK}}

	log, err := run(t, fake, tg, func(o *Options) {
		o.Filter = "github.webhooks.*.issues.>"
		o.Count = 2
	})
	if err != nil {
		t.Fatalf("relay: %v\n%s", err, log)
	}
	if got := fake.ackedSeqs(); fmt.Sprint(got) != "[1 2 3 4]" {
		t.Errorf("acks = %v, want [1 2 3 4] (each once)", got)
	}
	q := fake.queries[0]
	for _, want := range []string{"ack=client", "raw=1", "durable=relay-test", "from=all", "filter=github.webhooks.%2A.issues.%3E"} {
		if !strings.Contains(q, want) {
			t.Errorf("stream query %q missing %q", q, want)
		}
	}
	hits := tg.snapshot()
	if len(hits) != 3 {
		t.Fatalf("target hits = %d, want 3 (500 then 200 for seq 1, 200 for seq 4)", len(hits))
	}
	for i, want := range []string{body1, body1, body4} {
		if string(hits[i].body) != want {
			t.Errorf("hit %d body = %q, want %q", i, hits[i].body, want)
		}
		if hits[i].path != "/hook" {
			t.Errorf("hit %d path = %q", i, hits[i].path)
		}
	}
	h := hits[2].header
	wantHeaders := map[string]string{
		"X-GitHub-Event":                         "issues",
		"X-GitHub-Delivery":                      "d-four",
		"X-GitHub-Hook-ID":                       "4242",
		"X-GitHub-Hook-Installation-Target-Type": "integration",
		"X-GitHub-Hook-Installation-Target-ID":   "777",
		"X-Hub-Signature-256":                    webhook.Sign([]byte(testSecret), []byte(body4)),
		"X-Hub-Signature":                        "sha1=0123456789abcdef0123456789abcdef01234567",
		"Content-Type":                           "application/json",
		"User-Agent":                             "GitHub-Hookshot/1a2b3c",
	}
	for k, v := range wantHeaders {
		if got := h.Get(k); got != v {
			t.Errorf("target header %s = %q, want %q", k, got, v)
		}
	}
	for _, k := range []string{"Authorization", "Cookie", "Last-Event-Id"} {
		if v := h.Get(k); v != "" {
			t.Errorf("target received %s: %q", k, v)
		}
	}
	for _, want := range []string{
		"retrying seq=1 delivery=d-one: status 500",
		"relayed seq=1 delivery=d-one",
		"skipped seq=2 delivery=d-old",
		"no stored signature",
		"skipped seq=3 delivery=d-form",
		"form-encoded",
		"relayed seq=4 delivery=d-four",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("stderr missing %q:\n%s", want, log)
		}
	}
}

func TestRun_RedirectNotFollowed(t *testing.T) {
	var redirected atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer other.Close()
	fake := newFakeServer(t, signedEnvelope(1, "d-r", `{"a":1}`))
	tg := &target{statuses: []int{http.StatusFound, http.StatusNoContent}, redirect: other.URL + "/elsewhere"}
	log, err := run(t, fake, tg, func(o *Options) { o.Count = 1 })
	if err != nil {
		t.Fatal(err)
	}
	if redirected.Load() != 0 {
		t.Errorf("redirect was followed %d times", redirected.Load())
	}
	if n := len(tg.snapshot()); n != 2 {
		t.Errorf("target hits = %d, want 2", n)
	}
	if got := fake.ackedSeqs(); fmt.Sprint(got) != "[1]" {
		t.Errorf("acks = %v", got)
	}
	if !strings.Contains(log, "status 302") {
		t.Errorf("expected 302 retry line:\n%s", log)
	}
}

func TestRun_InterruptLeavesDeliveryUnacked(t *testing.T) {
	fake := newFakeServer(t, signedEnvelope(1, "d-stuck", `{"a":1}`))
	ghp := httptest.NewServer(fake)
	defer ghp.Close()
	tg := &target{statuses: []int{http.StatusServiceUnavailable}}
	tsrv := httptest.NewServer(tg)
	defer tsrv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, fastOptions(ghp.URL, tsrv.URL), io.Discard) }()
	deadline := time.Now().Add(10 * time.Second)
	for len(tg.snapshot()) < 3 {
		if time.Now().After(deadline) {
			t.Fatal("target not retried")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("interrupted relay returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not stop on interrupt")
	}
	if got := fake.ackedSeqs(); len(got) != 0 {
		t.Errorf("acks = %v, want none", got)
	}
}

// Finding 1: a failed ack must not stall the relay.
func TestRun_AckFailures(t *testing.T) {
	tests := []struct {
		name      string
		ackStatus []int
		// wantHits for seq 1: a recovered ack relays once; an ack that
		// fails for good drops the stream and seq 1 is relayed again.
		wantHits    int
		wantStreams int
		wantLog     string
	}{
		{name: "transport error then success is retried", ackStatus: []int{-1}, wantHits: 2, wantStreams: 1},
		{name: "5xx then success is retried", ackStatus: []int{http.StatusBadGateway, http.StatusServiceUnavailable}, wantHits: 2, wantStreams: 1},
		{name: "persistent 5xx reconnects for redelivery", ackStatus: []int{500, 500, 500, 500}, wantHits: 3, wantStreams: 2, wantLog: "failed: server returned 500: scripted ack failure; reconnecting"},
		{name: "persistent transport error reconnects", ackStatus: []int{-1, -1, -1, -1}, wantHits: 3, wantStreams: 2, wantLog: "; reconnecting"},
		{name: "session gone reconnects", ackStatus: []int{http.StatusNotFound}, wantHits: 3, wantStreams: 2, wantLog: "stream session ended"},
		{name: "already resolved continues on the stream", ackStatus: []int{-3, 4091}, wantHits: 2, wantStreams: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeServer(t, signedEnvelope(1, "d-1", `{"a":1}`), signedEnvelope(2, "d-2", `{"a":2}`))
			fake.ackStatus = tt.ackStatus
			tg := &target{statuses: []int{http.StatusOK}}
			log, err := run(t, fake, tg, func(o *Options) { o.Count = 2 })
			if err != nil {
				t.Fatalf("relay: %v\n%s", err, log)
			}
			if got := fake.ackedSeqs(); fmt.Sprint(got) != "[1 2]" {
				t.Errorf("acks = %v, want [1 2]\n%s", got, log)
			}
			if n := len(tg.snapshot()); n != tt.wantHits {
				t.Errorf("target hits = %d, want %d\n%s", n, tt.wantHits, log)
			}
			if n := fake.streamConnects(); n != tt.wantStreams {
				t.Errorf("stream connections = %d, want %d\n%s", n, tt.wantStreams, log)
			}
			if tt.wantLog != "" && !strings.Contains(log, tt.wantLog) {
				t.Errorf("stderr missing %q:\n%s", tt.wantLog, log)
			}
			if strings.Contains(log, "it will be redelivered") {
				t.Errorf("misleading log line:\n%s", log)
			}
		})
	}
}

// Finding 2: an old server must be detected before the stream is opened.
func TestRun_ProbeBeforeStream(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		t.Run(fmt.Sprintf("old server %d", code), func(t *testing.T) {
			fake := newFakeServer(t, signedEnvelope(1, "d-1", `{}`))
			fake.oldServer, fake.oldStatus = true, code
			_, err := run(t, fake, &target{statuses: []int{200}}, nil)
			if !errors.Is(err, ErrServerTooOld) {
				t.Errorf("err = %v, want ErrServerTooOld", err)
			}
			if n := fake.streamConnects(); n != 0 {
				t.Errorf("stream connections = %d, want 0 against an old server", n)
			}
		})
	}
	t.Run("transient probe failures are retried", func(t *testing.T) {
		fake := newFakeServer(t, signedEnvelope(1, "d-1", `{"a":1}`))
		fake.probeStatus = []int{http.StatusBadGateway, http.StatusServiceUnavailable}
		log, err := run(t, fake, &target{statuses: []int{200}}, func(o *Options) { o.Count = 1 })
		if err != nil {
			t.Fatalf("relay: %v\n%s", err, log)
		}
		if fake.probes != 3 || fmt.Sprint(fake.ackedSeqs()) != "[1]" {
			t.Errorf("probes = %d acks = %v\n%s", fake.probes, fake.ackedSeqs(), log)
		}
	})
	t.Run("auth failure is fatal", func(t *testing.T) {
		fake := newFakeServer(t)
		fake.probeStatus = []int{http.StatusForbidden}
		_, err := run(t, fake, &target{statuses: []int{200}}, nil)
		if err == nil || !strings.Contains(err.Error(), "403") || fake.streamConnects() != 0 {
			t.Errorf("err = %v, streams = %d", err, fake.streamConnects())
		}
	})
}

// Finding 3: a large delivery full of characters json.Marshal escapes.
func TestRun_LargeDelivery(t *testing.T) {
	body := `{"b":"` + strings.Repeat("<>&", (12<<20)/3) + `"}`
	fake := newFakeServer(t, signedEnvelope(1, "d-big", body))
	fake.maxPayload = 25 << 20
	tg := &target{statuses: []int{200}}
	log, err := run(t, fake, tg, func(o *Options) { o.Count = 1 })
	if err != nil {
		t.Fatalf("relay: %v\n%s", err, log)
	}
	hits := tg.snapshot()
	if len(hits) != 1 || !bytes.Equal(hits[0].body, []byte(body)) {
		t.Fatalf("large body not relayed intact: %d hits", len(hits))
	}
	if fake.streamConnects() != 1 {
		t.Errorf("stream connections = %d, want 1", fake.streamConnects())
	}
}

func TestScanSSE_LineLimit(t *testing.T) {
	big := strings.Repeat("x", 200<<10)
	stream := "event: session\ndata: {}\n\ndata: " + big + "\n\n"
	var got []string
	err := scanSSE(strings.NewReader(stream), 300<<10, func(kind, _, data string) (bool, error) {
		got = append(got, kind+":"+fmt.Sprint(len(data)))
		return false, nil
	})
	if err != nil || len(got) != 2 || got[1] != fmt.Sprintf(":%d", len(big)) {
		t.Errorf("err=%v got=%v", err, got)
	}
	err = scanSSE(strings.NewReader(stream), 100<<10, func(string, string, string) (bool, error) { return false, nil })
	var tooLarge *EventTooLargeError
	if !errors.As(err, &tooLarge) {
		t.Errorf("err = %v, want EventTooLargeError", err)
	}
	// CRLF line endings and a final event without a trailing blank line.
	var last string
	_ = scanSSE(strings.NewReader("event: a\r\ndata: 1\r\n\r\ndata: 2"), 1024, func(kind, _, data string) (bool, error) {
		last = kind + "=" + data
		return false, nil
	})
	if last != "=2" {
		t.Errorf("last event = %q", last)
	}
}

// Finding 4: a stream that goes silent (half-open) is dropped.
func TestRun_IdleStreamReconnects(t *testing.T) {
	fake := newFakeServer(t, signedEnvelope(1, "d-1", `{"a":1}`))
	fake.silentConns = 1
	log, err := run(t, fake, &target{statuses: []int{200}}, func(o *Options) {
		o.Count = 1
		o.IdleTimeout = 200 * time.Millisecond
	})
	if err != nil {
		t.Fatalf("relay: %v\n%s", err, log)
	}
	if fake.streamConnects() != 2 || !strings.Contains(log, "no data from the server") {
		t.Errorf("streams = %d\n%s", fake.streamConnects(), log)
	}
}

// The idle timeout does not fire while a delivery is being retried: the
// second delivery arrives on the same connection.
func TestRun_IdleTimeoutPausedWhileRetrying(t *testing.T) {
	fake := newFakeServer(t, signedEnvelope(1, "d-1", `{"a":1}`), signedEnvelope(2, "d-2", `{"a":2}`))
	tg := &target{statuses: []int{500, 500, 500, 500, 500, 200}}
	log, err := run(t, fake, tg, func(o *Options) {
		o.Count = 2
		o.IdleTimeout = 100 * time.Millisecond
		o.Backoff, o.MaxDelay = 60*time.Millisecond, 60*time.Millisecond
	})
	if err != nil {
		t.Fatalf("relay: %v\n%s", err, log)
	}
	if fake.streamConnects() != 1 || fmt.Sprint(fake.ackedSeqs()) != "[1 2]" {
		t.Errorf("streams = %d acks = %v, want 1 and [1 2]\n%s", fake.streamConnects(), fake.ackedSeqs(), log)
	}
}

// Finding 5: 5xx and 429 from the stream are retried; other 4xx are fatal.
func TestRun_StreamStatus(t *testing.T) {
	t.Run("retryable", func(t *testing.T) {
		fake := newFakeServer(t, signedEnvelope(1, "d-1", `{"a":1}`))
		fake.streamStatus = []int{http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusInternalServerError}
		log, err := run(t, fake, &target{statuses: []int{200}}, func(o *Options) { o.Count = 1 })
		if err != nil {
			t.Fatalf("relay: %v\n%s", err, log)
		}
		if fake.streamConnects() != 4 || !strings.Contains(log, "stream unavailable") {
			t.Errorf("streams = %d\n%s", fake.streamConnects(), log)
		}
	})
	t.Run("4xx is fatal", func(t *testing.T) {
		fake := newFakeServer(t)
		fake.streamStatus = []int{http.StatusBadRequest}
		_, err := run(t, fake, &target{statuses: []int{200}}, nil)
		if err == nil || !strings.Contains(err.Error(), "400") || fake.streamConnects() != 1 {
			t.Errorf("err = %v streams = %d", err, fake.streamConnects())
		}
	})
}

// Finding 6: an empty body (payload_base64 omitted) is relayed, not fatal.
func TestRun_EmptyBody(t *testing.T) {
	fake := newFakeServer(t, signedEnvelope(1, "d-empty", ""))
	tg := &target{statuses: []int{200}}
	log, err := run(t, fake, tg, func(o *Options) { o.Count = 1 })
	if err != nil {
		t.Fatalf("relay: %v\n%s", err, log)
	}
	hits := tg.snapshot()
	if len(hits) != 1 || len(hits[0].body) != 0 || fmt.Sprint(fake.ackedSeqs()) != "[1]" {
		t.Errorf("hits = %d acks = %v\n%s", len(hits), fake.ackedSeqs(), log)
	}
}

func TestValidateTargetURL(t *testing.T) {
	tests := []struct {
		in      string
		wantErr bool
	}{
		{"http://127.0.0.1:8080/hook", false},
		{"https://skipper.example.com/github/webhook?x=1", false},
		{"ftp://example.com/", true},
		{"file:///tmp/x", true},
		{"http://user:pw@example.com/", true},
		{"http://example.com/#frag", true},
		{"http:///nohost", true},
		{"not a url", true},
		{"", true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if err := ValidateTargetURL(tt.in); (err != nil) != tt.wantErr {
				t.Errorf("ValidateTargetURL(%q) = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
		})
	}
}

// Round 2, finding 5: a 400 without the capability header is not this
// endpoint (an older server behind a proxy or WAF).
func TestRun_ProbeRequiresCapabilityHeader(t *testing.T) {
	fake := newFakeServer(t, signedEnvelope(1, "d-1", `{}`))
	fake.noCapHeader = true
	_, err := run(t, fake, &target{statuses: []int{200}}, nil)
	if !errors.Is(err, ErrServerTooOld) || fake.streamConnects() != 0 {
		t.Errorf("err = %v streams = %d, want ErrServerTooOld and no stream", err, fake.streamConnects())
	}
}

// Round 2, finding 6: a server-side ack_error is not retried and does not
// reconnect; the server redelivers on the same stream.
func TestRun_ServerAckErrorContinues(t *testing.T) {
	fake := newFakeServer(t, signedEnvelope(1, "d-1", `{"a":1}`), signedEnvelope(2, "d-2", `{"a":2}`))
	fake.ackStatus = []int{-2}
	tg := &target{statuses: []int{200}}
	// The ack_error delivery is not counted; its redelivery is.
	log, err := run(t, fake, tg, func(o *Options) { o.Count = 2 })
	if err != nil {
		t.Fatalf("relay: %v\n%s", err, log)
	}
	if fake.streamConnects() != 1 {
		t.Errorf("stream connections = %d, want 1\n%s", fake.streamConnects(), log)
	}
	// seq 1: posted, ack_error (not retried), redelivered, posted, acked.
	if fake.ackCalls != 3 || fmt.Sprint(fake.ackedSeqs()) != "[1 2]" || len(tg.snapshot()) != 3 {
		t.Errorf("ack calls = %d acks = %v hits = %d\n%s", fake.ackCalls, fake.ackedSeqs(), len(tg.snapshot()), log)
	}
	if !strings.Contains(log, "the server will redeliver it") || strings.Contains(log, "reconnecting") {
		t.Errorf("unexpected log:\n%s", log)
	}
}

// Round 2, finding 2: a takeover stops the relay instead of reconnecting.
func TestRun_TakenOver(t *testing.T) {
	t.Run("evicted event while idle", func(t *testing.T) {
		fake := newFakeServer(t, signedEnvelope(1, "d-1", `{"a":1}`), signedEnvelope(2, "d-2", `{"a":2}`))
		fake.evictAfter = 1
		log, err := run(t, fake, &target{statuses: []int{200}}, nil)
		if !errors.Is(err, ErrTakenOver) || !strings.Contains(err.Error(), "durable relay-test was taken over by another relay (opened by bob)") {
			t.Errorf("err = %v, want ErrTakenOver\n%s", err, log)
		}
		if fake.streamConnects() != 1 {
			t.Errorf("stream connections = %d, want 1", fake.streamConnects())
		}
	})
	t.Run("ack 404 then evicted event", func(t *testing.T) {
		fake := newFakeServer(t, signedEnvelope(1, "d-1", `{"a":1}`))
		fake.ackStatus = []int{http.StatusNotFound}
		fake.evictAfter = 0
		// The stream sends the evicted event after the failed ack.
		fake.envs = append(fake.envs, nil)
		ghp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/webhooks/stream" {
				fake.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set(webhook.ClientAckHeader, "1")
			fmt.Fprintf(w, "event: session\ndata: {\"session\":%q}\n\n", fake.session)
			data, _ := json.Marshal(signedEnvelope(1, "d-1", `{"a":1}`))
			fmt.Fprintf(w, "id: 1\nevent: issues\ndata: %s\n\n", data)
			w.(http.Flusher).Flush()
			time.Sleep(200 * time.Millisecond) // the ack happens meanwhile
			fmt.Fprint(w, "event: evicted\ndata: {}\n\n")
		}))
		defer ghp.Close()
		tsrv := httptest.NewServer(&target{statuses: []int{200}})
		defer tsrv.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var log syncBuffer
		err := Run(ctx, fastOptions(ghp.URL, tsrv.URL), &log)
		if !errors.Is(err, ErrTakenOver) {
			t.Errorf("err = %v, want ErrTakenOver", err)
		}
		if strings.Contains(log.String(), "reconnect") {
			t.Errorf("misleading reconnect line before a takeover exit:\n%s", log.String())
		}
	})
}

// Round 2, finding 4: an event larger than the reader's cap.
func TestRun_EventTooLarge(t *testing.T) {
	body := `{"b":"` + strings.Repeat("y", 3<<20) + `"}`
	t.Run("server raised its cap: grow and reconnect", func(t *testing.T) {
		fake := newFakeServer(t, signedEnvelope(1, "d-big", body))
		fake.maxPayload, fake.maxPayloadLater = 1<<20, 8<<20
		tg := &target{statuses: []int{200}}
		log, err := run(t, fake, tg, func(o *Options) { o.Count = 1 })
		if err != nil {
			t.Fatalf("relay: %v\n%s", err, log)
		}
		if fake.streamConnects() != 2 || len(tg.snapshot()) != 1 || !strings.Contains(log, "reconnecting with a larger reader") {
			t.Errorf("streams = %d hits = %d\n%s", fake.streamConnects(), len(tg.snapshot()), log)
		}
	})
	t.Run("cap unchanged: stop with a clear error", func(t *testing.T) {
		fake := newFakeServer(t, signedEnvelope(7, "d-huge", body))
		fake.maxPayload = 1 << 20
		_, err := run(t, fake, &target{statuses: []int{200}}, nil)
		var e *EventTooLargeError
		if !errors.As(err, &e) || e.Sequence != "7" || e.Delivery != "d-huge" || !strings.Contains(err.Error(), "seq=7 delivery=d-huge") {
			t.Errorf("err = %v", err)
		}
		if fake.streamConnects() != 1 {
			t.Errorf("stream connections = %d, want 1 (no loop)", fake.streamConnects())
		}
	})
}

func TestRun_StatusAtStartup(t *testing.T) {
	t.Run("transient failure is retried", func(t *testing.T) {
		fake := newFakeServer(t, signedEnvelope(1, "d-1", `{"a":1}`))
		fake.statusFail, fake.maxPayload = 2, 1<<20
		log, err := run(t, fake, &target{statuses: []int{200}}, func(o *Options) { o.Count = 1 })
		if err != nil || fake.statusCalls != 3 || strings.Contains(log, "warning") {
			t.Errorf("err = %v status calls = %d\n%s", err, fake.statusCalls, log)
		}
	})
	t.Run("persistent failure warns", func(t *testing.T) {
		fake := newFakeServer(t, signedEnvelope(1, "d-1", `{"a":1}`))
		fake.statusFail = 100
		log, err := run(t, fake, &target{statuses: []int{200}}, func(o *Options) { o.Count = 1 })
		if err != nil || !strings.Contains(log, "warning: could not read the server's max_payload_bytes") {
			t.Errorf("err = %v\n%s", err, log)
		}
	})
	t.Run("a cap of exactly 1 GiB is accepted", func(t *testing.T) {
		fake := newFakeServer(t)
		fake.maxPayload = 1 << 30
		ghp := httptest.NewServer(fake)
		defer ghp.Close()
		r := &relayer{opts: fastOptions(ghp.URL, "http://127.0.0.1:1"), errOut: io.Discard}
		r.opts.defaults()
		if n, err := r.fetchMaxPayload(context.Background()); err != nil || n != 1<<30 {
			t.Errorf("n = %d err = %v", n, err)
		}
	})
}

// Round 3, finding 1: a reconnect that lands on an older server is caught
// by the per-connect probe, before any delivery can be flush-acked.
func TestRun_ReconnectToOldServerLosesNothing(t *testing.T) {
	fake := newFakeServer(t, signedEnvelope(1, "d-1", `{"a":1}`), signedEnvelope(2, "d-2", `{"a":2}`))
	fake.oldAfterFirst = true
	tg := &target{statuses: []int{200}}
	log, err := run(t, fake, tg, nil)
	if !errors.Is(err, ErrServerTooOld) {
		t.Fatalf("err = %v, want ErrServerTooOld\n%s", err, log)
	}
	if fake.streamConnects() != 1 || fake.lostToOld != 0 {
		t.Errorf("streams = %d, flush-acked by the old server = %d; want 1 and 0\n%s", fake.streamConnects(), fake.lostToOld, log)
	}
	if fmt.Sprint(fake.ackedSeqs()) != "[1]" || len(tg.snapshot()) != 1 {
		t.Errorf("acks = %v hits = %d", fake.ackedSeqs(), len(tg.snapshot()))
	}
}

// A stream response without the capability header is closed unread.
func TestRun_StreamWithoutCapabilityHeader(t *testing.T) {
	fake := newFakeServer(t, signedEnvelope(1, "d-1", `{"a":1}`))
	fake.streamNoHeader = true
	tg := &target{statuses: []int{200}}
	_, err := run(t, fake, tg, nil)
	if !errors.Is(err, ErrServerTooOld) || len(tg.snapshot()) != 0 || len(fake.ackedSeqs()) != 0 {
		t.Errorf("err = %v hits = %d acks = %v", err, len(tg.snapshot()), fake.ackedSeqs())
	}
}

// Round 3, finding 2: an undecodable event is never skipped silently; the
// relay logs it and drops the stream so the server redelivers.
func TestRun_UndecodableEventDropsStream(t *testing.T) {
	for name, garbage := range map[string]string{
		"bad json":   "id: 9\nevent: issues\ndata: {not json\n\n",
		"sequence 0": "id: 9\nevent: issues\ndata: {\"sequence\":0,\"delivery\":\"x\"}\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeServer(t, signedEnvelope(1, "d-1", `{"a":1}`))
			fake.garbageFirst = garbage
			log, err := run(t, fake, &target{statuses: []int{200}}, func(o *Options) { o.Count = 1 })
			if err != nil {
				t.Fatalf("relay: %v\n%s", err, log)
			}
			if fake.streamConnects() != 2 || !strings.Contains(log, "undecodable event id=9") {
				t.Errorf("streams = %d\n%s", fake.streamConnects(), log)
			}
		})
	}
}

// Round 3, finding 5: a 409 "acked" counts; a 409 "released" does not, and
// the redelivery is relayed and counted.
func TestRun_ConflictCodes(t *testing.T) {
	t.Run("acked counts", func(t *testing.T) {
		fake := newFakeServer(t, signedEnvelope(1, "d-1", `{"a":1}`))
		fake.ackStatus = []int{-3, 4091}
		tg := &target{statuses: []int{200}}
		log, err := run(t, fake, tg, func(o *Options) { o.Count = 1 })
		if err != nil || len(tg.snapshot()) != 1 {
			t.Errorf("err = %v hits = %d\n%s", err, len(tg.snapshot()), log)
		}
	})
	t.Run("released does not count", func(t *testing.T) {
		fake := newFakeServer(t, signedEnvelope(1, "d-1", `{"a":1}`))
		fake.ackStatus = []int{4092}
		tg := &target{statuses: []int{200}}
		log, err := run(t, fake, tg, func(o *Options) { o.Count = 1 })
		if err != nil {
			t.Fatalf("relay: %v\n%s", err, log)
		}
		// Count=1 is reached only by the redelivery.
		if len(tg.snapshot()) != 2 || fmt.Sprint(fake.ackedSeqs()) != "[1]" || fake.streamConnects() != 1 {
			t.Errorf("hits = %d acks = %v streams = %d\n%s", len(tg.snapshot()), fake.ackedSeqs(), fake.streamConnects(), log)
		}
		if !strings.Contains(log, "the server will redeliver it") {
			t.Errorf("no redelivery note:\n%s", log)
		}
	})
}

// The relay decodes stream events into its own delivery struct (so it
// tolerates envelope changes between server versions). Its JSON tags must
// still match webhook.Envelope, as the server marshals it in raw mode.
func TestDeliveryDecodesEnvelope(t *testing.T) {
	env := webhook.Envelope{
		Subject: "github.webhooks.1.issues.opened", Sequence: 42, StoredAt: time.Now(),
		Delivery: "d-42", Event: "issues", Action: "opened", HookID: "98765",
		TargetType: "integration", TargetID: "123456", AppRecordID: "rec", AppName: "app",
		Repository: "o/r", InstallationID: 7, Sender: "octocat", ReceivedAt: time.Now(),
		Signature256: "sha256=abc", SignatureSHA1: "sha1=def", UserAgent: "GitHub-Hookshot/x",
		OriginalContentType: "application/json", Headers: map[string]string{"k": "v"},
		PayloadBase64: []byte(`{"exact":"bytes"}`),
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var d delivery
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	want := delivery{
		Sequence: 42, Delivery: "d-42", Event: "issues", HookID: "98765",
		TargetType: "integration", TargetID: "123456", Signature256: "sha256=abc",
		SignatureSHA1: "sha1=def", UserAgent: "GitHub-Hookshot/x",
		OriginalContentType: "application/json", PayloadBase64: []byte(`{"exact":"bytes"}`),
	}
	if !reflect.DeepEqual(d, want) {
		t.Errorf("decoded %+v\nwant    %+v", d, want)
	}
	// Every field the relay declares must be filled from the envelope, so
	// a field added to delivery with a tag the server never sends fails.
	v := reflect.ValueOf(d)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).IsZero() {
			t.Errorf("delivery.%s (json %q) is not filled from webhook.Envelope", v.Type().Field(i).Name, v.Type().Field(i).Tag.Get("json"))
		}
	}
}

// The target URL's query string can carry a secret; no log line or error
// shows it.
func TestRun_RedactsTargetQuery(t *testing.T) {
	fake := newFakeServer(t, signedEnvelope(1, "d-1", `{"a":1}`))
	var n atomic.Int32
	tsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			// Drop the connection: net/http reports it with the full URL.
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
	}))
	defer tsrv.Close()
	log, err := run(t, fake, &target{statuses: []int{200}}, func(o *Options) {
		o.Target = tsrv.URL + "/hook?token=s3cret"
		o.Count = 1
	})
	if err != nil {
		t.Fatalf("relay: %v\n%s", err, log)
	}
	if strings.Contains(log, "s3cret") {
		t.Errorf("secret query in the log:\n%s", log)
	}
	if !strings.Contains(log, "relaying webhook deliveries to "+tsrv.URL+"/hook?REDACTED") || !strings.Contains(log, `/hook?REDACTED": EOF`) {
		t.Errorf("banner or retry line not redacted as expected:\n%s", log)
	}
}

func TestRedactURL(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"https://r.example/hook", "https://r.example/hook"},
		{"https://r.example/hook?token=s3cret", "https://r.example/hook?REDACTED"},
		{"https://r.example/hook#frag", "https://r.example/hook?REDACTED"},
		{"https://u:pw@r.example/hook?t=1", "https://r.example/hook?REDACTED"},
		{"http://exa mple/?token=s3cret", "http://exa mple/?REDACTED"},
	} {
		if got := RedactURL(tt.in); got != tt.want {
			t.Errorf("RedactURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	if err := ValidateTargetURL("http://exa mple/?token=s3cret"); err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("ValidateTargetURL error shows the query: %v", err)
	}
}

// A target URL that net/http cannot even build a request from (Run does not
// validate it; the CLI does) is still never shown with its query.
func TestRun_RedactsTargetQueryInRequestErrors(t *testing.T) {
	fake := newFakeServer(t, signedEnvelope(1, "d-1", `{"a":1}`))
	ghp := httptest.NewServer(fake)
	defer ghp.Close()
	opts := fastOptions(ghp.URL, "http://exa mple/hook?token=s3cret")
	var log syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, opts, &log) }()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(log.String(), "retrying seq=1") {
		if time.Now().After(deadline) {
			t.Fatalf("no retry line:\n%s", log.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if out := log.String(); strings.Contains(out, "s3cret") || !strings.Contains(out, "?REDACTED") {
		t.Errorf("request error not redacted:\n%s", out)
	}
}
