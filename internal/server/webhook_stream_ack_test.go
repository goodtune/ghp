package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/webhook"
	"github.com/goodtune/ghp/internal/webhook/relay"
)

type sseTestEvent struct {
	id, event, data string
}

// sseEvents parses an SSE body in the background and sends each complete
// event (comments skipped) on the returned channel, which is closed at EOF.
func sseEvents(body io.Reader) <-chan sseTestEvent {
	ch := make(chan sseTestEvent, 16)
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(body)
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		var ev sseTestEvent
		var data strings.Builder
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if data.Len() > 0 {
					ev.data = data.String()
					ch <- ev
				}
				ev = sseTestEvent{}
				data.Reset()
			case strings.HasPrefix(line, ":"):
			case strings.HasPrefix(line, "id: "):
				ev.id = strings.TrimPrefix(line, "id: ")
			case strings.HasPrefix(line, "event: "):
				ev.event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				data.WriteString(strings.TrimPrefix(line, "data: "))
			}
		}
	}()
	return ch
}

func nextEvent(t *testing.T, ch <-chan sseTestEvent, within time.Duration) sseTestEvent {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("stream closed before the next event")
		}
		return ev
	case <-time.After(within):
		t.Fatalf("no event within %s", within)
	}
	return sseTestEvent{}
}

func expectNoEvent(t *testing.T, ch <-chan sseTestEvent, within time.Duration) {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if ok {
			t.Fatalf("unexpected event within %s: %+v", within, ev)
		}
	case <-time.After(within):
	}
}

func ackCounter(t *testing.T, result string) float64 {
	t.Helper()
	c, err := metrics.WebhookStreamAckTotal.GetMetricWith(prometheus.Labels{"result": result})
	if err != nil {
		t.Fatal(err)
	}
	var m io_prometheus_client.Metric
	if err := c.(prometheus.Metric).Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

// streamTestServer serves handleWebhookStream with sess as the
// authenticated session and counts running handlers.
func streamTestServer(t *testing.T, a *API, sess *auth.Session) (*httptest.Server, func(*testing.T)) {
	t.Helper()
	return streamTestServerOn(t, a, sess, nil)
}

// streamTestServerOn is streamTestServer with the listener wrapped by wrap
// (when not nil).
func streamTestServerOn(t *testing.T, a *API, sess *auth.Session, wrap func(net.Listener) net.Listener) (*httptest.Server, func(*testing.T)) {
	t.Helper()
	var active atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.Add(1)
		defer active.Add(-1)
		if sess != nil {
			r = r.WithContext(auth.NewContextWithSession(r.Context(), sess))
		}
		a.handleWebhookStream(w, r)
	}))
	if wrap != nil {
		srv.Listener = wrap(srv.Listener)
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, func(t *testing.T) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for active.Load() != 0 {
			if time.Now().After(deadline) {
				t.Fatalf("%d stream handler(s) still running", active.Load())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func openStream(t *testing.T, ctx context.Context, url string) <-chan sseTestEvent {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("stream status %d: %s", resp.StatusCode, body)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return sseEvents(resp.Body)
}

// postAck calls the ack endpoint directly with sess as the caller.
func postAck(t *testing.T, a *API, sess *auth.Session, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/stream/ack", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if sess != nil {
		req = req.WithContext(auth.NewContextWithSession(req.Context(), sess))
	}
	w := httptest.NewRecorder()
	a.handleWebhookStreamAck(w, req)
	return w
}

func ackBody(session string, seq uint64) string {
	return fmt.Sprintf(`{"session":%q,"sequence":%d}`, session, seq)
}

func sessionToken(t *testing.T, ev sseTestEvent) string {
	t.Helper()
	if ev.event != "session" {
		t.Fatalf("first event = %+v, want session", ev)
	}
	var s struct {
		Session string `json:"session"`
	}
	if err := json.Unmarshal([]byte(ev.data), &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Session) != 64 {
		t.Fatalf("unexpected session event: %+v", s)
	}
	return s.Session
}

func envSeq(t *testing.T, ev sseTestEvent) uint64 {
	t.Helper()
	var env webhook.Envelope
	if err := json.Unmarshal([]byte(ev.data), &env); err != nil {
		t.Fatalf("bad envelope %q: %v", ev.data, err)
	}
	return env.Sequence
}

func TestParseStreamModes(t *testing.T) {
	tests := []struct {
		query     string
		raw       bool
		clientAck bool
		wantErr   bool
	}{
		{query: "", raw: false, clientAck: false},
		{query: "raw=1", raw: true},
		{query: "raw=true", raw: true},
		{query: "raw=0"},
		{query: "raw=yes", wantErr: true},
		{query: "ack=server"},
		{query: "ack=client&durable=x", clientAck: true},
		{query: "ack=client", wantErr: true},
		{query: "ack=bogus&durable=x", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/webhooks/stream?"+tt.query, nil)
			raw, clientAck, err := parseStreamModes(r)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && (raw != tt.raw || clientAck != tt.clientAck) {
				t.Errorf("raw=%v clientAck=%v, want %v %v", raw, clientAck, tt.raw, tt.clientAck)
			}
		})
	}
}

func TestWebhookStream_RawPayload(t *testing.T) {
	a, h, secret := newWebhookTestAPI(t)
	// Whitespace and key order that json compaction would change.
	body := "{ \"zen\" :  \"raw bytes\",\n  \"b\": [ 1, 2 ],   \"a\": {}\n}"
	postDelivery(t, h, secret, "ping", "d-raw", body)
	srv, _ := streamTestServer(t, a, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ev := nextEvent(t, openStream(t, ctx, srv.URL+"?from=all&raw=1"), 5*time.Second)
	var env webhook.Envelope
	if err := json.Unmarshal([]byte(ev.data), &env); err != nil {
		t.Fatal(err)
	}
	if string(env.PayloadBase64) != body {
		t.Errorf("raw payload = %q, want %q", env.PayloadBase64, body)
	}
	if !webhook.VerifySignature(secret, env.PayloadBase64, env.Signature256) {
		t.Error("stored signature does not verify over the raw payload")
	}
	if !strings.Contains(ev.data, `"payload_base64":"`+base64.StdEncoding.EncodeToString([]byte(body))+`"`) {
		t.Errorf("payload_base64 not standard base64 in %s", ev.data)
	}

	// Default output is unchanged: no raw field.
	ev = nextEvent(t, openStream(t, ctx, srv.URL+"?from=all"), 5*time.Second)
	if strings.Contains(ev.data, "payload_base64") {
		t.Errorf("payload_base64 present without raw=1: %s", ev.data)
	}
}

func TestWebhookStream_ClientAck(t *testing.T) {
	a, h, secret := newWebhookTestAPI(t)
	sess := adminSession()
	srv, waitExited := streamTestServer(t, a, sess)

	t.Run("no ack until the client acks", func(t *testing.T) {
		postDelivery(t, h, secret, "issues", "d-ca-1", `{"action":"opened"}`)
		postDelivery(t, h, secret, "issues", "d-ca-2", `{"action":"closed"}`)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		events := openStream(t, ctx, srv.URL+"?from=all&durable=ca-1&ack=client&filter=github.webhooks.*.issues.>")
		token := sessionToken(t, nextEvent(t, events, 5*time.Second))
		first := nextEvent(t, events, 5*time.Second)
		if s := envSeq(t, first); s != 1 || first.id != "1" {
			t.Fatalf("first delivery seq %d id %q, want 1", s, first.id)
		}
		expectNoEvent(t, events, time.Second)

		before := map[string]float64{}
		for _, r := range []string{"acked", "wrong_sequence", "invalid_session", "bad_request"} {
			before[r] = ackCounter(t, r)
		}
		cases := []struct {
			name string
			sess *auth.Session
			body string
			want int
		}{
			{"wrong sequence", sess, ackBody(token, 2), http.StatusConflict},
			{"unknown session", sess, ackBody(strings.Repeat("ab", 32), 1), http.StatusNotFound},
			{"other user", &auth.Session{UserID: "user-2", Role: "admin"}, ackBody(token, 1), http.StatusNotFound},
			{"malformed session", sess, ackBody("not-hex", 1), http.StatusBadRequest},
			{"zero sequence", sess, ackBody(token, 0), http.StatusBadRequest},
			{"bad json", sess, `{"session":`, http.StatusBadRequest},
			{"unknown field", sess, `{"session":"` + token + `","sequence":1,"x":1}`, http.StatusBadRequest},
			{"too large", sess, `{"session":"` + strings.Repeat("a", 8192) + `"}`, http.StatusRequestEntityTooLarge},
		}
		for _, c := range cases {
			if w := postAck(t, a, c.sess, c.body); w.Code != c.want {
				t.Errorf("%s: status %d, want %d: %s", c.name, w.Code, c.want, w.Body.String())
			}
		}
		expectNoEvent(t, events, 200*time.Millisecond)

		if w := postAck(t, a, sess, ackBody(token, 1)); w.Code != http.StatusOK {
			t.Fatalf("ack: status %d: %s", w.Code, w.Body.String())
		}
		// Single use: the same ack again is rejected.
		if w := postAck(t, a, sess, ackBody(token, 1)); w.Code != http.StatusConflict {
			t.Errorf("repeat ack: status %d, want 409", w.Code)
		}
		if s := envSeq(t, nextEvent(t, events, 5*time.Second)); s != 2 {
			t.Fatalf("second delivery seq %d, want 2", s)
		}
		if d := ackCounter(t, "acked") - before["acked"]; d != 1 {
			t.Errorf("acked delta %v, want 1", d)
		}
		if d := ackCounter(t, "wrong_sequence") - before["wrong_sequence"]; d != 2 {
			t.Errorf("wrong_sequence delta %v, want 2", d)
		}
		if d := ackCounter(t, "invalid_session") - before["invalid_session"]; d != 2 {
			t.Errorf("invalid_session delta %v, want 2", d)
		}
		if d := ackCounter(t, "bad_request") - before["bad_request"]; d != 5 {
			t.Errorf("bad_request delta %v, want 5", d)
		}
		cancel()
		waitExited(t)

		// The session ends with the stream.
		if w := postAck(t, a, sess, ackBody(token, 2)); w.Code != http.StatusNotFound {
			t.Errorf("ack after disconnect: status %d, want 404", w.Code)
		}
	})

	t.Run("disconnect naks and the delivery is redelivered", func(t *testing.T) {
		postDelivery(t, h, secret, "label", "d-nak", `{"action":"created"}`)
		before := ackCounter(t, "nak_disconnect")
		url := srv.URL + "?from=all&durable=ca-nak&ack=client&filter=github.webhooks.*.label.>"

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		events := openStream(t, ctx, url)
		sessionToken(t, nextEvent(t, events, 5*time.Second))
		seq := envSeq(t, nextEvent(t, events, 5*time.Second))
		cancel()
		waitExited(t)
		if d := ackCounter(t, "nak_disconnect") - before; d != 1 {
			t.Errorf("nak_disconnect delta %v, want 1", d)
		}

		// Redelivered at once (well inside the 10 s AckWait) to the same
		// durable.
		ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		events = openStream(t, ctx, url)
		token := sessionToken(t, nextEvent(t, events, 5*time.Second))
		if got := envSeq(t, nextEvent(t, events, 3*time.Second)); got != seq {
			t.Fatalf("redelivered seq %d, want %d", got, seq)
		}
		if w := postAck(t, a, sess, ackBody(token, seq)); w.Code != http.StatusOK {
			t.Fatalf("ack: %d %s", w.Code, w.Body.String())
		}
		cancel()
		waitExited(t)
	})

	t.Run("in-progress keeps a slow delivery from redelivery", func(t *testing.T) {
		a.webhooks.ackWait = time.Second
		a.webhooks.inProgressEvery = 200 * time.Millisecond
		defer func() { a.webhooks.ackWait, a.webhooks.inProgressEvery = 0, 0 }()

		postDelivery(t, h, secret, "deployment", "d-slow", `{"action":"created"}`)
		url := srv.URL + "?from=all&durable=ca-slow&ack=client&filter=github.webhooks.*.deployment.>"
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		holder := openStream(t, ctx, url)
		token := sessionToken(t, nextEvent(t, holder, 5*time.Second))
		seq := envSeq(t, nextEvent(t, holder, 5*time.Second))

		// A plain (server-ack) subscriber on the same durable pulls
		// throughout; without InProgress the delivery would be redelivered
		// to it after 1 s. (A second client-ack session would evict the
		// first instead.)
		other := openStream(t, ctx, strings.Replace(url, "&ack=client", "", 1))
		expectNoEvent(t, other, 3*time.Second)

		if w := postAck(t, a, sess, ackBody(token, seq)); w.Code != http.StatusOK {
			t.Fatalf("late ack: %d %s", w.Code, w.Body.String())
		}
		expectNoEvent(t, other, 1500*time.Millisecond)
		cancel()
		waitExited(t)
	})

	t.Run("ack=client without durable is 400", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "?ack=client")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status %d, want 400", resp.StatusCode)
		}
	})
}

func TestWebhookStreamAck_Disabled(t *testing.T) {
	a := newTestAPIWithStore(t)
	w := postAck(t, a, adminSession(), ackBody(strings.Repeat("ab", 32), 1))
	if w.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404", w.Code)
	}
}

// failingAckMsg wraps a delivery so that the confirmed ack fails.
type failingAckMsg struct{ jetstream.Msg }

func (failingAckMsg) DoubleAck(context.Context) error { return errors.New("injected ack failure") }

func TestWebhookStream_RawOmitsDecodedPayload(t *testing.T) {
	a, h, secret := newWebhookTestAPI(t)
	postDelivery(t, h, secret, "ping", "d-raw-only", `{"zen":"<b>&</b>"}`)
	srv, _ := streamTestServer(t, a, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ev := nextEvent(t, openStream(t, ctx, srv.URL+"?from=all&raw=1"), 5*time.Second)
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(ev.data), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["payload"]; ok {
		t.Errorf("raw mode still sends the decoded payload: %s", ev.data)
	}
	if _, ok := m["payload_base64"]; !ok {
		t.Errorf("raw mode has no payload_base64: %s", ev.data)
	}
}

func TestWebhookStream_ClientAckFailures(t *testing.T) {
	a, h, secret := newWebhookTestAPI(t)
	sess := adminSession()
	srv, waitExited := streamTestServer(t, a, sess)

	t.Run("ack_error releases the stream and the delivery is redelivered", func(t *testing.T) {
		a.webhooks.ackWait = time.Second
		a.webhooks.inProgressEvery = 200 * time.Millisecond
		defer func() { a.webhooks.ackWait, a.webhooks.inProgressEvery = 0, 0 }()
		postDelivery(t, h, secret, "fork", "d-ackerr", `{"forkee":{}}`)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		events := openStream(t, ctx, srv.URL+"?from=all&durable=ca-err&ack=client&filter=github.webhooks.*.fork.>")
		token := sessionToken(t, nextEvent(t, events, 5*time.Second))
		seq := envSeq(t, nextEvent(t, events, 5*time.Second))

		s := a.webhooks.acks.lookup(token, sess.UserID)
		s.mu.Lock()
		s.pendingMsg = failingAckMsg{s.pendingMsg}
		s.mu.Unlock()

		before := ackCounter(t, "ack_error")
		if w := postAck(t, a, sess, ackBody(token, seq)); w.Code != http.StatusBadGateway {
			t.Fatalf("failed ack: status %d, want 502: %s", w.Code, w.Body.String())
		}
		if d := ackCounter(t, "ack_error") - before; d != 1 {
			t.Errorf("ack_error delta %v, want 1", d)
		}
		// Unacked, so JetStream redelivers after AckWait to the same stream.
		if got := envSeq(t, nextEvent(t, events, 5*time.Second)); got != seq {
			t.Fatalf("redelivered seq %d, want %d", got, seq)
		}
		if w := postAck(t, a, sess, ackBody(token, seq)); w.Code != http.StatusOK {
			t.Fatalf("ack after redelivery: %d %s", w.Code, w.Body.String())
		}
		cancel()
		waitExited(t)
	})

	t.Run("shutdown naks the pending delivery", func(t *testing.T) {
		srvCtx, stop := context.WithCancel(context.Background())
		a.ctx = srvCtx
		defer func() { a.ctx = nil }()
		postDelivery(t, h, secret, "gollum", "d-shutdown", `{"pages":[]}`)
		url := srv.URL + "?from=all&durable=ca-shut&ack=client&filter=github.webhooks.*.gollum.>"
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		events := openStream(t, ctx, url)
		sessionToken(t, nextEvent(t, events, 5*time.Second))
		seq := envSeq(t, nextEvent(t, events, 5*time.Second))

		before := ackCounter(t, "nak_shutdown")
		stop()
		waitExited(t)
		if d := ackCounter(t, "nak_shutdown") - before; d != 1 {
			t.Errorf("nak_shutdown delta %v, want 1", d)
		}
		a.ctx = nil
		events = openStream(t, ctx, url)
		token := sessionToken(t, nextEvent(t, events, 5*time.Second))
		if got := envSeq(t, nextEvent(t, events, 3*time.Second)); got != seq {
			t.Fatalf("after shutdown: seq %d, want %d", got, seq)
		}
		if w := postAck(t, a, sess, ackBody(token, seq)); w.Code != http.StatusOK {
			t.Fatalf("ack: %d", w.Code)
		}
		cancel()
		waitExited(t)
	})

	t.Run("ack racing a disconnect resolves the delivery exactly once", func(t *testing.T) {
		url := srv.URL + "?from=all&durable=ca-race&ack=client&filter=github.webhooks.*.watch.>"
		for i := 0; i < 10; i++ {
			postDelivery(t, h, secret, "watch", fmt.Sprintf("d-race-%d", i), `{"action":"started"}`)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			events := openStream(t, ctx, url)
			token := sessionToken(t, nextEvent(t, events, 5*time.Second))
			seq := envSeq(t, nextEvent(t, events, 5*time.Second))

			ackedBefore, nakBefore := ackCounter(t, "acked"), ackCounter(t, "nak_disconnect")
			var code atomic.Int32
			done := make(chan struct{})
			go func() {
				defer close(done)
				code.Store(int32(postAck(t, a, sess, ackBody(token, seq)).Code))
			}()
			cancel()
			<-done
			waitExited(t)
			acked := ackCounter(t, "acked") - ackedBefore
			naked := ackCounter(t, "nak_disconnect") - nakBefore
			if acked+naked != 1 {
				t.Fatalf("iteration %d: acked %v + nak %v, want exactly one", i, acked, naked)
			}
			if (code.Load() == http.StatusOK) != (acked == 1) {
				t.Fatalf("iteration %d: ack status %d but acked delta %v", i, code.Load(), acked)
			}
			if naked == 1 {
				// Drain the redelivery so the next iteration starts clean.
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				ev := openStream(t, ctx, url)
				tok := sessionToken(t, nextEvent(t, ev, 5*time.Second))
				if got := envSeq(t, nextEvent(t, ev, 3*time.Second)); got != seq {
					t.Fatalf("iteration %d: redelivered %d, want %d", i, got, seq)
				}
				if w := postAck(t, a, sess, ackBody(tok, seq)); w.Code != http.StatusOK {
					t.Fatalf("drain ack: %d", w.Code)
				}
				cancel()
				waitExited(t)
			}
		}
	})

	t.Run("a new session on the durable evicts the old one", func(t *testing.T) {
		postDelivery(t, h, secret, "member", "d-evict", `{"action":"added"}`)
		url := srv.URL + "?from=all&durable=ca-evict&ack=client&filter=github.webhooks.*.member.>"
		ctxA, cancelA := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancelA()
		evA := openStream(t, ctxA, url)
		tokA := sessionToken(t, nextEvent(t, evA, 5*time.Second))
		seq := envSeq(t, nextEvent(t, evA, 5*time.Second))

		before := ackCounter(t, "nak_evicted")
		ctxB, cancelB := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancelB()
		evB := openStream(t, ctxB, url)
		tokB := sessionToken(t, nextEvent(t, evB, 5*time.Second))
		// The held delivery moves to the new session at once, in order.
		if got := envSeq(t, nextEvent(t, evB, 3*time.Second)); got != seq {
			t.Fatalf("new session got seq %d, want %d", got, seq)
		}
		if d := ackCounter(t, "nak_evicted") - before; d != 1 {
			t.Errorf("nak_evicted delta %v, want 1", d)
		}
		// The old stream is told it was evicted, then closed.
		if ev := nextEvent(t, evA, 5*time.Second); ev.event != "evicted" {
			t.Errorf("old stream event = %+v, want evicted", ev)
		}
		select {
		case _, ok := <-evA:
			if ok {
				t.Error("old stream still delivering")
			}
		case <-time.After(5 * time.Second):
			t.Error("old stream not closed")
		}
		if w := postAck(t, a, sess, ackBody(tokA, seq)); w.Code != http.StatusNotFound {
			t.Errorf("ack on evicted session: %d, want 404", w.Code)
		}
		if w := postAck(t, a, sess, ackBody(tokB, seq)); w.Code != http.StatusOK {
			t.Errorf("ack on new session: %d", w.Code)
		}
		cancelA()
		cancelB()
		waitExited(t)
	})
}

// TestRelay_AgainstRealStream runs the relay engine against the real
// stream, ack and status handlers backed by an embedded JetStream bus.
func TestRelay_AgainstRealStream(t *testing.T) {
	a, h, secret := newWebhookTestAPI(t)
	sess := adminSession()
	withSession := func(fn http.HandlerFunc) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fn(w, r.WithContext(auth.NewContextWithSession(r.Context(), sess)))
		})
	}
	mux := http.NewServeMux()
	mux.Handle("GET /api/webhooks/status", withSession(a.handleWebhookStatus))
	mux.Handle("GET /api/webhooks/stream", withSession(a.handleWebhookStream))
	mux.Handle("POST /api/webhooks/stream/ack", withSession(a.handleWebhookStreamAck))
	ghp := httptest.NewServer(mux)
	defer ghp.Close()

	bodies := []string{
		"{ \"action\" : \"opened\",\n  \"z\": [ 1 ,2 ] }",
		`{"action":"edited","b":"` + strings.Repeat("<>&", 300<<10/3) + `"}`,
	}
	for i, b := range bodies {
		postDelivery(t, h, secret, "issues", fmt.Sprintf("d-real-%d", i), b)
	}

	var mu sync.Mutex
	var got [][]byte
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		hits++
		if !webhook.VerifySignature(secret, body, r.Header.Get("X-Hub-Signature-256")) || r.Header.Get("Authorization") != "" {
			http.Error(w, "rejected", http.StatusUnauthorized)
			return
		}
		if hits == 1 {
			http.Error(w, "warming up", http.StatusInternalServerError)
			return
		}
		got = append(got, body)
	}))
	defer target.Close()

	acked := ackCounter(t, "acked")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var log bytes.Buffer
	err := relay.Run(ctx, relay.Options{
		ServerURL: ghp.URL, Token: "ghpr_test", Target: target.URL + "/hook",
		Durable: "real-relay", From: "all", Count: 2,
		Backoff: 10 * time.Millisecond, ReconnectDelay: 10 * time.Millisecond,
	}, &log)
	if err != nil {
		t.Fatalf("relay: %v\n%s", err, log.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || string(got[0]) != bodies[0] || string(got[1]) != bodies[1] {
		t.Fatalf("target got %d bodies (hits %d)\n%s", len(got), hits, log.String())
	}
	if d := ackCounter(t, "acked") - acked; d != 2 {
		t.Errorf("acked delta %v, want 2", d)
	}
}

// newLargeWebhookTestAPI is newWebhookTestAPI with the bus sized for the
// default 25 MiB ingest cap, for large-delivery tests.
func newLargeWebhookTestAPI(t *testing.T) (*API, *webhook.Handler, []byte) {
	t.Helper()
	a := newTestAPIWithStore(t)
	a.encryptor = crypto.NewPassthroughEncryptor()
	cfg := config.Defaults().Webhooks
	cfg.Enabled = true
	cfg.NATS.StoreDir = t.TempDir()
	bus, err := webhook.NewBus(context.Background(), cfg.NATS, webhook.BusOptions{MaxPayloadBytes: cfg.MaxPayloadBytes}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bus.Close)
	secret := []byte("app-secret")
	if err := a.store.CreateApp(context.Background(), &database.App{Name: "Hooked", AppID: 777, WebhookSecret: string(secret)}); err != nil {
		t.Fatal(err)
	}
	secrets := webhook.NewStoreSecretSource(a.store, a.encryptor, "", a.logger)
	a.SetWebhooks(newWebhookService(cfg, bus, secrets, "https://ghp.example.com"))
	return a, webhook.NewHandler(bus, secrets, cfg.MaxPayloadBytes, a.logger), secret
}

// Round 2, finding 1: the write deadline follows progress, not the frame.
func TestWebhookStream_SlowReaderLargeEvent(t *testing.T) {
	a, h, secret := newLargeWebhookTestAPI(t)
	// A 1 s per-chunk deadline; the whole event takes about four times
	// that, so a deadline over the whole frame would cut it.
	a.webhooks.writeTimeout = time.Second
	body := `{"b":"` + strings.Repeat("x", 6<<20) + `"}`
	postDelivery(t, h, secret, "push", "d-slow-reader", body)

	for _, mode := range []string{"from=all", "from=all&durable=slow-plain", "from=all&durable=slow-ca&ack=client&raw=1"} {
		t.Run(mode, func(t *testing.T) {
			srv, waitExited := streamTestServer(t, a, adminSession())
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"?"+mode, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			buf := make([]byte, 64<<10)
			var total int
			start := time.Now()
			for total < len(body) {
				n, err := resp.Body.Read(buf)
				total += n
				if err != nil {
					t.Fatalf("stream cut after %d of >%d bytes in %s: %v", total, len(body), time.Since(start), err)
				}
				time.Sleep(40 * time.Millisecond) // ~1.5 MiB/s: far longer than one deadline overall
			}
			if el := time.Since(start); el < 2*time.Second {
				t.Fatalf("read finished in %s; the test did not exercise a slow reader", el)
			}
			cancel()
			waitExited(t)
		})
	}
}

// A reader that stops reading altogether is still cut off, and in
// client-ack mode its delivery is Nak'd.
func TestWebhookStream_StalledReaderIsCutOff(t *testing.T) {
	a, h, secret := newLargeWebhookTestAPI(t)
	a.webhooks.writeTimeout = time.Second
	postDelivery(t, h, secret, "push", "d-stall", `{"b":"`+strings.Repeat("x", 16<<20)+`"}`)
	srv, waitExited := streamTestServer(t, a, adminSession())
	before := ackCounter(t, "nak_disconnect")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"?from=all&durable=stall&ack=client&raw=1", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// Read nothing. The handler must give up on its own.
	waitExited(t)
	if d := ackCounter(t, "nak_disconnect") - before; d != 1 {
		t.Errorf("nak_disconnect delta %v, want 1", d)
	}
}

func TestWebhookStreamAck_CapabilityHeaderAndAckErrorCode(t *testing.T) {
	a, h, secret := newWebhookTestAPI(t)
	sess := adminSession()
	for _, body := range []string{`{}`, ackBody(strings.Repeat("ab", 32), 1)} {
		if w := postAck(t, a, sess, body); w.Header().Get("GHP-Webhook-Client-Ack") != "1" {
			t.Errorf("%s: status %d without capability header", body, w.Code)
		}
	}
	disabled := newTestAPIWithStore(t)
	if w := postAck(t, disabled, sess, `{}`); w.Code != http.StatusNotFound || w.Header().Get("GHP-Webhook-Client-Ack") != "1" {
		t.Errorf("disabled: status %d header %q", w.Code, w.Header().Get("GHP-Webhook-Client-Ack"))
	}

	srv, waitExited := streamTestServer(t, a, sess)
	postDelivery(t, h, secret, "fork", "d-code", `{}`)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	events := openStream(t, ctx, srv.URL+"?from=all&durable=ca-code&ack=client")
	token := sessionToken(t, nextEvent(t, events, 5*time.Second))
	seq := envSeq(t, nextEvent(t, events, 5*time.Second))
	s := a.webhooks.acks.lookup(token, sess.UserID)
	s.mu.Lock()
	s.pendingMsg = failingAckMsg{s.pendingMsg}
	s.mu.Unlock()
	w := postAck(t, a, sess, ackBody(token, seq))
	var resp struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if w.Code != http.StatusBadGateway || resp.Code != "ack_error" {
		t.Errorf("ack_error response: %d %s", w.Code, w.Body.String())
	}
	cancel()
	waitExited(t)
}

// waitFor polls cond until it holds, failing the test after 15 seconds.
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// sessionCount returns how many client-ack sessions are open (a session
// leaves the count when its handler returns).
func sessionCount(a *API) int {
	r := a.webhooks.acks
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

// durableSession returns the client-ack session that currently owns
// durable, or nil.
func durableSession(a *API, durable string) *streamAckSession {
	r := a.webhooks.acks
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byDurable[durable]
}

// gateListener stands in for a slow network. The next connection it
// accepts after arm() lets the server write gateAfter bytes, then blocks
// every further write until the connection's write deadline (or close),
// as a client that stopped reading would. blocked is closed when the first
// write blocks.
type gateListener struct {
	net.Listener
	gateAfter int
	armed     atomic.Bool
	blocked   chan struct{}
}

func newGateListener(l net.Listener, gateAfter int) *gateListener {
	return &gateListener{Listener: l, gateAfter: gateAfter, blocked: make(chan struct{})}
}

func (l *gateListener) arm() { l.armed.Store(true) }

func (l *gateListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil || !l.armed.CompareAndSwap(true, false) {
		return c, err
	}
	return &gatedConn{Conn: c, l: l, closed: make(chan struct{})}, nil
}

type gatedConn struct {
	net.Conn
	l          *gateListener
	written    int
	signalled  atomic.Bool
	closedFlag atomic.Bool
	closed     chan struct{}
	deadline   atomic.Int64 // write deadline in Unix nanoseconds; 0 = none
}

func (c *gatedConn) Write(p []byte) (int, error) {
	if c.written+len(p) <= c.l.gateAfter {
		n, err := c.Conn.Write(p)
		c.written += n
		return n, err
	}
	if c.signalled.CompareAndSwap(false, true) {
		close(c.l.blocked)
	}
	var expire <-chan time.Time
	if d := c.deadline.Load(); d != 0 {
		timer := time.NewTimer(time.Until(time.Unix(0, d)))
		defer timer.Stop()
		expire = timer.C
	}
	select {
	case <-expire:
		return 0, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *gatedConn) setDeadline(t time.Time) {
	if t.IsZero() {
		c.deadline.Store(0)
		return
	}
	c.deadline.Store(t.UnixNano())
}

func (c *gatedConn) SetWriteDeadline(t time.Time) error {
	c.setDeadline(t)
	return c.Conn.SetWriteDeadline(t)
}

func (c *gatedConn) SetDeadline(t time.Time) error {
	c.setDeadline(t)
	return c.Conn.SetDeadline(t)
}

func (c *gatedConn) Close() error {
	if c.closedFlag.CompareAndSwap(false, true) {
		close(c.closed)
	}
	return c.Conn.Close()
}

// holdLargeFrame opens a client-ack stream on url over a gated connection
// with a client that reads everything it gets, so the server blocks part
// way through writing the (large) first delivery exactly at the gate, until
// the chunk write deadline expires. It returns once that write is blocked.
func holdLargeFrame(t *testing.T, ctx context.Context, gate *gateListener, url string) {
	t.Helper()
	gate.arm()
	go func() {
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			// Read everything, so only the gate (not the socket buffers)
			// holds the server back.
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	select {
	case <-gate.blocked:
	case <-time.After(15 * time.Second):
		t.Fatalf("the server never blocked writing the first delivery (still armed: %v)", gate.armed.Load())
	}
}

// Round 3, finding 8: the old session releases its delivery only when its
// blocked write times out; the new session must wait for that and get the
// held delivery first. Removing the eviction wait makes it get the next one.
func TestWebhookStream_EvictionKeepsOrder(t *testing.T) {
	a, h, secret := newLargeWebhookTestAPI(t)
	a.webhooks.writeTimeout = time.Second
	sess := adminSession()
	var gate *gateListener
	srv, waitExited := streamTestServerOn(t, a, sess, func(l net.Listener) net.Listener {
		gate = newGateListener(l, 1<<20)
		return gate
	})
	postDelivery(t, h, secret, "release", "d-ord-big", `{"b":"`+strings.Repeat("x", 16<<20)+`"}`)
	postDelivery(t, h, secret, "release", "d-ord-next", `{"n":2}`)
	url := srv.URL + "?from=all&durable=ca-order&ack=client&filter=github.webhooks.*.release.>"

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	holdLargeFrame(t, ctx, gate, url)
	before := ackCounter(t, "nak_evicted")
	evB := openStream(t, ctx, url)
	tokB := sessionToken(t, nextEvent(t, evB, 15*time.Second))
	first := nextEvent(t, evB, 15*time.Second)
	var env webhook.Envelope
	if err := json.Unmarshal([]byte(first.data), &env); err != nil {
		t.Fatal(err)
	}
	if env.Delivery != "d-ord-big" {
		t.Fatalf("new session's first delivery is %s (seq %d), want the held d-ord-big", env.Delivery, env.Sequence)
	}
	if d := ackCounter(t, "nak_evicted") - before; d != 1 {
		t.Errorf("nak_evicted delta %v, want 1", d)
	}
	if w := postAck(t, a, sess, ackBody(tokB, env.Sequence)); w.Code != http.StatusOK {
		t.Fatalf("ack: %d", w.Code)
	}
	cancel()
	waitExited(t)
}

// Round 3, finding 3: a takeover that cuts a large frame part way still
// delivers a parseable evicted event naming who took over.
func TestWebhookStream_EvictedAfterPartialFrame(t *testing.T) {
	a, h, secret := newLargeWebhookTestAPI(t)
	sess := adminSession()
	srv, waitExited := streamTestServer(t, a, sess)
	postDelivery(t, h, secret, "push", "d-partial", `{"b":"`+strings.Repeat("x", 16<<20)+`"}`)
	url := srv.URL + "?from=all&durable=ca-partial&ack=client&raw=1"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got bytes.Buffer
	buf := make([]byte, 64<<10)
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		n, _ := resp.Body.Read(buf)
		got.Write(buf[:n])
		time.Sleep(20 * time.Millisecond) // slow: the server stays mid-frame
	}
	go func() {
		r2, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		if resp2, err := http.DefaultClient.Do(r2); err == nil {
			defer resp2.Body.Close()
			_, _ = io.Copy(io.Discard, resp2.Body)
		}
	}()
	_, _ = io.Copy(&got, resp.Body)
	out := got.String()
	i := strings.Index(out, "event: evicted")
	if i < 0 {
		t.Fatalf("no evicted event after %d bytes", len(out))
	}
	if !strings.HasSuffix(out[:i], "\n\n") {
		t.Errorf("evicted event glued to the cut frame: %q", out[max(0, i-20):i])
	}
	if i > len(`{"b":"`)+16<<20 {
		t.Errorf("the frame was not cut (evicted at byte %d)", i)
	}
	if !strings.Contains(out[i:], `"by":"admin"`) {
		t.Errorf("evicted event does not name who took over: %q", out[i:])
	}
	cancel()
	waitExited(t)
}

// Round 3, finding 4: a session evicted while it waits in open() answers
// with an evicted event, not a 500, and the newest session then streams.
func TestWebhookStream_EvictedWhileOpening(t *testing.T) {
	a, h, secret := newWebhookTestAPI(t)
	a.webhooks.writeTimeout = 10 * time.Second // eviction wait: 25 s
	sess := adminSession()
	srv, waitExited := streamTestServer(t, a, sess)
	postDelivery(t, h, secret, "release", "d-open", `{"n":1}`)
	url := srv.URL + "?from=all&durable=ca-opening&ack=client&filter=github.webhooks.*.release.>"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// A never lets go on its own (a stream stuck in a write), so B stays in
	// open() until C evicts it.
	tokA, sA, err := a.webhooks.acks.open(context.Background(), sess.UserID, "admin", "ca-opening", func() {}, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	type result struct {
		status int
		header string
		body   string
	}
	bres := make(chan result, 1)
	go func() { // B: waits in open() for A
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			bres <- result{body: err.Error()}
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		bres <- result{resp.StatusCode, resp.Header.Get("GHP-Webhook-Client-Ack"), string(b)}
	}()
	// B has registered itself (and so is waiting in open() for A).
	waitFor(t, func() bool { s := durableSession(a, "ca-opening"); return s != nil && s != sA }, "B to wait in open()")
	// C evicts B while B is still opening. C's response starts only once
	// B and, through B, A have finished, so it is opened in the background.
	type cResult struct {
		resp *http.Response
		err  error
	}
	cres := make(chan cResult, 1)
	go func() {
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		resp, err := http.DefaultClient.Do(req)
		cres <- cResult{resp, err}
	}()
	select {
	case r := <-bres:
		if r.status != http.StatusOK || r.header != "1" || !strings.Contains(r.body, "event: evicted") || strings.Contains(r.body, "event: session") {
			t.Errorf("B answered %d header %q body %q, want an evicted-only stream", r.status, r.header, r.body)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("B did not answer")
	}
	// C waits for B, and B's session for A; A now finishes.
	a.webhooks.acks.close(tokA, sA)
	var c cResult
	select {
	case c = <-cres:
	case <-time.After(20 * time.Second):
		t.Fatal("C did not start streaming after A finished")
	}
	if c.err != nil || c.resp.StatusCode != http.StatusOK {
		t.Fatalf("C: %v %v", c.err, c.resp)
	}
	defer c.resp.Body.Close()
	evC := sseEvents(c.resp.Body)
	tokC := sessionToken(t, nextEvent(t, evC, 20*time.Second))
	var env webhook.Envelope
	if err := json.Unmarshal([]byte(nextEvent(t, evC, 20*time.Second).data), &env); err != nil {
		t.Fatal(err)
	}
	if env.Delivery != "d-open" {
		t.Errorf("C's first delivery is %s, want d-open", env.Delivery)
	}
	if w := postAck(t, a, sess, ackBody(tokC, env.Sequence)); w.Code != http.StatusOK {
		t.Errorf("ack: %d", w.Code)
	}
	cancel()
	waitExited(t)
}

// A new client that goes away while it waits in open() for the session it
// evicted releases its handler at once, not after the eviction wait. Its
// session still counts as finished only once the evicted one has, so a
// third client keeps the order.
func TestWebhookStream_ClientGoneWhileWaitingForEviction(t *testing.T) {
	a, _, _ := newWebhookTestAPI(t)
	a.webhooks.writeTimeout = 10 * time.Second // eviction wait: 25 s
	sess := adminSession()
	srv, waitExited := streamTestServer(t, a, sess)
	// The old session never lets go on its own: it stands for a stream
	// stuck in a write.
	tokOld, sOld, err := a.webhooks.acks.open(context.Background(), sess.UserID, "admin", "ca-gone", func() {}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctxB, cancelB := context.WithCancel(ctx)
	bDone := make(chan struct{})
	go func() {
		defer close(bDone)
		req, _ := http.NewRequestWithContext(ctxB, "GET", srv.URL+"?durable=ca-gone&ack=client", nil)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	var sB *streamAckSession
	waitFor(t, func() bool { sB = durableSession(a, "ca-gone"); return sB != nil && sB != sOld }, "B to wait in open()")
	if !sOld.evicted.Load() {
		t.Fatal("B did not evict the old session")
	}
	start := time.Now()
	cancelB()
	// B's handler closes its session when it returns; only the old one is
	// left open.
	waitFor(t, func() bool { return sessionCount(a) == 1 }, "B's handler to return")
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("B's handler returned %s after its client left; it waited for the eviction", el)
	}
	<-bDone
	select {
	case <-sB.done:
		t.Fatal("B's session finished before the session it evicted")
	default:
	}
	// B still owns the durable until the session it evicted lets go, so a
	// third client waits for it.
	if durableSession(a, "ca-gone") != sB {
		t.Fatal("B gave up the durable before the session it evicted finished")
	}
	a.webhooks.acks.close(tokOld, sOld)
	select {
	case <-sB.done:
	case <-time.After(5 * time.Second):
		t.Fatal("B's session did not finish after the evicted one did")
	}
	if durableSession(a, "ca-gone") != nil {
		t.Error("B's session still owns the durable after it finished")
	}
	cancel()
	waitExited(t)
}

// A holds delivery N; B evicts A, and B's client leaves while B still
// waits for A; C connects while A still holds N. C must wait for A too and
// receive N first.
func TestWebhookStream_EvictorLeavesEarlyKeepsOrder(t *testing.T) {
	a, h, secret := newLargeWebhookTestAPI(t)
	a.webhooks.writeTimeout = 3 * time.Second // A holds N this long once blocked
	sess := adminSession()
	var gate *gateListener
	srv, waitExited := streamTestServerOn(t, a, sess, func(l net.Listener) net.Listener {
		gate = newGateListener(l, 1<<20)
		return gate
	})
	postDelivery(t, h, secret, "release", "d-abc-big", `{"b":"`+strings.Repeat("x", 16<<20)+`"}`)
	postDelivery(t, h, secret, "release", "d-abc-next", `{"n":2}`)
	url := srv.URL + "?from=all&durable=ca-abc&ack=client&filter=github.webhooks.*.release.>"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	holdLargeFrame(t, ctx, gate, url) // A, blocked mid-frame holding N
	sA := durableSession(a, "ca-abc")
	ctxB, cancelB := context.WithCancel(ctx)
	bDone := make(chan struct{})
	go func() {
		defer close(bDone)
		req, _ := http.NewRequestWithContext(ctxB, "GET", url, nil)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	waitFor(t, func() bool { s := durableSession(a, "ca-abc"); return s != nil && s != sA }, "B to wait in open()")
	cancelB()
	<-bDone
	waitFor(t, func() bool { return sessionCount(a) == 1 }, "B's handler to return")
	select {
	case <-sA.done:
		t.Fatal("A let go before C connected; the test did not exercise the race")
	default:
	}

	evC := openStream(t, ctx, url)
	tokC := sessionToken(t, nextEvent(t, evC, 20*time.Second))
	var env webhook.Envelope
	if err := json.Unmarshal([]byte(nextEvent(t, evC, 20*time.Second).data), &env); err != nil {
		t.Fatal(err)
	}
	if env.Delivery != "d-abc-big" {
		t.Fatalf("C's first delivery is %s (seq %d), want the held d-abc-big", env.Delivery, env.Sequence)
	}
	if w := postAck(t, a, sess, ackBody(tokC, env.Sequence)); w.Code != http.StatusOK {
		t.Fatalf("ack: %d", w.Code)
	}
	cancel()
	waitExited(t)
}

// Round 3, finding 5: a 409 says whether the delivery was acked or released.
func TestWebhookStreamAck_ConflictCodes(t *testing.T) {
	a, h, secret := newWebhookTestAPI(t)
	sess := adminSession()
	srv, waitExited := streamTestServer(t, a, sess)
	code := func(w *httptest.ResponseRecorder) string {
		var m struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return m.Code
	}
	postDelivery(t, h, secret, "label", "d-409-a", `{}`)
	postDelivery(t, h, secret, "label", "d-409-b", `{}`)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	events := openStream(t, ctx, srv.URL+"?from=all&durable=ca-409&ack=client&filter=github.webhooks.*.label.>")
	token := sessionToken(t, nextEvent(t, events, 5*time.Second))
	seq := envSeq(t, nextEvent(t, events, 5*time.Second))
	if w := postAck(t, a, sess, ackBody(token, seq+5)); w.Code != http.StatusConflict || code(w) != "wrong_sequence" {
		t.Errorf("unknown seq: %d %s", w.Code, w.Body.String())
	}
	if w := postAck(t, a, sess, ackBody(token, seq)); w.Code != http.StatusOK {
		t.Fatalf("ack: %d", w.Code)
	}
	if w := postAck(t, a, sess, ackBody(token, seq)); w.Code != http.StatusConflict || code(w) != "acked" {
		t.Errorf("repeat ack: %d %s, want 409 acked", w.Code, w.Body.String())
	}
	// The next delivery is released while the session is still registered
	// (as when a heartbeat write fails): a late ack is told so.
	next := envSeq(t, nextEvent(t, events, 5*time.Second))
	s := a.webhooks.acks.lookup(token, sess.UserID)
	a.nakPending(s, next)
	if w := postAck(t, a, sess, ackBody(token, next)); w.Code != http.StatusConflict || code(w) != "released" {
		t.Errorf("released: %d %s, want 409 released", w.Code, w.Body.String())
	}
	cancel()
	waitExited(t)
}

func TestWebhookStream_CapabilityHeaderOnStream(t *testing.T) {
	a, _, _ := newWebhookTestAPI(t)
	srv, waitExited := streamTestServer(t, a, adminSession())
	for _, q := range []string{"", "?durable=cap&ack=client"} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+q, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Header.Get("GHP-Webhook-Client-Ack") != "1" {
			t.Errorf("%q: stream response without the capability header", q)
		}
		resp.Body.Close()
		cancel()
	}
	waitExited(t)
}

// slowBodyTransport throttles stream response bodies, so a relay stays in
// the middle of a large frame for a while, and counts the bytes read.
type slowBodyTransport struct{ read *atomic.Int64 }

func (tr slowBodyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err == nil && strings.HasSuffix(r.URL.Path, "/stream") {
		resp.Body = &slowBody{ReadCloser: resp.Body, read: tr.read}
	}
	return resp, err
}

type slowBody struct {
	io.ReadCloser
	read *atomic.Int64
}

func (b *slowBody) Read(p []byte) (int, error) {
	time.Sleep(10 * time.Millisecond)
	n, err := b.ReadCloser.Read(p[:min(len(p), 32<<10)])
	b.read.Add(int64(n))
	return n, err
}

// ackedOn reports whether the session that owns durable has recorded the
// acknowledgement of seq. After that the server never redelivers seq.
func ackedOn(a *API, durable string, seq uint64) bool {
	s := durableSession(a, durable)
	return s != nil && !s.hasPending() && s.resolution(seq) == webhook.AckCodeAcked
}

// Two relays on one durable: the newer one takes over, the older one stops
// for good instead of evicting it back, and nothing is posted twice.
func TestRelay_TakeoverStopsTheOldRelay(t *testing.T) {
	a, h, secret := newWebhookTestAPI(t)
	sess := adminSession()
	withSession := func(fn http.HandlerFunc) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fn(w, r.WithContext(auth.NewContextWithSession(r.Context(), sess)))
		})
	}
	mux := http.NewServeMux()
	mux.Handle("GET /api/webhooks/status", withSession(a.handleWebhookStatus))
	mux.Handle("GET /api/webhooks/stream", withSession(a.handleWebhookStream))
	mux.Handle("POST /api/webhooks/stream/ack", withSession(a.handleWebhookStreamAck))
	ghp := httptest.NewServer(mux)
	defer ghp.Close()

	var mu sync.Mutex
	seen := map[string]int{}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Header.Get("X-GitHub-Delivery")]++
		mu.Unlock()
	}))
	defer target.Close()
	opts := relay.Options{
		ServerURL: ghp.URL, Token: "ghpr_test", Target: target.URL, Durable: "shared", From: "all",
		Backoff: 10 * time.Millisecond, ReconnectDelay: 50 * time.Millisecond,
	}

	postDelivery(t, h, secret, "issues", "d-to-0", `{"n":0}`)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var logA, logB syncLog
	errA := make(chan error, 1)
	go func() { errA <- relay.Run(ctx, opts, &logA) }()
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return seen["d-to-0"] == 1 }, "relay A to relay d-to-0")
	waitFor(t, func() bool { return ackedOn(a, "shared", 1) }, "the server to record A's ack of d-to-0")

	doneB := make(chan error, 1)
	go func() { doneB <- relay.Run(ctx, opts, &logB) }()
	select {
	case err := <-errA:
		if !errors.Is(err, relay.ErrTakenOver) || !strings.Contains(err.Error(), "durable shared was taken over by another relay") {
			t.Errorf("relay A returned %v, want ErrTakenOver", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("relay A kept running after the takeover\n%s", logA.String())
	}
	for i := 1; i <= 3; i++ {
		postDelivery(t, h, secret, "issues", fmt.Sprintf("d-to-%d", i), fmt.Sprintf(`{"n":%d}`, i))
	}
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return seen["d-to-3"] == 1 }, "relay B to relay d-to-3")
	waitFor(t, func() bool { return ackedOn(a, "shared", 4) }, "the server to record B's ack of d-to-3")
	select {
	case err := <-doneB:
		t.Fatalf("relay B stopped: %v\n%s", err, logB.String())
	default:
	}
	mu.Lock()
	for d, n := range seen {
		if n != 1 {
			t.Errorf("%s reached the target %d times", d, n)
		}
	}
	if len(seen) != 4 {
		t.Errorf("target saw %d deliveries, want 4: %v", len(seen), seen)
	}
	mu.Unlock()
	cancel()
	<-doneB
}

type syncLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncLog) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncLog) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// A takeover that cuts relay A in the middle of a large frame still stops
// A with ErrTakenOver, and the delivery reaches the target once, from B.
func TestRelay_TakeoverMidFrame(t *testing.T) {
	a, h, secret := newLargeWebhookTestAPI(t)
	sess := adminSession()
	withSession := func(fn http.HandlerFunc) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fn(w, r.WithContext(auth.NewContextWithSession(r.Context(), sess)))
		})
	}
	mux := http.NewServeMux()
	mux.Handle("GET /api/webhooks/status", withSession(a.handleWebhookStatus))
	mux.Handle("GET /api/webhooks/stream", withSession(a.handleWebhookStream))
	mux.Handle("POST /api/webhooks/stream/ack", withSession(a.handleWebhookStreamAck))
	ghp := httptest.NewServer(mux)
	defer ghp.Close()

	var mu sync.Mutex
	seen := map[string]int{}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		seen[r.Header.Get("X-GitHub-Delivery")]++
		mu.Unlock()
	}))
	defer target.Close()
	postDelivery(t, h, secret, "issues", "d-mid", `{"b":"`+strings.Repeat("<>&", (12<<20)/3)+`"}`)

	opts := relay.Options{
		ServerURL: ghp.URL, Token: "ghpr_test", Target: target.URL, Durable: "mid", From: "all",
		Backoff: 10 * time.Millisecond, ReconnectDelay: 50 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	slow := opts
	var readA atomic.Int64
	slow.Client = &http.Client{Transport: slowBodyTransport{read: &readA}}
	var logA, logB syncLog
	errA := make(chan error, 1)
	go func() { errA <- relay.Run(ctx, slow, &logA) }()
	// A is part way through the 16 MiB frame: the server holds d-mid and A
	// has read some of it.
	waitFor(t, func() bool {
		s := durableSession(a, "mid")
		return s != nil && s.hasPending() && readA.Load() > 1<<20
	}, "relay A to be part way through the frame")
	if readA.Load() > 12<<20 {
		t.Fatal("relay A read almost the whole frame before the takeover; slow it down")
	}
	doneB := make(chan error, 1)
	go func() { doneB <- relay.Run(ctx, opts, &logB) }()
	select {
	case err := <-errA:
		if !errors.Is(err, relay.ErrTakenOver) || !strings.Contains(err.Error(), "admin") {
			t.Errorf("relay A returned %v, want ErrTakenOver naming admin\n%s", err, logA.String())
		}
		if strings.Contains(logA.String(), "reconnecting") {
			t.Errorf("relay A claimed it would reconnect:\n%s", logA.String())
		}
	case <-time.After(45 * time.Second):
		t.Fatalf("relay A kept running after the takeover\n%s", logA.String())
	}
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return seen["d-mid"] == 1 }, "relay B to relay d-mid")
	waitFor(t, func() bool { return ackedOn(a, "mid", 1) }, "the server to record B's ack of d-mid")
	mu.Lock()
	if seen["d-mid"] != 1 {
		t.Errorf("d-mid reached the target %d times", seen["d-mid"])
	}
	mu.Unlock()
	cancel()
	<-doneB
}
