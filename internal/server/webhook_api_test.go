package server

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/webhook"
)

// newWebhookTestAPI returns an API with a real SQLite store and a running
// in-process JetStream bus, plus the ingress handler bound to it.
func newWebhookTestAPI(t *testing.T) (*API, *webhook.Handler, []byte) {
	t.Helper()
	a := newTestAPIWithStore(t)
	a.encryptor = crypto.NewPassthroughEncryptor()

	cfg := config.Defaults().Webhooks
	cfg.Enabled = true
	cfg.NATS.StoreDir = t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	bus, err := webhook.NewBus(ctx, cfg.NATS, webhook.BusOptions{MaxPayloadBytes: 1 << 20}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewBus: %v", err)
	}
	t.Cleanup(bus.Close)

	secret := []byte("app-secret")
	app := &database.App{Name: "Hooked", AppID: 777, WebhookSecret: string(secret)}
	if err := a.store.CreateApp(context.Background(), app); err != nil {
		t.Fatal(err)
	}
	secrets := webhook.NewStoreSecretSource(a.store, a.encryptor, "", a.logger)
	a.SetWebhooks(newWebhookService(cfg, bus, secrets, "https://ghp.example.com"))
	h := webhook.NewHandler(bus, secrets, cfg.MaxPayloadBytes, a.logger)
	return a, h, secret
}

func postDelivery(t *testing.T, h http.Handler, secret []byte, event, delivery, body string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(webhook.HeaderEvent, event)
	req.Header.Set(webhook.HeaderDelivery, delivery)
	req.Header.Set(webhook.HeaderInstallationTargetType, webhook.TargetTypeIntegration)
	req.Header.Set(webhook.HeaderInstallationTargetID, "777")
	req.Header.Set(webhook.HeaderSignature256, webhook.Sign(secret, []byte(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("delivery %s: status %d: %s", delivery, w.Code, w.Body.String())
	}
}

func TestWebhookEndpoints_Disabled(t *testing.T) {
	a := newTestAPIWithStore(t)
	ctx := auth.NewContextWithSession(context.Background(), adminSession())

	w := httptest.NewRecorder()
	a.handleWebhookStatus(w, httptest.NewRequest("GET", "/api/webhooks/status", nil).WithContext(ctx))
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	var st webhookStatusResponse
	if err := json.NewDecoder(w.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.Enabled {
		t.Error("expected enabled=false")
	}
	if st.Apps == nil {
		t.Error("apps must encode as [] not null")
	}

	for name, fn := range map[string]http.HandlerFunc{
		"deliveries": a.handleWebhookDeliveries,
		"delivery":   a.handleWebhookDelivery,
		"stream":     a.handleWebhookStream,
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/webhooks/x", nil).WithContext(ctx)
		req.SetPathValue("seq", "1")
		fn(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", name, w.Code)
		}
	}
}

func TestWebhookStatus_Enabled(t *testing.T) {
	a, h, secret := newWebhookTestAPI(t)
	postDelivery(t, h, secret, "ping", "d-1", `{"zen":"x"}`)

	w := httptest.NewRecorder()
	a.handleWebhookStatus(w, httptest.NewRequest("GET", "/api/webhooks/status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d: %s", w.Code, w.Body.String())
	}
	var st webhookStatusResponse
	if err := json.NewDecoder(w.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if !st.Enabled || st.IngressPath != "/webhooks/github" {
		t.Errorf("unexpected status: %+v", st)
	}
	if st.IngressURL != "https://ghp.example.com/webhooks/github" {
		t.Errorf("ingress_url = %q", st.IngressURL)
	}
	if st.Stream.Messages != 1 || st.Stream.LastSeq != 1 || st.Stream.FirstTime == nil {
		t.Errorf("stream stats: %+v", st.Stream)
	}
	if st.NATS.Stream != "GITHUB_WEBHOOKS" || st.NATS.SubjectPrefix != "github.webhooks" || st.NATS.Listen != "" {
		t.Errorf("nats: %+v", st.NATS)
	}
	if len(st.Apps) != 1 || !st.Apps[0].HasWebhookSecret || st.Apps[0].GitHubAppID != 777 {
		t.Errorf("apps: %+v", st.Apps)
	}
	if st.Ngrok.Connected || st.Ngrok.Enabled {
		t.Errorf("ngrok should be off: %+v", st.Ngrok)
	}
}

func TestWebhookDeliveries(t *testing.T) {
	a, h, secret := newWebhookTestAPI(t)

	// Empty list encodes as [].
	w := httptest.NewRecorder()
	a.handleWebhookDeliveries(w, httptest.NewRequest("GET", "/api/webhooks/deliveries", nil))
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("empty list: %d %s", w.Code, w.Body.String())
	}

	for i := 1; i <= 3; i++ {
		postDelivery(t, h, secret, "push", "d-"+seqLabel(i), `{"ref":"refs/heads/main","repository":{"name":"r","owner":{"login":"o"}}}`)
	}

	w = httptest.NewRecorder()
	a.handleWebhookDeliveries(w, httptest.NewRequest("GET", "/api/webhooks/deliveries?limit=2", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var list []webhook.Envelope
	if err := json.NewDecoder(w.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Sequence != 3 || list[1].Sequence != 2 {
		t.Errorf("unexpected list: %+v", list)
	}
	if list[0].Repository != "o/r" || list[0].AppName != "Hooked" || len(list[0].Payload) != 0 {
		t.Errorf("unexpected envelope: %+v", list[0])
	}

	w = httptest.NewRecorder()
	a.handleWebhookDeliveries(w, httptest.NewRequest("GET", "/api/webhooks/deliveries?limit=abc", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad limit: %d", w.Code)
	}

	// Single delivery with payload.
	req := httptest.NewRequest("GET", "/api/webhooks/deliveries/2", nil)
	req.SetPathValue("seq", "2")
	w = httptest.NewRecorder()
	a.handleWebhookDelivery(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get: %d %s", w.Code, w.Body.String())
	}
	var env webhook.Envelope
	if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if env.Sequence != 2 || env.Delivery != "d-2" || !strings.Contains(string(env.Payload), "refs/heads/main") {
		t.Errorf("unexpected delivery: %+v", env)
	}

	for _, seq := range []string{"0", "x", ""} {
		req := httptest.NewRequest("GET", "/api/webhooks/deliveries/"+seq, nil)
		req.SetPathValue("seq", seq)
		w = httptest.NewRecorder()
		a.handleWebhookDelivery(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("seq %q: status %d, want 400", seq, w.Code)
		}
	}
	req = httptest.NewRequest("GET", "/api/webhooks/deliveries/999", nil)
	req.SetPathValue("seq", "999")
	w = httptest.NewRecorder()
	a.handleWebhookDelivery(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("missing seq: status %d, want 404", w.Code)
	}
}

func seqLabel(i int) string { return string(rune('0' + i)) }

func TestParseStreamOptions(t *testing.T) {
	const prefix = "github.webhooks"
	mk := func(rawQuery, lastID string) *http.Request {
		r := httptest.NewRequest("GET", "/api/webhooks/stream?"+rawQuery, nil)
		if lastID != "" {
			r.Header.Set("Last-Event-ID", lastID)
		}
		return r
	}
	tests := []struct {
		name    string
		req     *http.Request
		want    webhook.SubscribeOptions
		wantErr bool
	}{
		{"defaults", mk("", ""), webhook.SubscribeOptions{}, false},
		{"all", mk("from=all", ""), webhook.SubscribeOptions{FromStart: true}, false},
		{"seq", mk("from=42", ""), webhook.SubscribeOptions{StartSeq: 42}, false},
		{"filter", mk("filter=github.webhooks.*.push.>", ""), webhook.SubscribeOptions{Filter: "github.webhooks.*.push.>"}, false},
		{"durable", mk("durable=my-cli", ""), webhook.SubscribeOptions{Durable: "my-cli"}, false},
		{"last event id wins", mk("from=all", "10"), webhook.SubscribeOptions{StartSeq: 11}, false},
		{"bad filter", mk("filter=other.>", ""), webhook.SubscribeOptions{}, true},
		{"bad from", mk("from=yesterday", ""), webhook.SubscribeOptions{}, true},
		{"zero from", mk("from=0", ""), webhook.SubscribeOptions{}, true},
		{"bad last id", mk("", "abc"), webhook.SubscribeOptions{}, true},
		{"durable too long", mk("durable="+strings.Repeat("x", 65), ""), webhook.SubscribeOptions{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseStreamOptions(tt.req, prefix)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// readSSE reads events from an SSE body until n data events are collected
// or the deadline passes.
func readSSE(t *testing.T, body io.Reader, n int) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for len(out) < n && sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "data: ") {
			var m map[string]any
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &m); err != nil {
				t.Fatalf("bad data line %q: %v", line, err)
			}
			out = append(out, m)
		}
	}
	return out
}

func TestWebhookStream_SSE(t *testing.T) {
	a, h, secret := newWebhookTestAPI(t)
	postDelivery(t, h, secret, "push", "d-1", `{"repository":{"name":"r","owner":{"login":"o"}}}`)
	postDelivery(t, h, secret, "pull_request", "d-2", `{"action":"opened","repository":{"name":"r","owner":{"login":"o"}}}`)

	srv := httptest.NewServer(http.HandlerFunc(a.handleWebhookStream))
	defer srv.Close()

	t.Run("replay from start with filter", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"?from=all&filter=github.webhooks.*.pull_request.>", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
			t.Fatalf("status %d content-type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		events := readSSE(t, resp.Body, 1)
		if len(events) != 1 || events[0]["delivery"] != "d-2" || events[0]["action"] != "opened" {
			t.Errorf("unexpected events: %+v", events)
		}
		if _, ok := events[0]["payload"].(map[string]any); !ok {
			t.Errorf("payload should be embedded JSON: %+v", events[0]["payload"])
		}
	})

	t.Run("new only receives later deliveries", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		// Read the preamble so the subscription is established, then publish.
		br := bufio.NewReader(resp.Body)
		if _, err := br.ReadString('\n'); err != nil {
			t.Fatal(err)
		}
		postDelivery(t, h, secret, "issues", "d-3", `{"action":"closed"}`)
		events := readSSE(t, br, 1)
		if len(events) != 1 || events[0]["delivery"] != "d-3" {
			t.Errorf("unexpected events: %+v", events)
		}
	})

	t.Run("Last-Event-ID resumes", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
		req.Header.Set("Last-Event-ID", "1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		events := readSSE(t, resp.Body, 2)
		if len(events) != 2 || events[0]["sequence"].(float64) != 2 || events[1]["sequence"].(float64) != 3 {
			t.Errorf("unexpected events: %+v", events)
		}
	})

	t.Run("durable resumes after disconnect", func(t *testing.T) {
		get := func(n int) []map[string]any {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"?durable=test-cli&from=all", nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			return readSSE(t, resp.Body, n)
		}
		first := get(1)
		if len(first) != 1 || first[0]["sequence"].(float64) != 1 {
			t.Fatalf("first: %+v", first)
		}
		// Give the server a moment to ack and tear down. The first handler
		// may have pulled (and possibly delivered) sequence 2 before the
		// client went away; either way the durable consumer must continue
		// past sequence 1 rather than replaying from the start.
		time.Sleep(200 * time.Millisecond)
		second := get(1)
		if len(second) != 1 || second[0]["sequence"].(float64) <= 1 {
			t.Errorf("durable did not resume: %+v", second)
		}
	})

	t.Run("invalid filter is 400", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "?filter=nope.>")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status %d, want 400", resp.StatusCode)
		}
	})
}

func TestWebhookService_IngressURL(t *testing.T) {
	cfg := config.Defaults().Webhooks
	svc := newWebhookService(cfg, nil, nil, "")
	if got := svc.IngressURL(); got != "" {
		t.Errorf("no base url: got %q", got)
	}
	svc = newWebhookService(cfg, nil, nil, "https://ghp.example.com/")
	if got := svc.IngressURL(); got != "https://ghp.example.com/webhooks/github" {
		t.Errorf("base url: got %q", got)
	}
}
