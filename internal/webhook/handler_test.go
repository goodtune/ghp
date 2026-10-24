package webhook

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"

	"github.com/goodtune/ghp/internal/metrics"
)

const prPayload = `{"action":"opened","number":7,"repository":{"name":"ghp","owner":{"login":"goodtune"}},"installation":{"id":424242},"sender":{"login":"octocat"}}`

func counterValue(t *testing.T, event, result string) float64 {
	t.Helper()
	var m io_prometheus_client.Metric
	c, err := metrics.WebhookReceivedTotal.GetMetricWith(prometheus.Labels{"event": event, "result": result})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.(prometheus.Metric).Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

func newTestHandler(t *testing.T, src SecretSource) (*Handler, *Bus) {
	t.Helper()
	b := newTestBus(t)
	h := NewHandler(b, src, 1<<20, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return h, b
}

func deliveryRequest(t *testing.T, body, event, delivery, contentType string, secret []byte, extra map[string]string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set(HeaderEvent, event)
	req.Header.Set(HeaderDelivery, delivery)
	if secret != nil {
		req.Header.Set(HeaderSignature256, Sign(secret, []byte(body)))
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	return req
}

func TestHandler_PublishesVerifiedDelivery(t *testing.T) {
	appSecret := []byte("app-secret")
	src := StaticSecretSource{{AppRecordID: "app-uuid", GitHubAppID: 111, AppName: "My App", Secret: appSecret}}
	h, b := newTestHandler(t, src)

	before := counterValue(t, "pull_request", "published")
	req := deliveryRequest(t, prPayload, "pull_request", "deliv-1", "application/json", appSecret, map[string]string{
		HeaderHookID:                 "555",
		HeaderInstallationTargetType: TargetTypeIntegration,
		HeaderInstallationTargetID:   "111",
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	wantSubject := "github.webhooks.app-uuid.pull_request.opened.goodtune.ghp"
	if resp.Subject != wantSubject || resp.Sequence != 1 || resp.Duplicate || resp.Delivery != "deliv-1" || resp.Stream != b.StreamName() {
		t.Errorf("unexpected response: %+v", resp)
	}
	if got := counterValue(t, "pull_request", "published") - before; got != 1 {
		t.Errorf("published counter delta = %f, want 1", got)
	}

	env, err := b.Get(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if env.Event != "pull_request" || env.Action != "opened" || env.Repository != "goodtune/ghp" ||
		env.InstallationID != 424242 || env.Sender != "octocat" || env.AppRecordID != "app-uuid" ||
		env.AppName != "My App" || env.HookID != "555" || env.TargetType != "integration" || env.TargetID != "111" {
		t.Errorf("unexpected stored envelope: %+v", env)
	}
	if string(env.Payload) != prPayload {
		t.Errorf("payload altered: %s", env.Payload)
	}
	if env.ReceivedAt.IsZero() {
		t.Error("expected ReceivedAt")
	}
	if env.Headers[HdrContentType] != "application/json" || env.Headers[HdrOriginalContent] != "application/json" {
		t.Errorf("content-type headers: %+v", env.Headers)
	}
}

func TestHandler_DuplicateDelivery(t *testing.T) {
	secret := []byte("s")
	h, _ := newTestHandler(t, StaticSecretSource{{Secret: secret}})
	for i := 0; i < 2; i++ {
		req := deliveryRequest(t, `{"zen":"hi"}`, "ping", "dup-1", "application/json", secret, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusAccepted {
			t.Fatalf("attempt %d status = %d: %s", i, w.Code, w.Body.String())
		}
		var resp response
		_ = json.NewDecoder(w.Body).Decode(&resp)
		if i == 1 && !resp.Duplicate {
			t.Errorf("second delivery should be flagged duplicate: %+v", resp)
		}
		if resp.Subject != "github.webhooks._.ping._._._" {
			t.Errorf("subject = %q", resp.Subject)
		}
	}
}

func TestHandler_FormEncodedDelivery(t *testing.T) {
	secret := []byte("form-secret")
	h, b := newTestHandler(t, StaticSecretSource{{AppRecordID: "a", Secret: secret}})
	form := url.Values{"payload": {prPayload}}.Encode()
	req := deliveryRequest(t, form, "pull_request", "form-1", "application/x-www-form-urlencoded", secret, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	env, err := b.Get(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(env.Payload) != prPayload {
		t.Errorf("expected unwrapped JSON payload, got %s", env.Payload)
	}
	if env.Headers[HdrOriginalContent] != "application/x-www-form-urlencoded" {
		t.Errorf("original content type = %q", env.Headers[HdrOriginalContent])
	}

	// Form body without payload parameter.
	req = deliveryRequest(t, "foo=bar", "pull_request", "form-2", "application/x-www-form-urlencoded", secret, nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandler_Rejections(t *testing.T) {
	secret := []byte("right")
	tests := []struct {
		name       string
		src        SecretSource
		build      func(t *testing.T) *http.Request
		wantStatus int
		wantResult string
	}{
		{
			name: "wrong secret",
			src:  StaticSecretSource{{Secret: secret}},
			build: func(t *testing.T) *http.Request {
				return deliveryRequest(t, prPayload, "pull_request", "d", "application/json", []byte("wrong"), nil)
			},
			wantStatus: http.StatusUnauthorized, wantResult: "invalid_signature",
		},
		{
			name: "missing signature",
			src:  StaticSecretSource{{Secret: secret}},
			build: func(t *testing.T) *http.Request {
				return deliveryRequest(t, prPayload, "pull_request", "d", "application/json", nil, nil)
			},
			wantStatus: http.StatusUnauthorized, wantResult: "invalid_signature",
		},
		{
			name: "no candidate secrets",
			src:  StaticSecretSource{},
			build: func(t *testing.T) *http.Request {
				return deliveryRequest(t, prPayload, "pull_request", "d", "application/json", secret, nil)
			},
			wantStatus: http.StatusUnauthorized, wantResult: "unknown_app",
		},
		{
			name: "missing event header",
			src:  StaticSecretSource{{Secret: secret}},
			build: func(t *testing.T) *http.Request {
				r := deliveryRequest(t, prPayload, "", "d", "application/json", secret, nil)
				r.Header.Del(HeaderEvent)
				return r
			},
			wantStatus: http.StatusBadRequest, wantResult: "bad_request",
		},
		{
			name: "missing delivery header",
			src:  StaticSecretSource{{Secret: secret}},
			build: func(t *testing.T) *http.Request {
				r := deliveryRequest(t, prPayload, "push", "", "application/json", secret, nil)
				r.Header.Del(HeaderDelivery)
				return r
			},
			wantStatus: http.StatusBadRequest, wantResult: "bad_request",
		},
		{
			name: "oversized body",
			src:  StaticSecretSource{{Secret: secret}},
			build: func(t *testing.T) *http.Request {
				big := `{"pad":"` + strings.Repeat("x", 2<<20) + `"}`
				return deliveryRequest(t, big, "push", "d", "application/json", secret, nil)
			},
			wantStatus: http.StatusRequestEntityTooLarge, wantResult: "bad_request",
		},
		{
			name: "secret lookup error",
			src:  errSecretSource{},
			build: func(t *testing.T) *http.Request {
				return deliveryRequest(t, prPayload, "push", "d", "application/json", secret, nil)
			},
			wantStatus: http.StatusInternalServerError, wantResult: "internal_error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHandler(&fakePublisher{}, tt.src, 1<<20, slog.New(slog.NewTextHandler(io.Discard, nil)))
			req := tt.build(t)
			label := EventLabel(req.Header.Get(HeaderEvent))
			before := counterValue(t, label, tt.wantResult)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d: %s", w.Code, tt.wantStatus, w.Body.String())
			}
			if got := counterValue(t, label, tt.wantResult) - before; got != 1 {
				t.Errorf("%s counter delta = %f, want 1", tt.wantResult, got)
			}
		})
	}
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	h := NewHandler(&fakePublisher{}, StaticSecretSource{}, 0, nil)
	req := httptest.NewRequest(http.MethodGet, "/webhooks/github", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHandler_PublishError(t *testing.T) {
	secret := []byte("s")
	h := NewHandler(&fakePublisher{err: context.DeadlineExceeded}, StaticSecretSource{{Secret: secret}}, 0, nil)
	before := counterValue(t, "push", "publish_error")
	req := deliveryRequest(t, `{}`, "push", "d", "application/json", secret, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header")
	}
	if got := counterValue(t, "push", "publish_error") - before; got != 1 {
		t.Errorf("publish_error delta = %f", got)
	}
}

func TestHandler_TriesCandidatesInOrder(t *testing.T) {
	first := []byte("first")
	second := []byte("second")
	fp := &fakePublisher{}
	h := NewHandler(fp, StaticSecretSource{{AppRecordID: "one", Secret: first}, {AppRecordID: "two", Secret: second}}, 0, nil)
	req := deliveryRequest(t, prPayload, "push", "d", "application/json", second, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if !strings.HasPrefix(fp.lastSubject, "github.webhooks.two.") {
		t.Errorf("subject = %q, want app two", fp.lastSubject)
	}
}

func TestIngressMux(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) })
	mux := IngressMux("/webhooks/github", inner)
	tests := []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, "/webhooks/github", http.StatusAccepted},
		{http.MethodGet, "/webhooks/github", http.StatusMethodNotAllowed},
		{http.MethodPost, "/", http.StatusNotFound},
		{http.MethodGet, "/admin", http.StatusNotFound},
		{http.MethodPost, "/webhooks/github/extra", http.StatusNotFound},
	}
	for _, tt := range tests {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(tt.method, tt.path, nil))
		if w.Code != tt.want {
			t.Errorf("%s %s = %d, want %d", tt.method, tt.path, w.Code, tt.want)
		}
	}
}

func TestEventLabel(t *testing.T) {
	if EventLabel("pull_request") != "pull_request" {
		t.Error("known event should pass through")
	}
	if EventLabel("made_up") != "unknown" || EventLabel("") != "unknown" {
		t.Error("unknown events should normalise")
	}
}

// fakePublisher records the last publish and optionally fails.
type fakePublisher struct {
	err         error
	lastSubject string
}

func (f fakePublisher) SubjectPrefix() string { return "github.webhooks" }
func (f fakePublisher) StreamName() string    { return "TEST" }
func (f *fakePublisher) Publish(_ context.Context, subject string, _ nats.Header, _ []byte, _ string) (*jetstream.PubAck, error) {
	f.lastSubject = subject
	if f.err != nil {
		return nil, f.err
	}
	return &jetstream.PubAck{Stream: "TEST", Sequence: 1}, nil
}

type errSecretSource struct{}

func (errSecretSource) Candidates(context.Context, string, string) ([]Candidate, error) {
	return nil, context.Canceled
}

func TestHandler_EdgeCasePayloads(t *testing.T) {
	secret := []byte("s")
	tests := []struct {
		name        string
		body        string
		contentType string
		wantSubject string
	}{
		{"form content type with charset", url.Values{"payload": {prPayload}}.Encode(), "application/x-www-form-urlencoded; charset=utf-8", "github.webhooks._.pull_request.opened.goodtune.ghp"},
		{"non-object JSON payload", `[1,2,3]`, "application/json", "github.webhooks._.ping._._._"},
		{"empty body", ``, "application/json", "github.webhooks._.ping._._._"},
		{"payload with nested dots and spaces in names", `{"action":"re opened","repository":{"name":"a.b","owner":{"login":"o"}}}`, "application/json", "github.webhooks._.ping.re_opened.o.a_b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &fakePublisher{}
			h := NewHandler(fp, StaticSecretSource{{Secret: secret}}, 0, nil)
			event := "ping"
			if strings.Contains(tt.wantSubject, "pull_request") {
				event = "pull_request"
			}
			req := deliveryRequest(t, tt.body, event, "d", tt.contentType, secret, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusAccepted {
				t.Fatalf("status = %d: %s", w.Code, w.Body.String())
			}
			if fp.lastSubject != tt.wantSubject {
				t.Errorf("subject = %q, want %q", fp.lastSubject, tt.wantSubject)
			}
		})
	}
}
