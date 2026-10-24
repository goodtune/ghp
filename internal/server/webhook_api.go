package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/webhook"
)

// webhookService bundles the running webhook ingress components the admin
// API exposes: the JetStream bus, the secret resolver (so app mutations can
// invalidate it) and the optional ngrok tunnel.
type webhookService struct {
	cfg     config.WebhooksConfig
	bus     *webhook.Bus
	secrets *webhook.StoreSecretSource
	baseURL string

	mu     sync.RWMutex
	tunnel *webhook.Tunnel
}

func newWebhookService(cfg config.WebhooksConfig, bus *webhook.Bus, secrets *webhook.StoreSecretSource, baseURL string) *webhookService {
	return &webhookService{cfg: cfg, bus: bus, secrets: secrets, baseURL: baseURL}
}

func (s *webhookService) setTunnel(t *webhook.Tunnel) {
	s.mu.Lock()
	s.tunnel = t
	s.mu.Unlock()
}

// tunnelURL returns the public ngrok endpoint URL, or "" when no tunnel is
// connected.
func (s *webhookService) tunnelURL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tunnel.URL()
}

// IngressURL is the absolute URL operators paste into the GitHub App's
// webhook settings: the ngrok endpoint when a tunnel is up, otherwise the
// configured server.base_url, each joined with the ingress path. Empty when
// neither is known.
func (s *webhookService) IngressURL() string {
	if u := s.tunnelURL(); u != "" {
		return strings.TrimSuffix(u, "/") + s.cfg.Path
	}
	if s.baseURL != "" {
		return strings.TrimSuffix(s.baseURL, "/") + s.cfg.Path
	}
	return ""
}

// SetWebhooks wires the webhook service into the API. A nil service leaves
// the endpoints reporting the feature as disabled.
func (a *API) SetWebhooks(ws *webhookService) {
	a.webhooks = ws
}

func (a *API) invalidateWebhookSecrets() {
	if a.webhooks != nil && a.webhooks.secrets != nil {
		a.webhooks.secrets.Invalidate()
	}
}

// webhookDisabled writes the standard 404 for webhook endpoints when the
// feature is off and reports whether it did so.
func (a *API) webhookDisabled(w http.ResponseWriter) bool {
	if a.webhooks == nil || a.webhooks.bus == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "Webhooks are not enabled on this server"})
		return true
	}
	return false
}

type webhookStatusApp struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	GitHubAppID      int64  `json:"github_app_id"`
	HasWebhookSecret bool   `json:"has_webhook_secret"`
}

type webhookStatusResponse struct {
	Enabled      bool   `json:"enabled"`
	IngressPath  string `json:"ingress_path,omitempty"`
	IngressURL   string `json:"ingress_url,omitempty"`
	GlobalSecret bool   `json:"global_secret_configured"`
	Ngrok        struct {
		Enabled   bool   `json:"enabled"`
		Connected bool   `json:"connected"`
		URL       string `json:"url,omitempty"`
		Domain    string `json:"domain,omitempty"`
	} `json:"ngrok"`
	NATS struct {
		Listen        string `json:"listen,omitempty"`
		ClientURL     string `json:"client_url,omitempty"`
		AuthRequired  bool   `json:"auth_required"`
		Clients       int    `json:"clients"`
		Stream        string `json:"stream"`
		SubjectPrefix string `json:"subject_prefix"`
	} `json:"nats"`
	Stream struct {
		Messages  uint64     `json:"messages"`
		Bytes     uint64     `json:"bytes"`
		FirstSeq  uint64     `json:"first_seq"`
		LastSeq   uint64     `json:"last_seq"`
		FirstTime *time.Time `json:"first_time,omitempty"`
		LastTime  *time.Time `json:"last_time,omitempty"`
		Consumers int        `json:"consumers"`
		MaxAge    string     `json:"max_age"`
		MaxBytes  int64      `json:"max_bytes"`
	} `json:"stream"`
	Apps []webhookStatusApp `json:"apps"`
}

// handleWebhookStatus reports the ingress configuration, public URL, stream
// statistics, and which apps have a webhook secret. Always 200 so the admin
// UI can decide whether to show the panel; enabled=false when the feature is
// off.
func (a *API) handleWebhookStatus(w http.ResponseWriter, r *http.Request) {
	resp := webhookStatusResponse{Apps: make([]webhookStatusApp, 0)}
	if a.webhooks == nil || a.webhooks.bus == nil {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	ws := a.webhooks
	resp.Enabled = true
	resp.IngressPath = ws.cfg.Path
	resp.IngressURL = ws.IngressURL()
	resp.GlobalSecret = ws.cfg.Secret != ""
	resp.Ngrok.Enabled = ws.cfg.Ngrok.Enabled
	resp.Ngrok.Domain = ws.cfg.Ngrok.Domain
	resp.Ngrok.URL = ws.tunnelURL()
	resp.Ngrok.Connected = resp.Ngrok.URL != ""
	resp.NATS.Listen = ws.bus.ListenAddr()
	resp.NATS.ClientURL = ws.bus.ClientURL()
	resp.NATS.AuthRequired = ws.cfg.NATS.AuthToken != ""
	resp.NATS.Clients = ws.bus.NumClients()
	resp.NATS.Stream = ws.bus.StreamName()
	resp.NATS.SubjectPrefix = ws.bus.SubjectPrefix()
	resp.Stream.MaxAge = ws.cfg.NATS.MaxAge.String()
	resp.Stream.MaxBytes = ws.cfg.NATS.MaxBytes

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if info, err := ws.bus.Info(ctx); err == nil {
		st := info.State
		resp.Stream.Messages = st.Msgs
		resp.Stream.Bytes = st.Bytes
		resp.Stream.FirstSeq = st.FirstSeq
		resp.Stream.LastSeq = st.LastSeq
		resp.Stream.Consumers = st.Consumers
		if st.Msgs > 0 {
			ft, lt := st.FirstTime, st.LastTime
			resp.Stream.FirstTime = &ft
			resp.Stream.LastTime = &lt
		}
	} else {
		a.logger.Warn("webhook_stream_info_failed", "error", err)
	}

	if a.store != nil {
		apps, err := a.store.ListApps(ctx)
		if err != nil {
			a.logger.Error("failed to list apps for webhook status", "error", err)
		}
		for _, app := range apps {
			resp.Apps = append(resp.Apps, webhookStatusApp{
				ID: app.ID, Name: app.Name, GitHubAppID: app.AppID, HasWebhookSecret: app.WebhookSecret != "",
			})
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

const (
	webhookDeliveriesDefaultLimit = 50
	webhookDeliveriesMaxLimit     = 200
)

// handleWebhookDeliveries lists the most recent deliveries (newest first,
// headers only).
func (a *API) handleWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	if a.webhookDisabled(w) {
		return
	}
	limit := webhookDeliveriesDefaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "limit must be a positive integer"})
			return
		}
		if n > webhookDeliveriesMaxLimit {
			n = webhookDeliveriesMaxLimit
		}
		limit = n
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	list, err := a.webhooks.bus.Recent(ctx, limit)
	if err != nil {
		a.logger.Error("webhook_recent_failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to read deliveries"})
		return
	}
	if list == nil {
		list = []*webhook.Envelope{}
	}
	writeJSON(w, http.StatusOK, list)
}

// handleWebhookDelivery returns one stored delivery, including its payload.
func (a *API) handleWebhookDelivery(w http.ResponseWriter, r *http.Request) {
	if a.webhookDisabled(w) {
		return
	}
	seq, err := strconv.ParseUint(r.PathValue("seq"), 10, 64)
	if err != nil || seq == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid sequence number"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	env, err := a.webhooks.bus.Get(ctx, seq)
	if err != nil {
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "Delivery not found"})
			return
		}
		a.logger.Error("webhook_get_failed", "seq", seq, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to read delivery"})
		return
	}
	writeJSON(w, http.StatusOK, env)
}

const (
	sseHeartbeat    = 15 * time.Second
	maxDurableName  = 64
	sseRetryMillis  = 3000
	sseFlushTimeout = 10 * time.Second
)

// parseStreamOptions turns the query parameters of GET /api/webhooks/stream
// (and the Last-Event-ID header) into SubscribeOptions.
func parseStreamOptions(r *http.Request, prefix string) (webhook.SubscribeOptions, error) {
	q := r.URL.Query()
	opts := webhook.SubscribeOptions{Filter: strings.TrimSpace(q.Get("filter"))}
	if opts.Filter != "" && !webhook.ValidFilter(prefix, opts.Filter) {
		return opts, fmt.Errorf("filter must be a NATS subject filter under %q", prefix)
	}
	switch from := strings.TrimSpace(q.Get("from")); from {
	case "", "new":
	case "all":
		opts.FromStart = true
	default:
		seq, err := strconv.ParseUint(from, 10, 64)
		if err != nil || seq == 0 {
			return opts, errors.New("from must be \"new\", \"all\", or a positive sequence number")
		}
		opts.StartSeq = seq
	}
	if last := strings.TrimSpace(r.Header.Get("Last-Event-ID")); last != "" {
		seq, err := strconv.ParseUint(last, 10, 64)
		if err != nil {
			return opts, errors.New("Last-Event-ID must be a sequence number")
		}
		opts.StartSeq = seq + 1
		opts.FromStart = false
	}
	if d := strings.TrimSpace(q.Get("durable")); d != "" {
		if len(d) > maxDurableName {
			return opts, fmt.Errorf("durable name must be at most %d characters", maxDurableName)
		}
		opts.Durable = d
	}
	return opts, nil
}

// handleWebhookStream streams deliveries as server-sent events. Each event
// carries id=<stream sequence>, event=<GitHub event name>, and the JSON
// Envelope as data. Clients reconnecting with Last-Event-ID resume after the
// last sequence they saw; the durable query parameter gives the same
// guarantee server-side via a named JetStream consumer.
func (a *API) handleWebhookStream(w http.ResponseWriter, r *http.Request) {
	if a.webhookDisabled(w) {
		return
	}
	opts, err := parseStreamOptions(r, a.webhooks.bus.SubjectPrefix())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}
	rc := http.NewResponseController(w)

	ctx := r.Context()
	sub, err := a.webhooks.bus.Subscribe(ctx, opts)
	if err != nil {
		a.logger.Error("webhook_subscribe_failed", "error", err, "filter", opts.Filter, "durable", opts.Durable)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to subscribe"})
		return
	}
	defer sub.Close()

	gauge := metrics.WebhookSubscribersActive.WithLabelValues("sse")
	gauge.Inc()
	defer gauge.Dec()

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "retry: %d\n\n: connected filter=%s\n\n", sseRetryMillis, opts.Filter)
	_ = rc.Flush()

	for {
		nctx, cancel := context.WithTimeout(ctx, sseHeartbeat)
		env, msg, err := sub.Next(nctx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return // client went away or server shutting down
			}
			if errors.Is(err, context.DeadlineExceeded) {
				if _, werr := fmt.Fprint(w, ": ping\n\n"); werr != nil {
					return
				}
				if ferr := rc.Flush(); ferr != nil {
					return
				}
				continue
			}
			a.logger.Warn("webhook_stream_next_failed", "error", err)
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", jsonString(err.Error()))
			_ = rc.Flush()
			return
		}
		data, merr := json.Marshal(env)
		if merr != nil {
			_ = sub.Nak(msg)
			continue
		}
		if _, werr := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", env.Sequence, sseEventName(env.Event), data); werr != nil {
			_ = sub.Nak(msg)
			return
		}
		if ferr := rc.Flush(); ferr != nil {
			_ = sub.Nak(msg)
			return
		}
		// Only acknowledge after the bytes have been handed to the client.
		if aerr := sub.Ack(msg); aerr != nil {
			a.logger.Warn("webhook_stream_ack_failed", "seq", env.Sequence, "error", aerr)
		}
	}
}

// sseEventName keeps the SSE event field to a single safe token.
func sseEventName(event string) string {
	if event == "" {
		return "webhook"
	}
	return webhook.SanitizeToken(event)
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// appHasWebhookSecret is a small helper shared by the app responses.
func appHasWebhookSecret(app *database.App) bool {
	return app != nil && app.WebhookSecret != ""
}
