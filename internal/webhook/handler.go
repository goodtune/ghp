package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/goodtune/ghp/internal/metrics"
)

// Publisher is the subset of Bus the ingress handler depends on.
type Publisher interface {
	Publish(ctx context.Context, subject string, header nats.Header, data []byte, msgID string) (*jetstream.PubAck, error)
	SubjectPrefix() string
	StreamName() string
}

// Handler is the HTTP ingress for GitHub webhook deliveries.
type Handler struct {
	pub     Publisher
	secrets SecretSource
	maxBody int64
	logger  *slog.Logger
	// publishTimeout bounds the JetStream publish round trip.
	publishTimeout time.Duration
}

// NewHandler creates an ingress handler. maxBody caps the request body in
// bytes; GitHub never sends more than 25 MiB.
func NewHandler(pub Publisher, secrets SecretSource, maxBody int64, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	if maxBody <= 0 {
		maxBody = 25 * 1024 * 1024
	}
	return &Handler{pub: pub, secrets: secrets, maxBody: maxBody, logger: logger, publishTimeout: 10 * time.Second}
}

// IngressMux returns a handler that serves only POST requests to path with
// h and answers everything else with 404. It is what the ngrok tunnel serves,
// guaranteeing nothing but the webhook ingress is reachable publicly.
func IngressMux(path string, h http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST "+path, h)
	return mux
}

// response is the JSON body returned to GitHub (visible in the delivery log
// under "Response") so operators can see what ghp did with a delivery.
type response struct {
	Message   string `json:"message"`
	Delivery  string `json:"delivery,omitempty"`
	Stream    string `json:"stream,omitempty"`
	Sequence  uint64 `json:"sequence,omitempty"`
	Duplicate bool   `json:"duplicate,omitempty"`
	Subject   string `json:"subject,omitempty"`
}

// payloadMeta is the minimal projection of a webhook payload used for
// subject construction and message headers. Decoding failures are tolerated.
type payloadMeta struct {
	Action     string `json:"action"`
	Repository struct {
		Name  string `json:"name"`
		Owner struct {
			Login string `json:"login"`
		} `json:"owner"`
	} `json:"repository"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
	Sender struct {
		Login string `json:"login"`
	} `json:"sender"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, response{Message: "method not allowed"})
		return
	}

	event := strings.TrimSpace(r.Header.Get(HeaderEvent))
	delivery := strings.TrimSpace(r.Header.Get(HeaderDelivery))
	eventLabel := EventLabel(event)

	if event == "" || delivery == "" {
		h.reject(w, http.StatusBadRequest, eventLabel, "bad_request", "missing X-GitHub-Event or X-GitHub-Delivery header", delivery)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.maxBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			h.reject(w, http.StatusRequestEntityTooLarge, eventLabel, "bad_request", fmt.Sprintf("payload exceeds %d bytes", h.maxBody), delivery)
			return
		}
		h.reject(w, http.StatusBadRequest, eventLabel, "bad_request", "could not read request body", delivery)
		return
	}

	targetType := strings.TrimSpace(r.Header.Get(HeaderInstallationTargetType))
	targetID := strings.TrimSpace(r.Header.Get(HeaderInstallationTargetID))

	candidates, err := h.secrets.Candidates(r.Context(), targetType, targetID)
	if err != nil {
		h.logger.Error("webhook_secret_lookup_failed", "delivery", delivery, "error", err)
		h.reject(w, http.StatusInternalServerError, eventLabel, "internal_error", "could not resolve webhook secret", delivery)
		return
	}
	if len(candidates) == 0 {
		h.logger.Warn("webhook_unknown_target", "delivery", delivery, "event", event, "target_type", targetType, "target_id", targetID)
		// Same wording as the signature failure below so an anonymous
		// sender cannot learn which GitHub App IDs have secrets configured;
		// the metric result and the server log keep the distinction.
		h.reject(w, http.StatusUnauthorized, eventLabel, "unknown_app", "signature verification failed", delivery)
		return
	}

	sig := r.Header.Get(HeaderSignature256)
	var matched *Candidate
	if sig != "" {
		for i := range candidates {
			if VerifySignature(candidates[i].Secret, body, sig) {
				matched = &candidates[i]
				break
			}
		}
	}
	if matched == nil {
		h.logger.Warn("webhook_signature_invalid", "delivery", delivery, "event", event, "target_type", targetType, "target_id", targetID, "has_signature", sig != "")
		h.reject(w, http.StatusUnauthorized, eventLabel, "invalid_signature", "signature verification failed", delivery)
		return
	}

	// Unwrap form-encoded deliveries; the signature was computed over the
	// raw form body, so verification above used the original bytes.
	origContentType := r.Header.Get("Content-Type")
	payload := body
	if mt, _, _ := mime.ParseMediaType(origContentType); mt == "application/x-www-form-urlencoded" {
		values, perr := url.ParseQuery(string(body))
		if perr != nil || values.Get("payload") == "" {
			h.reject(w, http.StatusBadRequest, eventLabel, "bad_request", "form-encoded delivery has no payload parameter", delivery)
			return
		}
		payload = []byte(values.Get("payload"))
	}

	var meta payloadMeta
	_ = json.Unmarshal(payload, &meta) // best effort; empty fields become placeholders

	subject := Subject(h.pub.SubjectPrefix(), SubjectParts{
		AppRecordID: matched.AppRecordID,
		Event:       event,
		Action:      meta.Action,
		Owner:       meta.Repository.Owner.Login,
		Repo:        meta.Repository.Name,
	})

	hdr := nats.Header{}
	hdr.Set(HdrDelivery, delivery)
	hdr.Set(HdrEvent, event)
	setIf(hdr, HdrHookID, r.Header.Get(HeaderHookID))
	setIf(hdr, HdrTargetType, targetType)
	setIf(hdr, HdrTargetID, targetID)
	setIf(hdr, HdrAppRecordID, matched.AppRecordID)
	setIf(hdr, HdrAppName, matched.AppName)
	setIf(hdr, HdrAction, meta.Action)
	if meta.Repository.Owner.Login != "" && meta.Repository.Name != "" {
		hdr.Set(HdrRepository, meta.Repository.Owner.Login+"/"+meta.Repository.Name)
	}
	if meta.Installation.ID != 0 {
		hdr.Set(HdrInstallationID, strconv.FormatInt(meta.Installation.ID, 10))
	}
	setIf(hdr, HdrSender, meta.Sender.Login)
	hdr.Set(HdrReceivedAt, time.Now().UTC().Format(time.RFC3339Nano))
	hdr.Set(HdrContentType, "application/json")
	setIf(hdr, HdrOriginalContent, origContentType)

	pctx, cancel := context.WithTimeout(r.Context(), h.publishTimeout)
	defer cancel()
	start := time.Now()
	ack, err := h.pub.Publish(pctx, subject, hdr, payload, delivery)
	metrics.WebhookPublishDuration.Observe(time.Since(start).Seconds())
	if err != nil {
		h.logger.Error("webhook_publish_failed", "delivery", delivery, "event", event, "subject", subject, "error", err)
		w.Header().Set("Retry-After", "5")
		h.reject(w, http.StatusServiceUnavailable, eventLabel, "publish_error", "could not store delivery; redeliver from GitHub", delivery)
		return
	}

	result := "published"
	if ack.Duplicate {
		result = "duplicate"
	}
	metrics.WebhookReceivedTotal.WithLabelValues(eventLabel, result).Inc()
	h.logger.Info("webhook_received",
		"delivery", delivery,
		"event", event,
		"action", meta.Action,
		"repository", hdr.Get(HdrRepository),
		"app_record_id", matched.AppRecordID,
		"subject", subject,
		"sequence", ack.Sequence,
		"duplicate", ack.Duplicate,
		"bytes", len(payload),
	)
	writeJSON(w, http.StatusAccepted, response{
		Message:   "accepted",
		Delivery:  delivery,
		Stream:    ack.Stream,
		Sequence:  ack.Sequence,
		Duplicate: ack.Duplicate,
		Subject:   subject,
	})
}

func (h *Handler) reject(w http.ResponseWriter, status int, eventLabel, result, msg, delivery string) {
	metrics.WebhookReceivedTotal.WithLabelValues(eventLabel, result).Inc()
	writeJSON(w, status, response{Message: msg, Delivery: delivery})
}

func setIf(h nats.Header, key, value string) {
	if value != "" {
		h.Set(key, value)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// knownEvents bounds the cardinality of the event metric label to GitHub's
// documented webhook event catalogue. Anything else is reported as
// "unknown"; the real name is still stored on the message.
var knownEvents = map[string]struct{}{
	"branch_protection_configuration": {}, "branch_protection_rule": {}, "check_run": {}, "check_suite": {},
	"code_scanning_alert": {}, "commit_comment": {}, "create": {}, "custom_property": {},
	"custom_property_values": {}, "delete": {}, "dependabot_alert": {}, "deploy_key": {}, "deployment": {},
	"deployment_protection_rule": {}, "deployment_review": {}, "deployment_status": {}, "discussion": {},
	"discussion_comment": {}, "fork": {}, "github_app_authorization": {}, "gollum": {}, "installation": {},
	"installation_repositories": {}, "installation_target": {}, "issue_comment": {}, "issue_dependencies": {},
	"issues": {}, "label": {}, "marketplace_purchase": {}, "member": {}, "membership": {}, "merge_group": {},
	"merge_queue_entry": {}, "meta": {}, "milestone": {}, "org_block": {}, "organization": {}, "package": {},
	"page_build": {}, "personal_access_token_request": {}, "ping": {}, "project": {}, "project_card": {},
	"project_column": {}, "projects_v2": {}, "projects_v2_item": {}, "projects_v2_status_update": {},
	"public": {}, "pull_request": {}, "pull_request_review": {}, "pull_request_review_comment": {},
	"pull_request_review_thread": {}, "push": {}, "registry_package": {}, "release": {}, "repository": {},
	"repository_advisory": {}, "repository_dispatch": {}, "repository_import": {}, "repository_ruleset": {},
	"repository_vulnerability_alert": {}, "secret_scanning_alert": {}, "secret_scanning_alert_location": {},
	"secret_scanning_scan": {}, "security_advisory": {}, "security_and_analysis": {}, "sponsorship": {},
	"star": {}, "status": {}, "sub_issues": {}, "team": {}, "team_add": {}, "watch": {}, "workflow_dispatch": {},
	"workflow_job": {}, "workflow_run": {},
}

// EventLabel normalises an X-GitHub-Event value for use as a metric label.
func EventLabel(event string) string {
	if _, ok := knownEvents[event]; ok {
		return event
	}
	return "unknown"
}
