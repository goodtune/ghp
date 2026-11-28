// Package relay replays stored GitHub webhook deliveries from a ghp server
// to another webhook receiver exactly as GitHub sent them. It is the engine
// behind "ghp webhooks tail --relay".
//
// The relay follows GET /api/webhooks/stream in client-acknowledgement mode
// (ack=client, raw=1) on a durable consumer, POSTs each delivery's exact
// signed body with GitHub's original headers to the target, and
// acknowledges it via POST /api/webhooks/stream/ack only after the target
// answers 2xx. Delivery to the target is at-least-once.
package relay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/ghp/internal/webhook"
)

// Defaults. GitHub itself gives a receiver 10 seconds to answer.
const (
	DefaultTimeout        = 10 * time.Second
	DefaultBackoff        = time.Second
	DefaultMaxDelay       = 60 * time.Second
	DefaultReconnectDelay = 2 * time.Second
	MaxReconnectDelay     = 30 * time.Second
	// DefaultIdleTimeout drops a stream that has sent nothing (not even the
	// 15-second ping) for this long, so a half-open connection is noticed.
	DefaultIdleTimeout = 45 * time.Second
	// DefaultAckTimeout bounds one ack POST.
	DefaultAckTimeout = 10 * time.Second
	// DefaultAckAttempts is how many times an ack is tried on transport
	// errors and 5xx before the relay drops the stream.
	DefaultAckAttempts = 4
	// sessionGoneDrain is how long the relay keeps reading a stream whose
	// session the server no longer knows, waiting for an evicted event.
	sessionGoneDrain = 2 * time.Second
	// DefaultAckBackoff is the first delay between ack attempts.
	DefaultAckBackoff = 250 * time.Millisecond
	// maxReaderPayload bounds the payload cap the relay accepts from the
	// server (1 GiB).
	maxReaderPayload = 1 << 30
	// DefaultMaxPayloadBytes is the ingest body cap assumed when the server
	// does not report its own (GitHub sends at most 25 MiB).
	DefaultMaxPayloadBytes = 25 << 20
	// eventHeadroom is the room left for the envelope around the base64
	// payload in one SSE data line (raw mode omits the decoded payload).
	eventHeadroom = 1 << 20
	// responseDrain bounds how much of a target response is read before
	// the connection is reused.
	responseDrain = 64 << 10
)

// ErrServerTooOld means the server has no client acknowledgement endpoint,
// so the relay cannot acknowledge deliveries only after the target accepts
// them. The relay checks this before it touches the durable consumer.
var ErrServerTooOld = errors.New("--relay: the ghp server does not support client acknowledgements (POST " + webhook.StreamAckPath + "); upgrade the server")

// ErrTakenOver means another client-ack stream (normally another relay)
// took over the durable. The relay stops instead of reconnecting, which
// would evict the other relay in turn.
var ErrTakenOver = errors.New("durable was taken over by another relay")

type takenOverError struct{ durable, by string }

func (e takenOverError) Error() string {
	by := ""
	if e.by != "" {
		by = fmt.Sprintf(" (opened by %s)", e.by)
	}
	return fmt.Sprintf("durable %s was taken over by another relay%s; stop the other relay or use a different --durable name", e.durable, by)
}

func (e takenOverError) Is(target error) bool { return target == ErrTakenOver }

// EventTooLargeError means one stream event exceeded the reader's cap.
type EventTooLargeError struct {
	Sequence string // the event's id, when it was read
	Delivery string // best effort, from the start of the event data
	Limit    int
}

func (e *EventTooLargeError) Error() string {
	return fmt.Sprintf("event seq=%s delivery=%s is larger than %d bytes, the most the server's max_payload_bytes allows",
		orUnknown(e.Sequence), orUnknown(e.Delivery), e.Limit)
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// errSessionGone means the server no longer knows the stream session (the
// stream ended or was replaced); the relay reconnects.
var errSessionGone = errors.New("stream session ended")

// Options configures Run. Zero durations take the defaults above.
type Options struct {
	// ServerURL and Token address and authenticate to the ghp server. The
	// token is sent only to ServerURL, never to Target.
	ServerURL string
	Token     string

	// Target is the receiver URL (see ValidateTargetURL).
	Target string
	// Durable names the server-side consumer. Required.
	Durable string
	// Filter and From are passed to the stream as filter and from.
	Filter string
	From   string
	// Count stops Run after this many successful relays (0 = no limit).
	Count int

	Timeout        time.Duration // per target attempt
	Backoff        time.Duration // first target retry delay
	MaxDelay       time.Duration // cap on target retry delay
	ReconnectDelay time.Duration // first stream reconnect delay
	IdleTimeout    time.Duration // stream read idle timeout
	AckTimeout     time.Duration // per ack POST
	AckAttempts    int
	AckBackoff     time.Duration

	// Client is used for requests to the ghp server (default: a client
	// with no overall timeout, since the stream is long-lived).
	Client *http.Client
}

func (o *Options) defaults() {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Backoff <= 0 {
		o.Backoff = DefaultBackoff
	}
	if o.MaxDelay <= 0 {
		o.MaxDelay = DefaultMaxDelay
	}
	if o.ReconnectDelay <= 0 {
		o.ReconnectDelay = DefaultReconnectDelay
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = DefaultIdleTimeout
	}
	if o.AckTimeout <= 0 {
		o.AckTimeout = DefaultAckTimeout
	}
	if o.AckAttempts <= 0 {
		o.AckAttempts = DefaultAckAttempts
	}
	if o.AckBackoff <= 0 {
		o.AckBackoff = DefaultAckBackoff
	}
	if o.Client == nil {
		o.Client = &http.Client{}
	}
}

// RedactURL returns raw without userinfo and with any query string or
// fragment replaced by "?REDACTED", for log lines and errors: a receiver
// URL can carry a secret token in its query.
func RedactURL(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.User != nil {
		u.User = nil
		raw = u.String()
	}
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i] + "?REDACTED"
	}
	return raw
}

// redactTargetError redacts the URL that net/http and net/url name in
// their errors: the query string can carry a receiver's secret token.
func redactTargetError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		ue.URL = RedactURL(ue.URL)
	}
	return err
}

// ValidateTargetURL accepts absolute http and https URLs with a host and
// rejects other schemes, userinfo and fragments.
func ValidateTargetURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("--relay needs a URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("--relay: %w", redactTargetError(err))
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("--relay: scheme must be http or https (got %q)", u.Scheme)
	}
	if u.Host == "" || u.Hostname() == "" {
		return errors.New("--relay: URL needs a host")
	}
	if u.User != nil {
		return errors.New("--relay: URL must not contain userinfo")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("--relay: URL must not contain a fragment")
	}
	return nil
}

// delivery holds the fields of a stream event the relay uses. It is decoded
// on its own, not as a webhook.Envelope, so an unrelated change to the
// envelope cannot stop the relay from reading deliveries.
type delivery struct {
	Sequence            uint64 `json:"sequence"`
	Delivery            string `json:"delivery"`
	Event               string `json:"event"`
	HookID              string `json:"hook_id"`
	TargetType          string `json:"target_type"`
	TargetID            string `json:"target_id"`
	Signature256        string `json:"signature_256"`
	SignatureSHA1       string `json:"signature_sha1"`
	UserAgent           string `json:"user_agent"`
	OriginalContentType string `json:"original_content_type"`
	PayloadBase64       []byte `json:"payload_base64"`
}

// skipReason reports why a delivery cannot be replayed so that its
// signature verifies, or "" when it can.
func skipReason(env *delivery) string {
	if env.Signature256 == "" {
		return "no stored signature (delivery stored before ghp kept signatures)"
	}
	if mt, _, _ := mime.ParseMediaType(env.OriginalContentType); mt == "application/x-www-form-urlencoded" {
		return "form-encoded delivery: ghp stores the unwrapped payload, not the signed form body"
	}
	return ""
}

// relayHeaders builds the header set GitHub sent, with GitHub's spelling.
func relayHeaders(env *delivery) http.Header {
	h := http.Header{}
	set := func(k, v string) {
		if v != "" {
			h[k] = []string{v}
		}
	}
	ct := env.OriginalContentType
	if ct == "" {
		ct = "application/json"
	}
	set("Content-Type", ct)
	// An empty User-Agent entry stops net/http adding its own.
	h["User-Agent"] = []string{env.UserAgent}
	set(webhook.HeaderEvent, env.Event)
	set(webhook.HeaderDelivery, env.Delivery)
	set(webhook.HeaderHookID, env.HookID)
	set(webhook.HeaderInstallationTargetType, env.TargetType)
	set(webhook.HeaderInstallationTargetID, env.TargetID)
	set(webhook.HeaderSignature256, env.Signature256)
	set(webhook.HeaderSignature, env.SignatureSHA1)
	return h
}

// relayer holds one Run's state.
type relayer struct {
	opts   Options
	errOut io.Writer
	// target is used only for the relay target: no cookie jar, no
	// redirects, and never ghp's credentials.
	target *http.Client
	// ack is used for ack POSTs to ghp; it has a timeout.
	ack *http.Client
	// maxEventBytes caps one SSE line, derived from the server's ingest
	// body cap.
	maxEventBytes int
	relayed       int
}

// Run relays deliveries until ctx is cancelled (returns nil; the in-flight
// delivery stays unacknowledged and is redelivered) or opts.Count
// deliveries have been relayed. It returns an error for conditions retrying
// cannot fix: an old server, bad credentials, or a 4xx from the stream.
func Run(ctx context.Context, opts Options, errOut io.Writer) error {
	opts.defaults()
	if opts.Durable == "" {
		return errors.New("relay requires a durable consumer name")
	}
	r := &relayer{
		opts:   opts,
		errOut: errOut,
		target: &http.Client{
			Transport: http.DefaultTransport.(*http.Transport).Clone(),
			// A 3xx is a failure to retry, never a hop to follow: the
			// receiver's URL is the one the operator configured.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		ack: &http.Client{Transport: opts.Client.Transport, Timeout: opts.AckTimeout},
	}

	fmt.Fprintf(errOut, "relaying webhook deliveries to %s (durable %s)\n", RedactURL(opts.Target), opts.Durable)
	r.maxEventBytes = eventLimit(r.maxPayloadBytes(ctx, true))

	q := url.Values{}
	if opts.Filter != "" {
		q.Set("filter", opts.Filter)
	}
	if opts.From != "" {
		q.Set("from", opts.From)
	}
	q.Set("durable", opts.Durable)
	q.Set("ack", "client")
	q.Set("raw", "1")

	delay := opts.ReconnectDelay
	for {
		// Probe before every connect, not only at startup: a reconnect
		// can land on an older server (rollback, rolling deploy) that
		// would acknowledge deliveries as soon as it sent them.
		if err := r.probe(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		resp, err := r.get(ctx, "/api/webhooks/stream?"+q.Encode())
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Fprintf(errOut, "connection failed: %v; retrying in %s\n", err, delay)
			if !sleepCtx(ctx, delay) {
				return nil
			}
			delay = min(delay*2, MaxReconnectDelay)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			apiErr := apiError(resp.StatusCode, body)
			if !retryableStatus(resp.StatusCode) {
				return apiErr
			}
			fmt.Fprintf(errOut, "stream unavailable: %v; retrying in %s\n", apiErr, delay)
			if !sleepCtx(ctx, delay) {
				return nil
			}
			delay = min(delay*2, MaxReconnectDelay)
			continue
		}
		if resp.Header.Get(webhook.ClientAckHeader) != "1" {
			// Not a stream that honours ack=client (the probe and this
			// connection reached different servers): close before reading.
			resp.Body.Close()
			return ErrServerTooOld
		}
		delay = opts.ReconnectDelay

		done, rerr := r.consume(ctx, resp.Body)
		resp.Body.Close()
		switch {
		case done || ctx.Err() != nil:
			return nil
		case errors.Is(rerr, ErrServerTooOld), errors.Is(rerr, ErrTakenOver):
			return rerr
		case errors.As(rerr, new(*EventTooLargeError)):
			// The server may have raised its cap since startup.
			if limit := eventLimit(r.maxPayloadBytes(ctx, false)); limit > r.maxEventBytes {
				fmt.Fprintf(errOut, "%v; the server now allows %d bytes, reconnecting with a larger reader\n", rerr, limit)
				r.maxEventBytes = limit
			} else {
				return rerr
			}
		case rerr != nil:
			fmt.Fprintf(errOut, "stream ended: %v; reconnecting\n", rerr)
		default:
			fmt.Fprintln(errOut, "stream ended; reconnecting")
		}
		if !sleepCtx(ctx, delay) {
			return nil
		}
	}
}

func retryableStatus(code int) bool {
	return code >= 500 || code == http.StatusTooManyRequests
}

// probe checks, before the relay touches its durable consumer, that the
// server has the client acknowledgement endpoint. An invalid ack body gets
// 400 from a server that has it; a server without it answers 404 or 405.
// Opening the stream first would let an old server acknowledge deliveries
// on flush, losing them for the relay.
func (r *relayer) probe(ctx context.Context) error {
	delay := r.opts.ReconnectDelay
	for {
		code, hdr, body, err := r.postAck(ctx, []byte(`{}`))
		capable := hdr.Get(webhook.ClientAckHeader) == "1"
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			fmt.Fprintf(r.errOut, "server check failed: %v; retrying in %s\n", err, delay)
		case code == http.StatusBadRequest && capable:
			return nil
		case code == http.StatusNotFound && capable:
			// A current server with webhooks disabled.
			return apiError(code, body)
		case code == http.StatusBadRequest || code == http.StatusNotFound || code == http.StatusMethodNotAllowed:
			// Not this endpoint answering: an older server, or a proxy.
			return ErrServerTooOld
		case code == http.StatusUnauthorized || code == http.StatusForbidden:
			return apiError(code, body)
		default:
			fmt.Fprintf(r.errOut, "server check failed: %v; retrying in %s\n", apiError(code, body), delay)
		}
		if !sleepCtx(ctx, delay) {
			return ctx.Err()
		}
		delay = min(delay*2, MaxReconnectDelay)
	}
}

// eventLimit is the longest SSE line the reader accepts for a payload cap:
// the base64 payload plus room for the envelope.
func eventLimit(maxPayload int) int {
	return base64.StdEncoding.EncodedLen(maxPayload) + eventHeadroom
}

// maxPayloadBytes asks the server for its ingest body cap so the SSE
// reader can hold the largest delivery the server will ever store. Failures
// are retried a few times and then reported; the default cap is used only
// after a warning, or silently when the server reports none (an older
// server). When retry is false a single attempt is made.
func (r *relayer) maxPayloadBytes(ctx context.Context, retry bool) int {
	attempts := 1
	if retry {
		attempts = 3
	}
	delay := r.opts.ReconnectDelay
	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 && !sleepCtx(ctx, delay) {
			break
		}
		n, err := r.fetchMaxPayload(ctx)
		if err == nil {
			if n == 0 {
				return DefaultMaxPayloadBytes
			}
			return n
		}
		last = err
		delay *= 2
	}
	if ctx.Err() == nil {
		fmt.Fprintf(r.errOut, "warning: could not read the server's max_payload_bytes (%v); assuming %d bytes\n", last, DefaultMaxPayloadBytes)
	}
	return DefaultMaxPayloadBytes
}

// fetchMaxPayload returns the server's max_payload_bytes, or 0 when the
// server does not report one.
func (r *relayer) fetchMaxPayload(ctx context.Context) (int, error) {
	resp, err := r.get(ctx, "/api/webhooks/status")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return 0, apiError(resp.StatusCode, body)
	}
	var st struct {
		MaxPayloadBytes int64 `json:"max_payload_bytes"`
	}
	if err := json.Unmarshal(body, &st); err != nil {
		return 0, fmt.Errorf("decoding status: %w", err)
	}
	if st.MaxPayloadBytes < 0 || st.MaxPayloadBytes > maxReaderPayload {
		return 0, fmt.Errorf("max_payload_bytes %d out of range", st.MaxPayloadBytes)
	}
	return int(st.MaxPayloadBytes), nil
}

func (r *relayer) get(ctx context.Context, pathAndQuery string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.opts.ServerURL+pathAndQuery, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+r.opts.Token)
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := r.opts.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to server: %w", err)
	}
	return resp, nil
}

// consume handles one stream connection and reports whether the count
// limit was reached.
func (r *relayer) consume(ctx context.Context, body io.ReadCloser) (bool, error) {
	idle := newIdleWatch(body, r.opts.IdleTimeout)
	defer idle.stop()

	var (
		session string
		// broken is set when this stream can no longer be used (the
		// session is gone, or an event could not be decoded). The relay
		// keeps reading briefly, ignoring deliveries, in case an evicted
		// event follows, and then drops the stream.
		broken error
	)
	drain := func(err error) {
		if broken == nil {
			broken = err
			idle.resumeWith(min(sessionGoneDrain, r.opts.IdleTimeout))
		}
	}
	err := scanSSE(idle, r.maxEventBytes, func(kind, id, data string) (bool, error) {
		switch kind {
		case webhook.EventEvicted:
			var ev struct {
				By string `json:"by"`
			}
			_ = json.Unmarshal([]byte(data), &ev)
			return true, takenOverError{durable: r.opts.Durable, by: ev.By}
		case webhook.EventSession:
			var s struct {
				Session string `json:"session"`
			}
			if err := json.Unmarshal([]byte(data), &s); err != nil || s.Session == "" {
				return false, fmt.Errorf("bad session event: %q", data)
			}
			session = s.Session
			return false, nil
		case "error":
			fmt.Fprintf(r.errOut, "server error: %s\n", data)
			return false, nil
		}
		if session == "" {
			// A delivery before any session: not a client-ack stream.
			return false, ErrServerTooOld
		}
		if broken != nil {
			return false, nil
		}
		var env delivery
		if err := json.Unmarshal([]byte(data), &env); err != nil || env.Sequence == 0 {
			if err == nil {
				err = errors.New("no sequence")
			}
			// Never skip an event silently: the server holds it until it
			// is acked, so drop the stream and let the server Nak it.
			drain(fmt.Errorf("undecodable event id=%s: %v", orUnknown(id), err))
			return false, nil
		}
		// Handling can take as long as the target keeps failing; the
		// stream is legitimately quiet meanwhile.
		idle.pause()
		ok, err := r.handle(ctx, session, &env)
		idle.resume()
		if errors.Is(err, errSessionGone) {
			// If another relay took over, the server sends an evicted
			// event before closing the stream.
			drain(err)
			return false, nil
		}
		if err != nil || ctx.Err() != nil {
			return true, err
		}
		if ok {
			r.relayed++
			if r.opts.Count > 0 && r.relayed >= r.opts.Count {
				return true, nil
			}
		}
		return false, nil
	})
	if idle.fired() {
		err = fmt.Errorf("no data from the server for %s", r.opts.IdleTimeout)
	}
	if broken != nil && !errors.Is(err, ErrTakenOver) {
		err = broken
	}
	return r.opts.Count > 0 && r.relayed >= r.opts.Count, err
}

// handle relays (or skips) one delivery and acknowledges it. It reports
// whether the delivery was relayed. It returns early, without an ack, when
// ctx is cancelled, and returns an error when the ack could not be made so
// the caller drops the stream and the server redelivers.
func (r *relayer) handle(ctx context.Context, session string, env *delivery) (bool, error) {
	if reason := skipReason(env); reason != "" {
		fmt.Fprintf(r.errOut, "skipped seq=%d delivery=%s event=%s: %s\n", env.Sequence, env.Delivery, env.Event, reason)
		_, err := r.ackDelivery(ctx, session, env)
		return false, err
	}
	// payload_base64 is omitted when empty: with a session open (so raw=1
	// is honoured) a missing field is an empty body.
	backoff := r.opts.Backoff
	for attempt := 1; ; attempt++ {
		status, err := r.post(ctx, env)
		if ctx.Err() != nil {
			return false, nil
		}
		if err == nil && status >= 200 && status < 300 {
			fmt.Fprintf(r.errOut, "relayed seq=%d delivery=%s event=%s: status %d after %d attempt(s)\n", env.Sequence, env.Delivery, env.Event, status, attempt)
			return r.ackDelivery(ctx, session, env)
		}
		wait := jitter(backoff)
		why := fmt.Sprintf("status %d", status)
		if err != nil {
			why = "error: " + err.Error()
		}
		fmt.Fprintf(r.errOut, "retrying seq=%d delivery=%s: %s (attempt %d); next attempt in %s\n", env.Sequence, env.Delivery, why, attempt, wait.Round(time.Millisecond))
		if !sleepCtx(ctx, wait) {
			return false, nil
		}
		backoff = min(backoff*2, r.opts.MaxDelay)
	}
}

// jitter returns a delay between d/2 and d.
func jitter(d time.Duration) time.Duration {
	if d <= 1 {
		return d
	}
	half := d / 2
	return half + rand.N(d-half+1)
}

// post sends one attempt to the target: the raw stored body with GitHub's
// original headers and nothing of ghp's.
func (r *relayer) post(ctx context.Context, env *delivery) (int, error) {
	actx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(actx, http.MethodPost, r.opts.Target, bytes.NewReader(env.PayloadBase64))
	if err != nil {
		return 0, redactTargetError(err)
	}
	req.Header = relayHeaders(env)
	resp, err := r.target.Do(req)
	if err != nil {
		return 0, redactTargetError(err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, responseDrain))
	resp.Body.Close()
	return resp.StatusCode, nil
}

// ackDelivery confirms a delivery to ghp and reports whether it counts as
// relayed (the server recorded it). Transport errors and 5xx are retried a
// few times. When the ack cannot be made it returns an error: the server
// still holds the delivery, so the relay must drop the stream for the
// server to Nak and redeliver it (the target may then see it again). A 404
// (the session is gone, for example after a takeover) returns
// errSessionGone without logging, so the caller can tell a takeover from a
// plain reconnect.
func (r *relayer) ackDelivery(ctx context.Context, session string, env *delivery) (bool, error) {
	body, _ := json.Marshal(map[string]any{"session": session, "sequence": env.Sequence})
	delay := r.opts.AckBackoff
	var last error
	for attempt := 1; attempt <= r.opts.AckAttempts; attempt++ {
		code, _, respBody, err := r.postAck(ctx, body)
		if ctx.Err() != nil {
			return false, nil
		}
		switch {
		case err == nil && code == http.StatusOK:
			return true, nil
		case err == nil && code == http.StatusBadGateway && ackErrorCode(respBody) == webhook.AckCodeAckError:
			// The server could not record the ack but has already released
			// the stream and will redeliver after its ack timeout: carry
			// on reading. The target will see this delivery again.
			fmt.Fprintf(r.errOut, "ack not recorded by the server seq=%d delivery=%s; the server will redeliver it\n", env.Sequence, env.Delivery)
			return false, nil
		case err == nil && code == http.StatusConflict:
			if ackErrorCode(respBody) == webhook.AckCodeAcked {
				// An earlier attempt was recorded; only its answer was lost.
				return true, nil
			}
			// "released" (Nak'd while the session was still registered) or
			// unknown: the delivery comes back on the stream.
			fmt.Fprintf(r.errOut, "ack refused seq=%d delivery=%s: %v; the server will redeliver it\n", env.Sequence, env.Delivery, apiError(code, respBody))
			return false, nil
		case err == nil && code == http.StatusNotFound:
			return false, fmt.Errorf("ack for seq=%d: %w: %v", env.Sequence, errSessionGone, apiError(code, respBody))
		case err == nil && code < 500:
			last = apiError(code, respBody)
			attempt = r.opts.AckAttempts
		case err == nil:
			last = apiError(code, respBody)
		default:
			last = err
		}
		if attempt < r.opts.AckAttempts {
			if !sleepCtx(ctx, delay) {
				return false, nil
			}
			delay *= 2
		}
	}
	return false, fmt.Errorf("ack for seq=%d delivery=%s failed: %w", env.Sequence, env.Delivery, last)
}

func (r *relayer) postAck(ctx context.Context, body []byte) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.opts.ServerURL+webhook.StreamAckPath, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+r.opts.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.ack.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, resp.Header, b, nil
}

// ackErrorCode returns the machine-readable code of an ack response.
func ackErrorCode(body []byte) string {
	var m struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &m)
	return m.Code
}

func apiError(status int, body []byte) error {
	var m struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &m)
	if m.Message != "" {
		return fmt.Errorf("server returned %d: %s", status, m.Message)
	}
	return fmt.Errorf("server returned %d: %s", status, strings.TrimSpace(string(body)))
}

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

// idleWatch closes the stream body when no bytes arrive for d while the
// watch is running. pause stops the clock while a delivery is handled.
type idleWatch struct {
	body io.ReadCloser
	d    time.Duration

	mu      sync.Mutex
	timer   *time.Timer
	tripped bool
}

func newIdleWatch(body io.ReadCloser, d time.Duration) *idleWatch {
	w := &idleWatch{body: body, d: d}
	w.timer = time.AfterFunc(d, w.trip)
	return w
}

func (w *idleWatch) trip() {
	w.mu.Lock()
	w.tripped = true
	w.mu.Unlock()
	_ = w.body.Close()
}

func (w *idleWatch) Read(p []byte) (int, error) {
	n, err := w.body.Read(p)
	if n > 0 {
		w.mu.Lock()
		if !w.tripped {
			w.timer.Reset(w.d)
		}
		w.mu.Unlock()
	}
	return n, err
}

func (w *idleWatch) pause() {
	w.mu.Lock()
	w.timer.Stop()
	w.mu.Unlock()
}

func (w *idleWatch) resume() {
	w.mu.Lock()
	if !w.tripped {
		w.timer.Reset(w.d)
	}
	w.mu.Unlock()
}

// resumeWith restarts the clock with a different timeout.
func (w *idleWatch) resumeWith(d time.Duration) {
	w.mu.Lock()
	w.d = d
	if !w.tripped {
		w.timer.Reset(d)
	}
	w.mu.Unlock()
}

func (w *idleWatch) stop() { w.timer.Stop() }

func (w *idleWatch) fired() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.tripped
}

// deliveryField finds the delivery GUID near the start of an envelope.
var deliveryField = regexp.MustCompile(`"delivery":"([^"\\]{1,128})"`)

// scanSSE reads server-sent events and calls fn with each event's type and
// data. fn returns stop=true to end the scan early. A line longer than
// maxLine bytes is an error.
func scanSSE(body io.Reader, maxLine int, fn func(kind, id, data string) (bool, error)) error {
	br := bufio.NewReaderSize(body, 64<<10)
	var (
		kind   string
		lastID string
		data   strings.Builder
		line   []byte
	)
	dispatch := func() (bool, error) {
		defer func() { kind = ""; data.Reset() }()
		if data.Len() == 0 {
			return false, nil
		}
		return fn(kind, lastID, data.String())
	}
	for {
		line = line[:0]
		var err error
		for {
			var chunk []byte
			chunk, err = br.ReadSlice('\n')
			if len(line)+len(chunk) > maxLine {
				head := append(line, chunk...)
				if len(head) > 64<<10 {
					head = head[:64<<10]
				}
				e := &EventTooLargeError{Sequence: lastID, Limit: maxLine}
				if m := deliveryField.FindSubmatch(head); m != nil {
					e.Delivery = string(m[1])
				}
				return e
			}
			line = append(line, chunk...)
			if !errors.Is(err, bufio.ErrBufferFull) {
				break
			}
		}
		if err != nil && len(line) == 0 {
			if stop, derr := dispatch(); stop || derr != nil {
				return derr
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		s := strings.TrimRight(string(line), "\r\n")
		switch {
		case s == "":
			if stop, derr := dispatch(); stop || derr != nil {
				return derr
			}
		case strings.HasPrefix(s, "id:"):
			lastID = strings.TrimSpace(s[3:])
		case strings.HasPrefix(s, ":"), strings.HasPrefix(s, "retry:"):
		case strings.HasPrefix(s, "event:"):
			kind = strings.TrimSpace(s[6:])
		case strings.HasPrefix(s, "data:"):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(s, "data:"), " "))
		}
		if err != nil {
			// Last line had no newline: dispatch what we have and stop.
			if stop, derr := dispatch(); stop || derr != nil {
				return derr
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}
