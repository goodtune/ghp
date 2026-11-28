package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/webhook"
)

// Client-ack mode (GET /api/webhooks/stream?ack=client&durable=NAME).
//
// In the default mode the stream acknowledges each delivery as soon as the
// SSE event is flushed. That is "delivered to the socket", not "processed by
// the client". In client-ack mode the server holds the delivery unacked
// until the client confirms it with POST /api/webhooks/stream/ack, so a
// client that relays deliveries elsewhere can acknowledge only once the
// relay target has accepted the delivery. Meanwhile the server keeps the
// message alive with InProgress, and Naks it when the stream ends (client
// disconnect or server shutdown) so the durable consumer redelivers it at
// once. If ghp itself dies, JetStream redelivers after AckWait. Either way
// the guarantee is at-least-once.

const (
	// webhookAckBodyLimit bounds the ack request body.
	webhookAckBodyLimit = 4096
	// webhookAckTimeout bounds the confirmed JetStream ack.
	webhookAckTimeout = 5 * time.Second
	// sessionTokenBytes is the size of a stream session token before hex
	// encoding (64 hex characters).
	sessionTokenBytes = 32
)

// streamAckSession is one live client-ack stream. At most one delivery is
// pending at a time: the durable consumer fetches one message per Next and
// the stream does not fetch again until that message is resolved.
type streamAckSession struct {
	userID string
	// durable is the sanitised consumer name; one session per durable.
	durable string
	// cancel ends the session's stream; done is closed when its handler
	// has returned (and so has resolved its pending delivery).
	cancel context.CancelFunc
	done   chan struct{}
	// prevDone and prevDeadline are the done channel of the session this
	// one evicted and the end of the wait for it. done is closed only once
	// that session has finished too (or the wait is over), so a session
	// that leaves early still holds back whoever evicts it next.
	prevDone     chan struct{}
	prevDeadline time.Time
	evicted      atomic.Bool
	// evictedBy is the GitHub login of the session that evicted this one;
	// written before evicted is set.
	evictedBy string
	// acked receives one signal for each pending delivery the client
	// acknowledged. Buffered so the ack handler never blocks.
	acked chan struct{}

	mu         sync.Mutex
	pendingSeq uint64
	pendingMsg jetstream.Msg
	// lastSeq and lastResolution remember how the most recent delivery
	// left the pending slot ("acked" or "released"), so a repeated or late
	// ack can be answered precisely.
	lastSeq        uint64
	lastResolution string
}

// resolve records how seq left the pending slot.
func (s *streamAckSession) resolve(seq uint64, how string) {
	s.mu.Lock()
	s.lastSeq, s.lastResolution = seq, how
	s.mu.Unlock()
}

// resolution reports how seq left the pending slot, or "" when this session
// has no record of it.
func (s *streamAckSession) resolution(seq uint64) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastSeq == seq {
		return s.lastResolution
	}
	return ""
}

func (s *streamAckSession) setPending(seq uint64, m jetstream.Msg) {
	s.mu.Lock()
	s.pendingSeq, s.pendingMsg = seq, m
	s.mu.Unlock()
}

// takePending removes and returns the pending delivery, or nil when there is
// none. Whoever takes it (the ack handler or the stream on disconnect) owns
// resolving it, so a delivery is never both acked and Nak'd.
func (s *streamAckSession) takePending() jetstream.Msg {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.pendingMsg
	s.pendingSeq, s.pendingMsg = 0, nil
	return m
}

// takeIfSeq takes the pending delivery only when it has sequence seq.
func (s *streamAckSession) takeIfSeq(seq uint64) jetstream.Msg {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingMsg == nil || s.pendingSeq != seq {
		return nil
	}
	m := s.pendingMsg
	s.pendingSeq, s.pendingMsg = 0, nil
	return m
}

func (s *streamAckSession) hasPending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingMsg != nil
}

// streamAckRegistry holds the live client-ack sessions, keyed by the SHA-256
// of the session token so the raw token is never used as a map key.
type streamAckRegistry struct {
	mu        sync.Mutex
	sessions  map[string]*streamAckSession
	byDurable map[string]*streamAckSession
}

func newStreamAckRegistry() *streamAckRegistry {
	return &streamAckRegistry{sessions: make(map[string]*streamAckSession), byDurable: make(map[string]*streamAckSession)}
}

// sseChunkSize is the largest piece of an SSE frame written under one write
// deadline. The deadline is reset before each piece, so a slow but moving
// client can receive an event of any size, while one that stops reading is
// cut off within one deadline.
const sseChunkSize = 64 << 10

func tokenKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// open creates a session for durable bound to userID and returns it with
// its token. Only one client-ack session may consume a durable: an existing
// one is evicted (its stream is cancelled, so it Naks its pending delivery)
// and open waits for it to finish, so the held delivery is redelivered to
// the new session first and order is kept. cancel ends the new session's
// stream. The wait also ends when ctx is done (the new client went away,
// was itself evicted, or the server is shutting down); the caller checks
// ctx and the session's evicted flag afterwards.
func (r *streamAckRegistry) open(ctx context.Context, userID, login, durable string, cancel context.CancelFunc, evictWait time.Duration) (string, *streamAckSession, error) {
	b := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	token := hex.EncodeToString(b)
	s := &streamAckSession{
		userID: userID, durable: durable, cancel: cancel,
		acked: make(chan struct{}, 1), done: make(chan struct{}),
	}
	r.mu.Lock()
	old := r.byDurable[durable]
	r.sessions[tokenKey(token)] = s
	r.byDurable[durable] = s
	r.mu.Unlock()
	if old != nil {
		old.evictedBy = login
		old.evicted.Store(true)
		old.cancel()
		s.prevDone, s.prevDeadline = old.done, time.Now().Add(evictWait)
		timer := time.NewTimer(evictWait)
		defer timer.Stop()
		select {
		case <-old.done:
		case <-timer.C:
		case <-ctx.Done():
		}
	}
	return token, s, nil
}

// close removes the session and marks its handler finished. A session
// that evicted another one keeps owning the durable until that one has
// finished (or the eviction wait is over): a client that connects meanwhile
// then evicts this session and waits on its done channel, instead of
// subscribing while the evicted stream still holds a delivery.
func (r *streamAckRegistry) close(token string, s *streamAckSession) {
	r.mu.Lock()
	delete(r.sessions, tokenKey(token))
	if s.prevDone == nil && r.byDurable[s.durable] == s {
		delete(r.byDurable, s.durable)
	}
	r.mu.Unlock()
	if s.prevDone == nil {
		close(s.done)
		return
	}
	go func() {
		timer := time.NewTimer(time.Until(s.prevDeadline))
		defer timer.Stop()
		select {
		case <-s.prevDone:
		case <-timer.C:
		}
		r.mu.Lock()
		if r.byDurable[s.durable] == s {
			delete(r.byDurable, s.durable)
		}
		r.mu.Unlock()
		close(s.done)
	}()
}

// lookup returns the session for token when it belongs to userID.
func (r *streamAckRegistry) lookup(token, userID string) *streamAckSession {
	r.mu.Lock()
	s := r.sessions[tokenKey(token)]
	r.mu.Unlock()
	if s == nil || s.userID != userID {
		return nil
	}
	return s
}

// parseStreamModes reads the opt-in stream modes: raw=1 adds the exact
// stored bytes to each event; ack=client switches to client
// acknowledgement, which needs a durable consumer.
func parseStreamModes(r *http.Request) (raw, clientAck bool, err error) {
	q := r.URL.Query()
	switch v := strings.TrimSpace(q.Get("raw")); v {
	case "", "0", "false":
	case "1", "true":
		raw = true
	default:
		return false, false, errors.New("raw must be 1, true, 0 or false")
	}
	switch v := strings.TrimSpace(q.Get("ack")); v {
	case "", "server":
	case "client":
		if strings.TrimSpace(q.Get("durable")) == "" {
			return false, false, errors.New("ack=client requires a durable consumer name")
		}
		clientAck = true
	default:
		return false, false, errors.New("ack must be \"server\" or \"client\"")
	}
	return raw, clientAck, nil
}

func sessionLogin(ctx context.Context) string {
	if s := auth.SessionFromContext(ctx); s != nil {
		return s.Username
	}
	return ""
}

func sessionUserID(ctx context.Context) string {
	if s := auth.SessionFromContext(ctx); s != nil {
		return s.UserID
	}
	return ""
}

// inProgressInterval is how often a held delivery is touched with
// InProgress: a third of AckWait, so two touches can be lost before
// JetStream would redeliver.
func (s *webhookService) inProgressInterval() time.Duration {
	if s.inProgressEvery > 0 {
		return s.inProgressEvery
	}
	return s.streamAckWait() / 3
}

// sseWriteTimeout is the write deadline for one chunk of an SSE frame.
func (s *webhookService) sseWriteTimeout() time.Duration {
	if s.writeTimeout > 0 {
		return s.writeTimeout
	}
	return sseFlushTimeout
}

// evictWait bounds how long a new client-ack session waits for the session
// it replaced to release its pending delivery before subscribing. The old
// session notices the eviction between chunks, so it releases within about
// one chunk deadline plus one durable pull; the wait leaves twice that and
// some.
func (s *webhookService) evictWait() time.Duration {
	return 2*s.sseWriteTimeout() + 5*time.Second
}

func (s *webhookService) streamAckWait() time.Duration {
	if s.ackWait > 0 {
		return s.ackWait
	}
	return webhook.DefaultAckWait
}

// awaitClientAck blocks until the client acknowledges the pending delivery
// (true) or the stream ends (false). While waiting it keeps the delivery
// alive with InProgress and keeps the connection alive with SSE pings. When
// the stream ends with the delivery still pending it Naks it for immediate
// redelivery to the durable consumer.
func (a *API) awaitClientAck(ctx context.Context, w io.Writer, rc *http.ResponseController, sess *streamAckSession, msg jetstream.Msg, seq uint64) bool {
	inProgress := time.NewTicker(a.webhooks.inProgressInterval())
	defer inProgress.Stop()
	heartbeat := time.NewTicker(sseHeartbeat)
	defer heartbeat.Stop()
	for {
		select {
		case <-sess.acked:
			return true
		case <-ctx.Done():
			a.nakPending(sess, seq)
			return false
		case <-inProgress.C:
			if sess.hasPending() {
				if err := msg.InProgress(); err != nil {
					a.logger.Warn("webhook_stream_in_progress_failed", "seq", seq, "error", err)
				}
			}
		case <-heartbeat.C:
			if err := a.writeSSE(ctx, w, rc, []byte(": ping\n\n")); err != nil {
				a.nakPending(sess, seq)
				return false
			}
		}
	}
}

// writeSSE writes one SSE frame in chunks of sseChunkSize, resetting the
// write deadline before each chunk and flushing after it. A client that
// keeps reading, however slowly, receives the whole frame; one that stops
// reading (a half-open connection) is cut off within one deadline. Between
// chunks ctx is checked, so an evicted or shutting-down stream stops
// promptly (the client sees a truncated frame and then EOF). Pings and
// small frames are a single chunk under a fixed deadline.
func (a *API) writeSSE(ctx context.Context, w io.Writer, rc *http.ResponseController, frame []byte) error {
	timeout := a.webhooks.sseWriteTimeout()
	for off := 0; off < len(frame); off += sseChunkSize {
		if off > 0 && ctx.Err() != nil {
			return fmt.Errorf("%w: %w", errFrameCut, ctx.Err())
		}
		end := min(off+sseChunkSize, len(frame))
		_ = rc.SetWriteDeadline(time.Now().Add(timeout)) // unsupported by some test writers
		if _, err := w.Write(frame[off:end]); err != nil {
			return err
		}
		if err := rc.Flush(); err != nil {
			return err
		}
	}
	return nil
}

// errFrameCut is returned by writeSSE when it stopped part way through a
// frame because ctx was done.
var errFrameCut = errors.New("SSE frame cut off")

// writeEvicted tells an evicted client-ack stream why it is ending, best
// effort, so a relay can stop instead of reconnecting and evicting the new
// session in turn. When the previous frame was cut off part way, a blank
// line first ends that partial event so the evicted event is parsed as an
// event of its own.
func (a *API) writeEvicted(w io.Writer, rc *http.ResponseController, sess *streamAckSession, frameCut bool) {
	data, _ := json.Marshal(map[string]string{
		"reason":  "another client-ack stream took over this durable",
		"durable": sess.durable,
		"by":      sess.evictedBy,
	})
	frame := fmt.Appendf(nil, "event: %s\ndata: %s\n\n", webhook.EventEvicted, data)
	if frameCut {
		frame = append([]byte("\n\n"), frame...)
	}
	_ = a.writeSSE(context.Background(), w, rc, frame)
}

// respondEvicted answers a client-ack stream request whose session was
// evicted before it started streaming (another client took the durable
// while this one waited to open): a stream holding only the evicted event.
func (a *API) respondEvicted(w http.ResponseWriter, rc *http.ResponseController, sess *streamAckSession) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set(webhook.ClientAckHeader, "1")
	w.WriteHeader(http.StatusOK)
	a.writeEvicted(w, rc, sess, false)
}

// nakPending Naks the session's pending delivery, if the client has not
// acknowledged it, and records why.
func (a *API) nakPending(sess *streamAckSession, seq uint64) {
	m := sess.takePending()
	if m == nil {
		return
	}
	sess.resolve(seq, webhook.AckCodeReleased)
	result := "nak_disconnect"
	switch {
	case sess.evicted.Load():
		result = "nak_evicted"
	case a.ctx != nil && a.ctx.Err() != nil:
		result = "nak_shutdown"
	}
	if err := m.Nak(); err != nil {
		a.logger.Warn("webhook_stream_nak_failed", "seq", seq, "error", err)
	}
	metrics.WebhookStreamAckTotal.WithLabelValues(result).Inc()
}

type webhookStreamAckRequest struct {
	Session  string `json:"session"`
	Sequence uint64 `json:"sequence"`
}

func validSessionToken(s string) bool {
	if len(s) != 2*sessionTokenBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// handleWebhookStreamAck acknowledges the pending delivery of a client-ack
// stream: POST {"session": "<token from the session event>", "sequence": N}.
// 200 once JetStream has confirmed the ack; 400/413 for a malformed body;
// 404 when no live stream of the caller has that session; 409 when the
// session's pending delivery is not N, with a code saying whether N was
// already acked, was released for redelivery, or was never pending.
func (a *API) handleWebhookStreamAck(w http.ResponseWriter, r *http.Request) {
	// Every answer names the capability, so a client can tell this endpoint
	// from a 400 or 404 produced by something else (an older server, a
	// proxy or a WAF).
	w.Header().Set(webhook.ClientAckHeader, "1")
	if a.webhookDisabled(w) {
		return
	}
	badRequest := func(status int, msg string) {
		metrics.WebhookStreamAckTotal.WithLabelValues("bad_request").Inc()
		writeJSON(w, status, map[string]string{"message": msg})
	}
	r.Body = http.MaxBytesReader(w, r.Body, webhookAckBodyLimit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req webhookStreamAckRequest
	if err := dec.Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			badRequest(http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		badRequest(http.StatusBadRequest, "invalid JSON body")
		return
	}
	if dec.More() {
		badRequest(http.StatusBadRequest, "unexpected data after JSON body")
		return
	}
	if !validSessionToken(req.Session) {
		badRequest(http.StatusBadRequest, "session must be the 64-character token from the stream's session event")
		return
	}
	if req.Sequence == 0 {
		badRequest(http.StatusBadRequest, "sequence must be a positive integer")
		return
	}

	sess := a.webhooks.acks.lookup(req.Session, sessionUserID(r.Context()))
	if sess == nil {
		metrics.WebhookStreamAckTotal.WithLabelValues("invalid_session").Inc()
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "No open stream with that session"})
		return
	}
	msg := sess.takeIfSeq(req.Sequence)
	if msg == nil {
		metrics.WebhookStreamAckTotal.WithLabelValues("wrong_sequence").Inc()
		// Say what happened to the delivery: "acked" (an earlier ack was
		// recorded; only its answer was lost), "released" (Nak'd or its
		// ack failed; it will be redelivered), or "wrong_sequence".
		code := sess.resolution(req.Sequence)
		if code == "" {
			code = webhook.AckCodeWrongSequence
		}
		writeJSON(w, http.StatusConflict, map[string]string{"message": "Sequence is not the stream's pending delivery", "code": code})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), webhookAckTimeout)
	defer cancel()
	err := msg.DoubleAck(ctx)
	// The delivery is resolved either way: release the stream to fetch the
	// next one. A failed ack is redelivered by JetStream after AckWait.
	select {
	case sess.acked <- struct{}{}:
	default:
	}
	if err != nil {
		sess.resolve(req.Sequence, webhook.AckCodeReleased)
		a.logger.Warn("webhook_stream_client_ack_failed", "seq", req.Sequence, "error", err)
		metrics.WebhookStreamAckTotal.WithLabelValues("ack_error").Inc()
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"message": "Acknowledgement failed; the delivery will be redelivered",
			"code":    webhook.AckCodeAckError,
		})
		return
	}
	sess.resolve(req.Sequence, webhook.AckCodeAcked)
	metrics.WebhookStreamAckTotal.WithLabelValues("acked").Inc()
	writeJSON(w, http.StatusOK, map[string]any{"message": "acknowledged", "sequence": req.Sequence})
}
