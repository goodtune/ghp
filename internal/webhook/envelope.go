package webhook

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Message headers ghp sets on every published delivery, in addition to the
// GitHub-* copies of the inbound request headers. Subscribers that consume
// via native NATS clients read these directly; the SSE stream and CLI expose
// them through Envelope.
const (
	HdrDelivery        = "GitHub-Delivery"
	HdrEvent           = "GitHub-Event"
	HdrHookID          = "GitHub-Hook-ID"
	HdrTargetType      = "GitHub-Hook-Installation-Target-Type"
	HdrTargetID        = "GitHub-Hook-Installation-Target-ID"
	HdrAppRecordID     = "GHP-App-Record-ID"
	HdrAppName         = "GHP-App-Name"
	HdrAction          = "GHP-Action"
	HdrRepository      = "GHP-Repository"
	HdrInstallationID  = "GHP-Installation-ID"
	HdrSender          = "GHP-Sender"
	HdrReceivedAt      = "GHP-Received-At"
	HdrOriginalContent = "GHP-Original-Content-Type"
	HdrContentType     = "Content-Type"
	// HdrSignature256 and HdrSignature keep GitHub's original
	// X-Hub-Signature-256 and (when sent) X-Hub-Signature values, and
	// HdrUserAgent the original User-Agent, so that a delivery can be
	// replayed to another receiver exactly as GitHub sent it (ghp webhooks
	// tail --relay). Deliveries stored before these headers existed do not
	// have them.
	HdrSignature256 = "Hub-Signature-256"
	HdrSignature    = "Hub-Signature"
	HdrUserAgent    = "GHP-Original-User-Agent"
)

// Client-ack stream protocol, shared by the server (internal/server) and
// the relay (internal/webhook/relay) so the two cannot drift apart.
const (
	// ClientAckHeader is set to "1" on every response of the ack endpoint
	// and on client-ack stream responses, so a client can tell a server
	// that honours ack=client from an older one (or a proxy).
	ClientAckHeader = "GHP-Webhook-Client-Ack"
	// StreamAckPath is the client-ack endpoint.
	StreamAckPath = "/api/webhooks/stream/ack"
	// EventSession is the SSE event that opens a client-ack stream; its
	// data is {"session": "<token>"}.
	EventSession = "session"
	// EventEvicted ends a client-ack stream that another one took over;
	// its data is {"reason", "durable", "by"}.
	EventEvicted = "evicted"
	// AckCodeAcked (409): that sequence was already acknowledged.
	AckCodeAcked = "acked"
	// AckCodeReleased (409): that sequence was returned to the durable and
	// will be redelivered.
	AckCodeReleased = "released"
	// AckCodeWrongSequence (409): that sequence was never pending.
	AckCodeWrongSequence = "wrong_sequence"
	// AckCodeAckError (502): the JetStream ack failed; the server has
	// released the delivery for redelivery, so the client must not retry.
	AckCodeAckError = "ack_error"
)

// Envelope is the subscriber-facing representation of one stored delivery.
// It is what the admin SSE stream emits as the event data and what the
// ghp webhooks tail command prints. Payload is omitted for headers-only
// listings.
type Envelope struct {
	Subject        string    `json:"subject"`
	Sequence       uint64    `json:"sequence"`
	StoredAt       time.Time `json:"stored_at"`
	Delivery       string    `json:"delivery"`
	Event          string    `json:"event"`
	Action         string    `json:"action,omitempty"`
	HookID         string    `json:"hook_id,omitempty"`
	TargetType     string    `json:"target_type,omitempty"`
	TargetID       string    `json:"target_id,omitempty"`
	AppRecordID    string    `json:"app_record_id,omitempty"`
	AppName        string    `json:"app_name,omitempty"`
	Repository     string    `json:"repository,omitempty"`
	InstallationID int64     `json:"installation_id,omitempty"`
	Sender         string    `json:"sender,omitempty"`
	ReceivedAt     time.Time `json:"received_at"`
	// Signature256 and SignatureSHA1 are GitHub's original X-Hub-Signature-256
	// and X-Hub-Signature header values. UserAgent and OriginalContentType
	// are the original User-Agent and Content-Type request headers. They are
	// empty for deliveries stored before ghp kept them.
	Signature256        string            `json:"signature_256,omitempty"`
	SignatureSHA1       string            `json:"signature_sha1,omitempty"`
	UserAgent           string            `json:"user_agent,omitempty"`
	OriginalContentType string            `json:"original_content_type,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	Payload             json.RawMessage   `json:"payload,omitempty"`
	// PayloadBase64 is the exact stored message data, base64-encoded. It is
	// only set when a stream subscriber asks for it (raw=1). Unlike Payload,
	// which encoding/json re-encodes, it is byte-for-byte what GitHub signed
	// for JSON deliveries.
	PayloadBase64 []byte `json:"payload_base64,omitempty"`
}

// envelopeFromHeader builds the shared part of an Envelope from a message
// header set.
func envelopeFromHeader(subject string, seq uint64, storedAt time.Time, h nats.Header, data []byte) *Envelope {
	get := func(k string) string {
		if h == nil {
			return ""
		}
		return h.Get(k)
	}
	e := &Envelope{
		Subject:     subject,
		Sequence:    seq,
		StoredAt:    storedAt,
		Delivery:    get(HdrDelivery),
		Event:       get(HdrEvent),
		Action:      get(HdrAction),
		HookID:      get(HdrHookID),
		TargetType:  get(HdrTargetType),
		TargetID:    get(HdrTargetID),
		AppRecordID: get(HdrAppRecordID),
		AppName:     get(HdrAppName),
		Repository:  get(HdrRepository),
		Sender:      get(HdrSender),

		Signature256:        get(HdrSignature256),
		SignatureSHA1:       get(HdrSignature),
		UserAgent:           get(HdrUserAgent),
		OriginalContentType: get(HdrOriginalContent),
	}
	if v := get(HdrInstallationID); v != "" {
		e.InstallationID, _ = strconv.ParseInt(v, 10, 64)
	}
	if v := get(HdrReceivedAt); v != "" {
		e.ReceivedAt, _ = time.Parse(time.RFC3339Nano, v)
	}
	if len(h) > 0 {
		e.Headers = make(map[string]string, len(h))
		for k, vs := range h {
			if len(vs) > 0 {
				e.Headers[k] = vs[0]
			}
		}
	}
	if len(data) > 0 {
		if json.Valid(data) {
			e.Payload = json.RawMessage(data)
		} else {
			// Never emit invalid JSON inside an SSE/JSON envelope; quote it.
			quoted, _ := json.Marshal(string(data))
			e.Payload = quoted
		}
	}
	return e
}

// EnvelopeFromMsg converts a JetStream message into an Envelope.
func EnvelopeFromMsg(m jetstream.Msg) (*Envelope, error) {
	md, err := m.Metadata()
	if err != nil {
		return nil, err
	}
	return envelopeFromHeader(m.Subject(), md.Sequence.Stream, md.Timestamp, m.Headers(), m.Data()), nil
}

// EnvelopeFromRaw converts a directly fetched stream message into an
// Envelope.
func EnvelopeFromRaw(m *jetstream.RawStreamMsg) *Envelope {
	return envelopeFromHeader(m.Subject, m.Sequence, m.Time, m.Header, m.Data)
}
