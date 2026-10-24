package webhook

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/metrics"
)

// Bus is the embedded NATS JetStream server plus the in-process client ghp
// uses to publish verified deliveries and to serve subscribers.
type Bus struct {
	cfg    config.WebhooksNATSConfig
	logger *slog.Logger

	srv    *natsserver.Server
	nc     *nats.Conn
	js     jetstream.JetStream
	stream jetstream.Stream

	closeOnce sync.Once
}

// BusOptions carries the startup parameters NewBus needs beyond the NATS
// config section.
type BusOptions struct {
	// MaxPayloadBytes bounds a single published message. Set it to the
	// ingress body cap plus headroom for headers.
	MaxPayloadBytes int64
	// TLS, when non-nil and cfg.TLS is true, is served on the client
	// listener.
	TLS *tls.Config
}

// NewBus starts the embedded server, connects in-process, and ensures the
// delivery stream exists with the configured limits. It blocks until the
// server is ready to accept connections (or fails within a few seconds).
func NewBus(ctx context.Context, cfg config.WebhooksNATSConfig, opts BusOptions, logger *slog.Logger) (*Bus, error) {
	if logger == nil {
		logger = slog.Default()
	}
	so := &natsserver.Options{
		ServerName: "ghp-webhooks",
		JetStream:  true,
		StoreDir:   cfg.StoreDir,
		NoSigs:     true,
		NoLog:      false,
	}
	if opts.MaxPayloadBytes > 0 {
		// Leave headroom for headers above the HTTP body cap.
		so.MaxPayload = int32(opts.MaxPayloadBytes + 64*1024)
	}
	if cfg.Listen == "" {
		so.DontListen = true
	} else {
		host, portStr, err := net.SplitHostPort(cfg.Listen)
		if err != nil {
			return nil, fmt.Errorf("webhooks.nats.listen: %w", err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("webhooks.nats.listen port: %w", err)
		}
		so.Host = host
		so.Port = port
		if host == "" {
			so.Host = "0.0.0.0"
		}
	}
	if cfg.AuthToken != "" {
		so.Authorization = cfg.AuthToken
	}
	if cfg.TLS {
		if opts.TLS == nil {
			return nil, errors.New("webhooks.nats.tls is enabled but no TLS certificates are configured")
		}
		tcfg := opts.TLS.Clone()
		tcfg.NextProtos = nil // NATS is not HTTP; drop h2/http1.1 ALPN.
		so.TLSConfig = tcfg
		so.TLS = true
		so.TLSTimeout = 2
	}

	srv, err := natsserver.NewServer(so)
	if err != nil {
		return nil, fmt.Errorf("creating embedded NATS server: %w", err)
	}
	srv.SetLoggerV2(&slogNATSLogger{logger: logger.With("component", "nats")}, false, false, false)
	srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		srv.Shutdown()
		return nil, errors.New("embedded NATS server did not become ready within 10s")
	}

	connOpts := []nats.Option{nats.InProcessServer(srv), nats.Name("ghp"), nats.MaxReconnects(-1)}
	if cfg.AuthToken != "" {
		// Token auth applies to every client connection, including the
		// in-process one.
		connOpts = append(connOpts, nats.Token(cfg.AuthToken))
	}
	nc, err := nats.Connect("", connOpts...)
	if err != nil {
		srv.Shutdown()
		return nil, fmt.Errorf("connecting to embedded NATS server: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		srv.Shutdown()
		return nil, fmt.Errorf("initialising JetStream: %w", err)
	}

	sc := jetstream.StreamConfig{
		Name:        cfg.Stream,
		Description: "GitHub webhook deliveries received by ghp",
		Subjects:    []string{cfg.SubjectPrefix + ".>"},
		Retention:   jetstream.LimitsPolicy,
		Storage:     jetstream.FileStorage,
		Discard:     jetstream.DiscardOld,
		MaxAge:      cfg.MaxAge,
		MaxBytes:    cfg.MaxBytes,
		Duplicates:  cfg.DedupeWindow,
	}
	if opts.MaxPayloadBytes > 0 {
		sc.MaxMsgSize = int32(opts.MaxPayloadBytes + 64*1024)
	}
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stream, err := js.CreateOrUpdateStream(sctx, sc)
	if err != nil {
		nc.Close()
		srv.Shutdown()
		return nil, fmt.Errorf("ensuring JetStream stream %q: %w", cfg.Stream, err)
	}

	b := &Bus{cfg: cfg, logger: logger, srv: srv, nc: nc, js: js, stream: stream}
	logger.Info("webhook_bus_ready",
		"stream", cfg.Stream,
		"subject_prefix", cfg.SubjectPrefix,
		"store_dir", cfg.StoreDir,
		"listen", b.ListenAddr(),
	)
	return b, nil
}

// SubjectPrefix returns the configured subject prefix.
func (b *Bus) SubjectPrefix() string { return b.cfg.SubjectPrefix }

// StreamName returns the configured stream name.
func (b *Bus) StreamName() string { return b.cfg.Stream }

// ListenAddr returns the address native NATS clients can connect to, or ""
// when the server is in-process only.
func (b *Bus) ListenAddr() string {
	if b.cfg.Listen == "" {
		return ""
	}
	if addr := b.srv.Addr(); addr != nil {
		return addr.String()
	}
	return b.cfg.Listen
}

// ClientURL returns the nats:// (or tls://) URL for native clients, or "".
func (b *Bus) ClientURL() string {
	if b.cfg.Listen == "" {
		return ""
	}
	return b.srv.ClientURL()
}

// NumClients returns the number of connected native NATS clients, excluding
// ghp's own in-process connection.
func (b *Bus) NumClients() int {
	n := b.srv.NumClients() - 1
	if n < 0 {
		n = 0
	}
	return n
}

// Publish stores one delivery. msgID is used for JetStream deduplication
// within the configured window; the returned PubAck reports whether the
// server considered the message a duplicate.
func (b *Bus) Publish(ctx context.Context, subject string, header nats.Header, data []byte, msgID string) (*jetstream.PubAck, error) {
	msg := &nats.Msg{Subject: subject, Header: header, Data: data}
	var opts []jetstream.PublishOpt
	if msgID != "" {
		opts = append(opts, jetstream.WithMsgID(msgID))
	}
	return b.js.PublishMsg(ctx, msg, opts...)
}

// Info returns the current stream info.
func (b *Bus) Info(ctx context.Context) (*jetstream.StreamInfo, error) {
	return b.stream.Info(ctx)
}

// Get fetches a single stored delivery by stream sequence. Returns
// jetstream.ErrMsgNotFound when the sequence does not exist (or was
// discarded by retention).
func (b *Bus) Get(ctx context.Context, seq uint64) (*Envelope, error) {
	raw, err := b.stream.GetMsg(ctx, seq)
	if err != nil {
		return nil, err
	}
	return EnvelopeFromRaw(raw), nil
}

// Recent returns up to limit of the most recent deliveries, newest first,
// without payloads.
func (b *Bus) Recent(ctx context.Context, limit int) ([]*Envelope, error) {
	if limit <= 0 {
		limit = 50
	}
	info, err := b.stream.Info(ctx)
	if err != nil {
		return nil, err
	}
	st := info.State
	if st.Msgs == 0 || st.LastSeq == 0 {
		return []*Envelope{}, nil
	}
	start := uint64(1)
	if st.LastSeq > uint64(limit) {
		start = st.LastSeq - uint64(limit) + 1
	}
	if start < st.FirstSeq {
		start = st.FirstSeq
	}
	cons, err := b.stream.OrderedConsumer(ctx, jetstream.OrderedConsumerConfig{
		DeliverPolicy: jetstream.DeliverByStartSequencePolicy,
		OptStartSeq:   start,
		HeadersOnly:   true,
	})
	if err != nil {
		return nil, err
	}
	want := int(st.LastSeq - start + 1)
	out := make([]*Envelope, 0, want)
	batch, err := cons.FetchNoWait(want)
	if err != nil {
		return nil, err
	}
	for m := range batch.Messages() {
		env, err := EnvelopeFromMsg(m)
		if err != nil {
			continue
		}
		out = append(out, env)
	}
	if err := batch.Error(); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	// Newest first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// SubscribeOptions controls a Subscribe call.
type SubscribeOptions struct {
	// Filter is a NATS subject filter under the configured prefix. Empty
	// means every delivery ("{prefix}.>").
	Filter string
	// StartSeq, when > 0, starts delivery at that stream sequence. When 0,
	// FromStart decides between all retained deliveries and new ones only.
	StartSeq uint64
	// FromStart delivers every retained message before new ones when
	// StartSeq is 0. The default (false) delivers only new deliveries.
	FromStart bool
	// Durable, when set, names a durable pull consumer whose position is
	// retained across subscriber reconnects. Messages must be acknowledged
	// via Subscription.Ack. Durable names are sanitised to a single NATS
	// token. When empty an ephemeral ordered consumer is used and Ack is a
	// no-op.
	Durable string
}

// Subscription iterates stored deliveries for one subscriber.
//
// Ephemeral (ordered) subscriptions prefetch through a MessagesContext.
// Durable subscriptions deliberately fetch one message at a time: a
// prefetched-but-unacknowledged message would otherwise sit pending for the
// full AckWait after a subscriber disconnects, delaying its redelivery to
// the reconnecting subscriber by up to 30 s. Webhook volumes are low enough
// that the extra round trip per message is irrelevant.
type Subscription struct {
	msgs    jetstream.MessagesContext // ephemeral
	cons    jetstream.Consumer        // durable
	durable bool
}

// Next blocks until the next delivery is available or ctx is done.
func (s *Subscription) Next(ctx context.Context) (*Envelope, jetstream.Msg, error) {
	var (
		m   jetstream.Msg
		err error
	)
	if s.durable {
		for {
			m, err = s.cons.Next(jetstream.FetchContext(ctx))
			if err == nil {
				break
			}
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			if errors.Is(err, jetstream.ErrNoMessages) || errors.Is(err, nats.ErrTimeout) || errors.Is(err, jetstream.ErrNoHeartbeat) {
				continue
			}
			return nil, nil, err
		}
	} else {
		m, err = s.msgs.Next(jetstream.NextContext(ctx))
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			return nil, nil, err
		}
	}
	env, err := EnvelopeFromMsg(m)
	if err != nil {
		return nil, nil, err
	}
	return env, m, nil
}

// Ack acknowledges a delivery on a durable subscription. For ephemeral
// subscriptions it is a no-op.
func (s *Subscription) Ack(m jetstream.Msg) error {
	if !s.durable || m == nil {
		return nil
	}
	return m.Ack()
}

// Nak returns a durable delivery to the stream for immediate redelivery.
// Call it when the message could not be handed to the subscriber (e.g. the
// client disconnected mid-write) so it does not sit pending for AckWait.
func (s *Subscription) Nak(m jetstream.Msg) error {
	if !s.durable || m == nil {
		return nil
	}
	return m.Nak()
}

// Close stops the iterator.
func (s *Subscription) Close() {
	if s.msgs != nil {
		s.msgs.Stop()
	}
}

// Subscribe creates a subscription per opts.
func (b *Bus) Subscribe(ctx context.Context, opts SubscribeOptions) (*Subscription, error) {
	filter := opts.Filter
	if filter == "" {
		filter = b.cfg.SubjectPrefix + ".>"
	}
	if !ValidFilter(b.cfg.SubjectPrefix, filter) {
		return nil, fmt.Errorf("invalid subject filter %q: must be under %q", filter, b.cfg.SubjectPrefix)
	}

	policy := jetstream.DeliverNewPolicy
	var startSeq uint64
	switch {
	case opts.StartSeq > 0:
		policy = jetstream.DeliverByStartSequencePolicy
		startSeq = opts.StartSeq
	case opts.FromStart:
		policy = jetstream.DeliverAllPolicy
	}

	var (
		cons jetstream.Consumer
		err  error
	)
	if opts.Durable != "" {
		name := SanitizeToken(opts.Durable)
		cons, err = b.stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
			Durable:        name,
			FilterSubjects: []string{filter},
			DeliverPolicy:  policy,
			OptStartSeq:    startSeq,
			AckPolicy:      jetstream.AckExplicitPolicy,
			// Subscribers ack as soon as the event is flushed to the client,
			// so a short AckWait keeps redelivery prompt when a client
			// disconnects mid-fetch without over-delivering to healthy ones.
			AckWait:       10 * time.Second,
			MaxAckPending: 256,
			// Durable position survives reconnects but is garbage-collected
			// after a long absence so abandoned CLIs don't pin storage.
			InactiveThreshold: 7 * 24 * time.Hour,
		})
	} else {
		cons, err = b.stream.OrderedConsumer(ctx, jetstream.OrderedConsumerConfig{
			FilterSubjects: []string{filter},
			DeliverPolicy:  policy,
			OptStartSeq:    startSeq,
		})
	}
	if err != nil {
		return nil, err
	}
	if opts.Durable != "" {
		return &Subscription{cons: cons, durable: true}, nil
	}
	msgs, err := cons.Messages(jetstream.PullMaxMessages(64))
	if err != nil {
		return nil, err
	}
	return &Subscription{msgs: msgs}, nil
}

// StartMetricsRefresh periodically copies stream size and native client
// count into the Prometheus gauges until ctx is cancelled.
func (b *Bus) StartMetricsRefresh(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	refresh := func() {
		ictx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if info, err := b.stream.Info(ictx); err == nil {
			metrics.WebhookStreamMessages.Set(float64(info.State.Msgs))
			metrics.WebhookStreamBytes.Set(float64(info.State.Bytes))
		}
		metrics.WebhookSubscribersActive.WithLabelValues("nats").Set(float64(b.NumClients()))
	}
	refresh()
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				refresh()
			}
		}
	}()
}

// Close disconnects the in-process client and shuts the server down,
// waiting for it to finish.
func (b *Bus) Close() {
	b.closeOnce.Do(func() {
		if b.nc != nil {
			b.nc.Close()
		}
		if b.srv != nil {
			b.srv.Shutdown()
			b.srv.WaitForShutdown()
		}
	})
}

// slogNATSLogger adapts nats-server's logger interface to slog.
type slogNATSLogger struct {
	logger *slog.Logger
}

func (l *slogNATSLogger) Noticef(format string, v ...any) {
	l.logger.Info(strings.TrimSpace(fmt.Sprintf(format, v...)))
}
func (l *slogNATSLogger) Warnf(format string, v ...any) {
	l.logger.Warn(strings.TrimSpace(fmt.Sprintf(format, v...)))
}
func (l *slogNATSLogger) Fatalf(format string, v ...any) {
	l.logger.Error(strings.TrimSpace(fmt.Sprintf(format, v...)), "fatal", true)
}
func (l *slogNATSLogger) Errorf(format string, v ...any) {
	l.logger.Error(strings.TrimSpace(fmt.Sprintf(format, v...)))
}
func (l *slogNATSLogger) Debugf(format string, v ...any) {
	l.logger.Debug(strings.TrimSpace(fmt.Sprintf(format, v...)))
}
func (l *slogNATSLogger) Tracef(format string, v ...any) {
	l.logger.Debug(strings.TrimSpace(fmt.Sprintf(format, v...)), "trace", true)
}
