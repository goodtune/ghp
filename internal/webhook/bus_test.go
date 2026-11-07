package webhook

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/goodtune/ghp/internal/config"
)

func testNATSConfig(t *testing.T) config.WebhooksNATSConfig {
	t.Helper()
	c := config.Defaults().Webhooks.NATS
	c.StoreDir = t.TempDir()
	return c
}

func newTestBus(t *testing.T) *Bus {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	b, err := NewBus(ctx, testNATSConfig(t), BusOptions{MaxPayloadBytes: 1 << 20}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewBus: %v", err)
	}
	t.Cleanup(b.Close)
	return b
}

func publishTest(t *testing.T, b *Bus, subject, delivery, event string) uint64 {
	t.Helper()
	h := nats.Header{}
	h.Set(HdrDelivery, delivery)
	h.Set(HdrEvent, event)
	h.Set(HdrReceivedAt, time.Now().UTC().Format(time.RFC3339Nano))
	ack, err := b.Publish(context.Background(), subject, h, []byte(`{"n":"`+delivery+`"}`), delivery)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	return ack.Sequence
}

func TestBus_PublishDedupAndGet(t *testing.T) {
	b := newTestBus(t)
	ctx := context.Background()
	subj := Subject(b.SubjectPrefix(), SubjectParts{Event: "ping"})

	seq := publishTest(t, b, subj, "d-1", "ping")
	if seq != 1 {
		t.Fatalf("first sequence = %d, want 1", seq)
	}

	h := nats.Header{}
	h.Set(HdrDelivery, "d-1")
	ack, err := b.Publish(ctx, subj, h, []byte(`{}`), "d-1")
	if err != nil {
		t.Fatalf("duplicate Publish: %v", err)
	}
	if !ack.Duplicate {
		t.Error("expected duplicate ack for repeated msg id")
	}

	env, err := b.Get(ctx, 1)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if env.Delivery != "d-1" || env.Event != "ping" || env.Subject != subj || env.Sequence != 1 {
		t.Errorf("unexpected envelope: %+v", env)
	}
	if string(env.Payload) != `{"n":"d-1"}` {
		t.Errorf("payload = %s", env.Payload)
	}

	if _, err := b.Get(ctx, 999); err == nil {
		t.Error("expected error fetching missing sequence")
	}

	info, err := b.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != 1 {
		t.Errorf("stream msgs = %d, want 1", info.State.Msgs)
	}
}

func TestBus_Recent(t *testing.T) {
	b := newTestBus(t)
	ctx := context.Background()
	subj := Subject(b.SubjectPrefix(), SubjectParts{Event: "push"})

	empty, err := b.Recent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Errorf("expected empty, got %d", len(empty))
	}

	for i := 1; i <= 5; i++ {
		publishTest(t, b, subj, "d-"+string(rune('0'+i)), "push")
	}
	got, err := b.Recent(ctx, 3)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d, want 3", len(got))
	}
	if got[0].Sequence != 5 || got[1].Sequence != 4 || got[2].Sequence != 3 {
		t.Errorf("expected newest first [5 4 3], got [%d %d %d]", got[0].Sequence, got[1].Sequence, got[2].Sequence)
	}
	if len(got[0].Payload) != 0 {
		t.Error("Recent should be headers-only")
	}
	if got[0].Delivery != "d-5" {
		t.Errorf("delivery = %q", got[0].Delivery)
	}

	all, err := b.Recent(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 {
		t.Errorf("got %d, want 5", len(all))
	}
}

func TestBus_SubscribeFilterAndStart(t *testing.T) {
	b := newTestBus(t)
	ctx := context.Background()
	pr := Subject(b.SubjectPrefix(), SubjectParts{Event: "pull_request", Action: "opened", Owner: "o", Repo: "r"})
	push := Subject(b.SubjectPrefix(), SubjectParts{Event: "push", Owner: "o", Repo: "r"})

	publishTest(t, b, pr, "a", "pull_request")
	publishTest(t, b, push, "b", "push")
	publishTest(t, b, pr, "c", "pull_request")

	t.Run("invalid filter rejected", func(t *testing.T) {
		if _, err := b.Subscribe(ctx, SubscribeOptions{Filter: "other.>"}); err == nil {
			t.Error("expected error for filter outside prefix")
		}
	})

	t.Run("from start with filter", func(t *testing.T) {
		sub, err := b.Subscribe(ctx, SubscribeOptions{Filter: b.SubjectPrefix() + ".*.pull_request.>", FromStart: true})
		if err != nil {
			t.Fatal(err)
		}
		defer sub.Close()
		nctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		e1, _, err := sub.Next(nctx)
		if err != nil {
			t.Fatal(err)
		}
		e2, _, err := sub.Next(nctx)
		if err != nil {
			t.Fatal(err)
		}
		if e1.Delivery != "a" || e2.Delivery != "c" {
			t.Errorf("got %q,%q want a,c", e1.Delivery, e2.Delivery)
		}
	})

	t.Run("start sequence", func(t *testing.T) {
		sub, err := b.Subscribe(ctx, SubscribeOptions{StartSeq: 2})
		if err != nil {
			t.Fatal(err)
		}
		defer sub.Close()
		nctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		e, _, err := sub.Next(nctx)
		if err != nil {
			t.Fatal(err)
		}
		if e.Sequence != 2 || e.Delivery != "b" {
			t.Errorf("got seq %d delivery %q, want 2/b", e.Sequence, e.Delivery)
		}
	})

	t.Run("new only", func(t *testing.T) {
		sub, err := b.Subscribe(ctx, SubscribeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer sub.Close()
		// Nothing retained should arrive; publish a fresh one.
		publishTest(t, b, push, "d", "push")
		nctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		e, _, err := sub.Next(nctx)
		if err != nil {
			t.Fatal(err)
		}
		if e.Delivery != "d" {
			t.Errorf("got %q, want d", e.Delivery)
		}
	})

	t.Run("durable resumes after ack", func(t *testing.T) {
		sub, err := b.Subscribe(ctx, SubscribeOptions{Durable: "cli test", FromStart: true})
		if err != nil {
			t.Fatal(err)
		}
		nctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		e, m, err := sub.Next(nctx)
		if err != nil {
			t.Fatal(err)
		}
		if e.Sequence != 1 {
			t.Fatalf("first durable msg seq = %d, want 1", e.Sequence)
		}
		if err := sub.Ack(m); err != nil {
			t.Fatal(err)
		}
		sub.Close()

		sub2, err := b.Subscribe(ctx, SubscribeOptions{Durable: "cli test", FromStart: true})
		if err != nil {
			t.Fatal(err)
		}
		defer sub2.Close()
		e2, _, err := sub2.Next(nctx)
		if err != nil {
			t.Fatal(err)
		}
		if e2.Sequence != 2 {
			t.Errorf("resumed durable seq = %d, want 2", e2.Sequence)
		}
	})
}

func TestBus_ListenAddrAndClients(t *testing.T) {
	cfg := testNATSConfig(t)
	cfg.Listen = "127.0.0.1:0"
	cfg.AuthToken = "s3cret"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := NewBus(ctx, cfg, BusOptions{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewBus: %v", err)
	}
	defer b.Close()

	if b.ListenAddr() == "" || b.ClientURL() == "" {
		t.Fatalf("expected listen addr and client url, got %q %q", b.ListenAddr(), b.ClientURL())
	}
	if b.NumClients() != 0 {
		t.Errorf("NumClients = %d, want 0", b.NumClients())
	}

	if _, err := nats.Connect(b.ClientURL()); err == nil {
		t.Error("expected connection without credentials to fail")
	}
	if _, err := nats.Connect(b.ClientURL(), nats.Token("s3cret")); err == nil {
		t.Error("expected bare token auth to fail; clients must use the subscriber user")
	}
	nc, err := nats.Connect(b.ClientURL(), nats.UserInfo(SubscriberUser, "s3cret"))
	if err != nil {
		t.Fatalf("connect as subscriber: %v", err)
	}
	defer nc.Close()
	deadline := time.Now().Add(2 * time.Second)
	for b.NumClients() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if b.NumClients() != 1 {
		t.Errorf("NumClients = %d, want 1", b.NumClients())
	}
}

func TestBus_InProcessOnlyHasNoListener(t *testing.T) {
	b := newTestBus(t)
	if b.ListenAddr() != "" || b.ClientURL() != "" {
		t.Errorf("expected no listener, got %q %q", b.ListenAddr(), b.ClientURL())
	}
}

func TestBus_ListenRequiresAuthToken(t *testing.T) {
	cfg := testNATSConfig(t)
	cfg.Listen = "127.0.0.1:0"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := NewBus(ctx, cfg, BusOptions{}, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("expected NewBus to refuse a listener without an auth token")
	}
}

func TestBus_SubscriberCannotPublishOrAlterStream(t *testing.T) {
	cfg := testNATSConfig(t)
	cfg.Listen = "127.0.0.1:0"
	cfg.AuthToken = "s3cret"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := NewBus(ctx, cfg, BusOptions{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewBus: %v", err)
	}
	defer b.Close()
	subj := Subject(b.SubjectPrefix(), SubjectParts{Event: "push"})
	publishTest(t, b, subj, "real-1", "push")

	nc, err := nats.Connect(b.ClientURL(), nats.UserInfo(SubscriberUser, "s3cret"))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}

	// Forging a delivery must be denied: no ack ever arrives.
	pctx, pcancel := context.WithTimeout(ctx, 2*time.Second)
	defer pcancel()
	if _, err := js.Publish(pctx, subj, []byte(`{"forged":true}`)); err == nil {
		t.Error("subscriber was able to publish into the webhook subject space")
	}
	// Destroying the stream must be denied.
	dctx, dcancel := context.WithTimeout(ctx, 2*time.Second)
	defer dcancel()
	if err := js.DeleteStream(dctx, b.StreamName()); err == nil {
		t.Error("subscriber was able to delete the stream")
	}
	// Reading must still work.
	cons, err := js.OrderedConsumer(ctx, b.StreamName(), jetstream.OrderedConsumerConfig{DeliverPolicy: jetstream.DeliverAllPolicy})
	if err != nil {
		t.Fatalf("subscriber could not create a consumer: %v", err)
	}
	m, err := cons.Next(jetstream.FetchMaxWait(5 * time.Second))
	if err != nil {
		t.Fatalf("subscriber could not read: %v", err)
	}
	if m.Headers().Get(HdrDelivery) != "real-1" {
		t.Errorf("unexpected message: %+v", m.Headers())
	}
	info, err := b.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != 1 {
		t.Errorf("stream should still hold exactly the real delivery, got %d msgs", info.State.Msgs)
	}
}

func TestBus_DurableIgnoresStartOnReconnect(t *testing.T) {
	b := newTestBus(t)
	ctx := context.Background()
	subj := Subject(b.SubjectPrefix(), SubjectParts{Event: "push"})
	for i := 1; i <= 3; i++ {
		publishTest(t, b, subj, "d-"+string(rune('0'+i)), "push")
	}
	sub, err := b.Subscribe(ctx, SubscribeOptions{Durable: "resume", FromStart: true})
	if err != nil {
		t.Fatal(err)
	}
	nctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	e, m, err := sub.Next(nctx)
	if err != nil || e.Sequence != 1 {
		t.Fatalf("first: seq=%v err=%v", e, err)
	}
	if err := sub.Ack(m); err != nil {
		t.Fatal(err)
	}
	sub.Close()

	// A reconnecting client (EventSource / CLI) sends Last-Event-ID, which
	// becomes StartSeq. JetStream forbids changing a durable's start policy;
	// the existing consumer must simply be reused.
	sub2, err := b.Subscribe(ctx, SubscribeOptions{Durable: "resume", StartSeq: 2})
	if err != nil {
		t.Fatalf("resubscribe with StartSeq: %v", err)
	}
	defer sub2.Close()
	e2, _, err := sub2.Next(nctx)
	if err != nil {
		t.Fatal(err)
	}
	if e2.Sequence != 2 {
		t.Errorf("resumed seq = %d, want 2", e2.Sequence)
	}

	if _, err := b.Get(ctx, 999); !errors.Is(err, ErrDeliveryNotFound) {
		t.Errorf("Get missing: err = %v, want ErrDeliveryNotFound", err)
	}
}

func TestBus_RecentAfterRetentionPurge(t *testing.T) {
	b := newTestBus(t)
	ctx := context.Background()
	subj := Subject(b.SubjectPrefix(), SubjectParts{Event: "push"})
	for i := 1; i <= 6; i++ {
		publishTest(t, b, subj, "d-"+string(rune('0'+i)), "push")
	}
	// Simulate retention discarding the oldest deliveries: FirstSeq becomes
	// 5, so a limit larger than what remains must clamp to FirstSeq rather
	// than request sequences that no longer exist.
	if err := b.stream.Purge(ctx, jetstream.WithPurgeSequence(5)); err != nil {
		t.Fatalf("purge: %v", err)
	}
	got, err := b.Recent(ctx, 4)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != 2 || got[0].Sequence != 6 || got[1].Sequence != 5 {
		t.Errorf("expected [6 5], got %+v", seqs(got))
	}
}

func seqs(envs []*Envelope) []uint64 {
	out := make([]uint64, 0, len(envs))
	for _, e := range envs {
		out = append(out, e.Sequence)
	}
	return out
}

// A durable subscriber that goes away while its pull is outstanding must not
// leave that pull registered on the server: a delivery published after the
// disconnect would land in the dead pull and wait AckWait (10 s) before
// redelivery to the reconnecting subscriber (#336).
func TestBus_DurableDisconnectDoesNotStrandNextDelivery(t *testing.T) {
	b := newTestBus(t)
	ctx := context.Background()
	subj := Subject(b.SubjectPrefix(), SubjectParts{Event: "star"})

	sub, err := b.Subscribe(ctx, SubscribeOptions{Durable: "stale-pull"})
	if err != nil {
		t.Fatal(err)
	}
	// Mirror the SSE handler: a long per-call deadline (the heartbeat), then
	// the client disconnects while the pull is waiting.
	hctx, hcancel := context.WithTimeout(ctx, 15*time.Second)
	done := make(chan error, 1)
	go func() {
		_, _, err := sub.Next(hctx)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond) // let the pull reach the server
	hcancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Next after cancel: err = %v, want context.Canceled", err)
	}
	sub.Close()

	seq := publishTest(t, b, subj, "after-disconnect", "star")

	sub2, err := b.Subscribe(ctx, SubscribeOptions{Durable: "stale-pull"})
	if err != nil {
		t.Fatal(err)
	}
	defer sub2.Close()
	// Well under AckWait: the delivery must not be stranded.
	nctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	e, _, err := sub2.Next(nctx)
	if err != nil {
		t.Fatalf("resumed Next: %v (delivery stranded in the disconnected pull)", err)
	}
	if e.Sequence != seq {
		t.Errorf("resumed seq = %d, want %d", e.Sequence, seq)
	}
}

// A durable Next cancelled while its pull is in flight must not strand a
// message the server has already handed out: before #336 the fetch was
// bound to the caller's context, so a message arriving as the context was
// cancelled was dropped client-side and stayed pending for AckWait (10 s).
// The race is timing-dependent, so cancel at a spread of offsets around
// the publish and require every delivery to reach the next Next promptly.
func TestBus_DurableCancelledNextDoesNotStrandDelivery(t *testing.T) {
	b := newTestBus(t)
	ctx := context.Background()
	subj := Subject(b.SubjectPrefix(), SubjectParts{Event: "star"})
	sub, err := b.Subscribe(ctx, SubscribeOptions{Durable: "cancel-race"})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()

	for i := 0; i < 40; i++ {
		offset := time.Duration(i%8) * 250 * time.Microsecond
		cctx, cancel := context.WithCancel(ctx)
		got := make(chan *Envelope, 1)
		go func() {
			e, m, err := sub.Next(cctx)
			if err == nil {
				_ = sub.Ack(m)
				got <- e
				return
			}
			got <- nil
		}()
		seq := publishTest(t, b, subj, fmt.Sprintf("race-%d", i), "star")
		time.Sleep(offset)
		cancel()
		if e := <-got; e != nil {
			if e.Sequence != seq {
				t.Fatalf("iteration %d: seq = %d, want %d", i, e.Sequence, seq)
			}
			continue
		}
		nctx, ncancel := context.WithTimeout(ctx, 3*time.Second)
		e, m, err := sub.Next(nctx)
		ncancel()
		if err != nil {
			t.Fatalf("iteration %d: delivery %d stranded after cancelled Next: %v", i, seq, err)
		}
		if e.Sequence != seq {
			t.Fatalf("iteration %d: seq = %d, want %d", i, e.Sequence, seq)
		}
		if err := sub.Ack(m); err != nil {
			t.Fatal(err)
		}
	}
}
