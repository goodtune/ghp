package webhook

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

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
		t.Error("expected connection without token to fail")
	}
	nc, err := nats.Connect(b.ClientURL(), nats.Token("s3cret"))
	if err != nil {
		t.Fatalf("connect with token: %v", err)
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
