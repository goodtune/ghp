package webhook

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.ngrok.com/ngrok/v2"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/metrics"
)

// Tunnel is an embedded ngrok endpoint serving the webhook ingress.
type Tunnel struct {
	agent  ngrok.Agent
	ln     ngrok.EndpointListener
	srv    *http.Server
	logger *slog.Logger
	once   sync.Once
}

// TunnelOptions carries everything StartTunnel needs beyond the config.
type TunnelOptions struct {
	// Authtoken is the resolved ngrok authtoken (config or NGROK_AUTHTOKEN).
	Authtoken string
	// Handler is served on the tunnel. Pass IngressMux(path, h) so only the
	// webhook path is exposed.
	Handler http.Handler
	// Version is reported to ngrok as client info.
	Version string
}

// EndpointURL converts the configured domain into the URL spec passed to
// ngrok. A bare hostname becomes https://hostname; an explicit scheme is kept.
// Empty returns "" (ngrok assigns a random URL).
func EndpointURL(domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	if strings.Contains(domain, "://") {
		return domain
	}
	return "https://" + domain
}

// StartTunnel connects to ngrok, opens the endpoint and starts serving
// opts.Handler on it. The tunnel is closed when ctx is cancelled.
func StartTunnel(ctx context.Context, cfg config.WebhooksNgrokConfig, opts TunnelOptions, logger *slog.Logger) (*Tunnel, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if opts.Authtoken == "" {
		return nil, errors.New("ngrok authtoken is required")
	}
	if opts.Handler == nil {
		return nil, errors.New("ngrok tunnel handler is required")
	}
	nlog := logger.With("component", "ngrok")
	agent, err := ngrok.NewAgent(
		ngrok.WithAuthtoken(opts.Authtoken),
		ngrok.WithLogger(nlog),
		ngrok.WithClientInfo("ghp", opts.Version),
		ngrok.WithAgentDescription("ghp GitHub webhook ingress"),
		ngrok.WithEventHandler(func(e ngrok.Event) {
			switch e.EventType() {
			case ngrok.EventTypeAgentConnectSucceeded:
				metrics.WebhookNgrokTunnelUp.Set(1)
				nlog.Info("ngrok_connected")
			case ngrok.EventTypeAgentDisconnected:
				metrics.WebhookNgrokTunnelUp.Set(0)
				if d, ok := e.(ngrok.EventAgentDisconnected); ok && d.Error != nil {
					nlog.Warn("ngrok_disconnected", "error", d.Error)
				} else {
					nlog.Warn("ngrok_disconnected")
				}
			}
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("creating ngrok agent: %w", err)
	}

	eopts := []ngrok.EndpointOption{
		ngrok.WithDescription("ghp GitHub webhook ingress"),
		ngrok.WithMetadata("ghp-webhooks"),
	}
	if u := EndpointURL(cfg.Domain); u != "" {
		eopts = append(eopts, ngrok.WithURL(u))
	}
	ln, err := agent.Listen(ctx, eopts...)
	if err != nil {
		_ = agent.Disconnect()
		return nil, fmt.Errorf("opening ngrok endpoint: %w", err)
	}
	metrics.WebhookNgrokTunnelUp.Set(1)

	srv := &http.Server{
		Handler:           opts.Handler,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	t := &Tunnel{agent: agent, ln: ln, srv: srv, logger: nlog}
	go func() {
		if serr := srv.Serve(ln); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			nlog.Error("ngrok_serve_error", "error", serr)
			metrics.WebhookNgrokTunnelUp.Set(0)
		}
	}()
	go func() {
		select {
		case <-ctx.Done():
		case <-ln.Done():
			nlog.Warn("ngrok_endpoint_closed")
		}
		t.Close()
	}()
	nlog.Info("ngrok_endpoint_ready", "url", t.URL(), "id", ln.ID())
	return t, nil
}

// URL returns the public endpoint URL.
func (t *Tunnel) URL() string {
	if t == nil || t.ln == nil || t.ln.URL() == nil {
		return ""
	}
	return t.ln.URL().String()
}

// Close shuts the HTTP server, endpoint and agent session down.
func (t *Tunnel) Close() {
	if t == nil {
		return
	}
	t.once.Do(func() {
		metrics.WebhookNgrokTunnelUp.Set(0)
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = t.srv.Shutdown(sctx)
		_ = t.ln.CloseWithContext(sctx)
		_ = t.agent.Disconnect()
	})
}
