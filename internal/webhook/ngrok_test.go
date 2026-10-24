package webhook

import (
	"context"
	"net/http"
	"testing"

	"github.com/goodtune/ghp/internal/config"
)

func TestEndpointURL(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"  ", ""},
		{"hooks.example.ngrok.app", "https://hooks.example.ngrok.app"},
		{"https://hooks.example.ngrok.app", "https://hooks.example.ngrok.app"},
		{"tcp://1.tcp.ngrok.io:12345", "tcp://1.tcp.ngrok.io:12345"},
	}
	for _, tt := range tests {
		if got := EndpointURL(tt.in); got != tt.want {
			t.Errorf("EndpointURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestStartTunnel_RequiresAuthtokenAndHandler(t *testing.T) {
	ctx := context.Background()
	h := http.NotFoundHandler()
	if _, err := StartTunnel(ctx, config.WebhooksNgrokConfig{}, TunnelOptions{Handler: h}, nil); err == nil {
		t.Error("expected error without authtoken")
	}
	if _, err := StartTunnel(ctx, config.WebhooksNgrokConfig{}, TunnelOptions{Authtoken: "x"}, nil); err == nil {
		t.Error("expected error without handler")
	}
}

func TestTunnel_NilSafe(t *testing.T) {
	var tun *Tunnel
	if tun.URL() != "" {
		t.Error("nil tunnel URL should be empty")
	}
	tun.Close() // must not panic
}
