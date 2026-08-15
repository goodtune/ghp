package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/netutil"
	"github.com/goodtune/ghp/internal/proxy"
)

func TestForwardProxyRouteInfoMiddleware(t *testing.T) {
	newCfg := func(allow bool) *config.Config {
		return &config.Config{ForwardProxy: config.ForwardProxyConfig{AllowRequestHeader: allow}}
	}

	t.Run("seeds client IP and strips headers when disabled", func(t *testing.T) {
		var info *proxy.ForwardProxyRouteInfo
		var upstreamHeader string
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info = proxy.ForwardProxyInfoFromContext(r.Context())
			upstreamHeader = r.Header.Get(proxy.ForwardProxyHeaderHTTPS)
		})
		h := forwardProxyRouteInfoMiddleware(inner, newCfg(false), netutil.IPHeaderNone)

		req := httptest.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
		req.RemoteAddr = "10.9.8.7:4242"
		req.Header.Set(proxy.ForwardProxyHeaderHTTPS, "http://team-proxy:3128")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		if info == nil || info.ClientIP != "10.9.8.7" {
			t.Fatalf("route info = %+v, want ClientIP 10.9.8.7", info)
		}
		if info.ClientProxy != nil {
			t.Errorf("ClientProxy = %v, want nil when feature disabled", info.ClientProxy)
		}
		if upstreamHeader != "" {
			t.Error("proxy header reached the inner handler; must be stripped")
		}
	})

	t.Run("records client proxy when enabled", func(t *testing.T) {
		var info *proxy.ForwardProxyRouteInfo
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info = proxy.ForwardProxyInfoFromContext(r.Context())
		})
		h := forwardProxyRouteInfoMiddleware(inner, newCfg(true), netutil.IPHeaderNone)

		req := httptest.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
		req.Header.Set(proxy.ForwardProxyHeaderHTTPS, "http://team-proxy:3128")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if info == nil || info.ClientProxy == nil || info.ClientProxy.Host != "team-proxy:3128" {
			t.Fatalf("route info = %+v, want ClientProxy team-proxy:3128", info)
		}
	})

	t.Run("invalid header value returns 400 when enabled", func(t *testing.T) {
		called := false
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
		h := forwardProxyRouteInfoMiddleware(inner, newCfg(true), netutil.IPHeaderNone)

		req := httptest.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
		req.Header.Set(proxy.ForwardProxyHeaderSOCKS, "http://wrong-scheme:3128")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
		if called {
			t.Error("inner handler called despite invalid proxy header")
		}
	})
}
