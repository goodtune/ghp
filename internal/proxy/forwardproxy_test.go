package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/goodtune/ghp/internal/database"
)

// fpStore is a minimal Store stub for router tests: only
// ListForwardProxyRulesets is implemented.
type fpStore struct {
	database.Store
	rulesets []*database.ForwardProxyRuleset
	err      error
}

func (s *fpStore) ListForwardProxyRulesets(ctx context.Context) ([]*database.ForwardProxyRuleset, error) {
	return s.rulesets, s.err
}

func reloadedRouter(t *testing.T, rulesets ...*database.ForwardProxyRuleset) *ForwardProxyRouter {
	t.Helper()
	fr := NewForwardProxyRouter(&fpStore{rulesets: rulesets}, nil)
	if err := fr.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	return fr
}

func TestForwardProxyRouter_LayerPrecedence(t *testing.T) {
	fr := reloadedRouter(t,
		&database.ForwardProxyRuleset{
			Name: "app-rs", Algorithm: database.ForwardProxyAlgoRoundRobin, Enabled: true,
			Proxies: []database.ForwardProxyEntry{{URL: "http://app-proxy:3128"}},
			Rules:   []database.ForwardProxyRule{{Type: database.ForwardProxyRuleApp, Value: "app-1"}},
		},
		&database.ForwardProxyRuleset{
			Name: "net-rs", Algorithm: database.ForwardProxyAlgoRoundRobin, Enabled: true,
			Proxies: []database.ForwardProxyEntry{{URL: "http://net-proxy:3128"}},
			Rules:   []database.ForwardProxyRule{{Type: database.ForwardProxyRuleNet, Value: "10.0.0.0/8"}},
		},
		&database.ForwardProxyRuleset{
			Name: "sys-rs", Algorithm: database.ForwardProxyAlgoRoundRobin, Enabled: true,
			Proxies: []database.ForwardProxyEntry{{URL: "http://sys-proxy:3128"}},
			Rules:   []database.ForwardProxyRule{{Type: database.ForwardProxyRuleSystem}},
		},
		&database.ForwardProxyRuleset{
			Name: "tok-rs", Algorithm: database.ForwardProxyAlgoRoundRobin, Enabled: true,
			Proxies: []database.ForwardProxyEntry{{URL: "http://tok-proxy:3128"}},
			Rules:   []database.ForwardProxyRule{{Type: database.ForwardProxyRuleToken, Value: "tok-1"}},
		},
	)

	tests := []struct {
		name                     string
		clientIP, tokenID, appID string
		wantHost, wantLayer      string
	}{
		{"token wins over all", "10.1.2.3", "tok-1", "app-1", "tok-proxy:3128", ForwardProxyLayerToken},
		{"app wins over net and system", "10.1.2.3", "other-token", "app-1", "app-proxy:3128", ForwardProxyLayerApp},
		{"net wins over system", "10.1.2.3", "", "", "net-proxy:3128", ForwardProxyLayerNet},
		{"system catches the rest", "192.168.1.1", "", "", "sys-proxy:3128", ForwardProxyLayerSystem},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _, layer := fr.Select(tt.clientIP, tt.tokenID, tt.appID)
			if u == nil || u.Host != tt.wantHost {
				t.Fatalf("Select() url = %v, want host %s", u, tt.wantHost)
			}
			if layer != tt.wantLayer {
				t.Errorf("Select() layer = %q, want %q", layer, tt.wantLayer)
			}
		})
	}
}

func TestForwardProxyRouter_AmbientFallback(t *testing.T) {
	fr := reloadedRouter(t) // empty table

	u, ruleset, layer := fr.Select("10.0.0.1", "tok", "app")
	if u != nil || ruleset != "" || layer != ForwardProxyLayerAmbient {
		t.Fatalf("Select() = (%v, %q, %q), want (nil, \"\", ambient)", u, ruleset, layer)
	}
}

func TestForwardProxyRouter_DisabledAndInvalidRulesetsSkipped(t *testing.T) {
	fr := reloadedRouter(t,
		&database.ForwardProxyRuleset{
			Name: "disabled", Algorithm: database.ForwardProxyAlgoRoundRobin, Enabled: false,
			Proxies: []database.ForwardProxyEntry{{URL: "http://disabled-proxy:3128"}},
			Rules:   []database.ForwardProxyRule{{Type: database.ForwardProxyRuleSystem}},
		},
		&database.ForwardProxyRuleset{
			Name: "no-valid-targets", Algorithm: database.ForwardProxyAlgoRoundRobin, Enabled: true,
			Proxies: []database.ForwardProxyEntry{{URL: "not a url"}, {URL: "ftp://nope:21"}},
			Rules:   []database.ForwardProxyRule{{Type: database.ForwardProxyRuleSystem}},
		},
		&database.ForwardProxyRuleset{
			Name: "bad-cidr", Algorithm: database.ForwardProxyAlgoRoundRobin, Enabled: true,
			Proxies: []database.ForwardProxyEntry{{URL: "http://ok-proxy:3128"}},
			Rules:   []database.ForwardProxyRule{{Type: database.ForwardProxyRuleNet, Value: "not-a-cidr"}},
		},
	)

	if u, _, layer := fr.Select("10.0.0.1", "", ""); u != nil || layer != ForwardProxyLayerAmbient {
		t.Fatalf("Select() = (%v, %q), want ambient fallback", u, layer)
	}
}

func TestForwardProxyRouter_MostSpecificCIDRWins(t *testing.T) {
	fr := reloadedRouter(t,
		&database.ForwardProxyRuleset{
			Name: "wide", Algorithm: database.ForwardProxyAlgoRoundRobin, Enabled: true,
			Proxies: []database.ForwardProxyEntry{{URL: "http://wide-proxy:3128"}},
			Rules:   []database.ForwardProxyRule{{Type: database.ForwardProxyRuleNet, Value: "10.0.0.0/8"}},
		},
		&database.ForwardProxyRuleset{
			Name: "narrow", Algorithm: database.ForwardProxyAlgoRoundRobin, Enabled: true,
			Proxies: []database.ForwardProxyEntry{{URL: "http://narrow-proxy:3128"}},
			Rules:   []database.ForwardProxyRule{{Type: database.ForwardProxyRuleNet, Value: "10.42.0.0/16"}},
		},
	)

	if u, _, _ := fr.Select("10.42.1.1", "", ""); u == nil || u.Host != "narrow-proxy:3128" {
		t.Fatalf("Select(10.42.1.1) = %v, want narrow-proxy:3128", u)
	}
	if u, _, _ := fr.Select("10.7.1.1", "", ""); u == nil || u.Host != "wide-proxy:3128" {
		t.Fatalf("Select(10.7.1.1) = %v, want wide-proxy:3128", u)
	}
	if u, _, layer := fr.Select("172.16.0.1", "", ""); u != nil || layer != ForwardProxyLayerAmbient {
		t.Fatalf("Select(172.16.0.1) = (%v, %q), want ambient", u, layer)
	}
}

func TestForwardProxyRouter_RoundRobinCycles(t *testing.T) {
	fr := reloadedRouter(t,
		&database.ForwardProxyRuleset{
			Name: "rr", Algorithm: database.ForwardProxyAlgoRoundRobin, Enabled: true,
			Proxies: []database.ForwardProxyEntry{
				{URL: "http://p1:3128"}, {URL: "http://p2:3128"}, {URL: "http://p3:3128"},
			},
			Rules: []database.ForwardProxyRule{{Type: database.ForwardProxyRuleSystem}},
		},
	)

	seen := make(map[string]int)
	for i := 0; i < 6; i++ {
		u, _, _ := fr.Select("", "", "")
		seen[u.Host]++
	}
	for _, host := range []string{"p1:3128", "p2:3128", "p3:3128"} {
		if seen[host] != 2 {
			t.Errorf("round robin: %s selected %d times over 6 requests, want 2 (all: %v)", host, seen[host], seen)
		}
	}
}

func TestForwardProxyRouter_WeightedDistribution(t *testing.T) {
	fr := reloadedRouter(t,
		&database.ForwardProxyRuleset{
			Name: "weighted", Algorithm: database.ForwardProxyAlgoWeighted, Enabled: true,
			Proxies: []database.ForwardProxyEntry{
				{URL: "http://heavy:3128", Weight: 80},
				{URL: "http://light:3128", Weight: 20},
			},
			Rules: []database.ForwardProxyRule{{Type: database.ForwardProxyRuleSystem}},
		},
	)

	seen := make(map[string]int)
	const n = 5000
	for i := 0; i < n; i++ {
		u, _, _ := fr.Select("", "", "")
		seen[u.Host]++
	}
	// 80/20 split: allow generous tolerance to keep the test deterministic
	// enough (P(fail) is negligible with ±10 percentage points at n=5000).
	if frac := float64(seen["heavy:3128"]) / n; frac < 0.70 || frac > 0.90 {
		t.Errorf("weighted: heavy fraction = %.3f, want ~0.80 (counts: %v)", frac, seen)
	}
}

func TestForwardProxyRouter_StickyIsDeterministicPerIP(t *testing.T) {
	fr := reloadedRouter(t,
		&database.ForwardProxyRuleset{
			Name: "sticky", Algorithm: database.ForwardProxyAlgoSticky, Enabled: true,
			Proxies: []database.ForwardProxyEntry{
				{URL: "http://s1:3128"}, {URL: "http://s2:3128"}, {URL: "http://s3:3128"},
			},
			Rules: []database.ForwardProxyRule{{Type: database.ForwardProxyRuleSystem}},
		},
	)

	first := make(map[string]string)
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "192.168.7.9"} {
		u, _, _ := fr.Select(ip, "", "")
		first[ip] = u.Host
		for i := 0; i < 20; i++ {
			if u2, _, _ := fr.Select(ip, "", ""); u2.Host != first[ip] {
				t.Fatalf("sticky: ip %s flapped from %s to %s", ip, first[ip], u2.Host)
			}
		}
	}
}

func TestForwardProxyRouter_ProxyFunc(t *testing.T) {
	fr := reloadedRouter(t,
		&database.ForwardProxyRuleset{
			Name: "tok-rs", Algorithm: database.ForwardProxyAlgoRoundRobin, Enabled: true,
			Proxies: []database.ForwardProxyEntry{{URL: "http://tok-proxy:3128"}},
			Rules:   []database.ForwardProxyRule{{Type: database.ForwardProxyRuleToken, Value: "tok-1"}},
		},
	)
	// Stub the ambient fallback: http.ProxyFromEnvironment caches the process
	// environment on first use, so tests can't rely on t.Setenv.
	fr.ambient = func(*http.Request) (*url.URL, error) { return nil, nil }
	proxyFn := fr.ProxyFunc()

	// No route info on the context → ambient fallback.
	bare := httptest.NewRequest(http.MethodGet, "https://api.github.com/", nil)
	if u, err := proxyFn(bare); err != nil || u != nil {
		t.Fatalf("ProxyFunc(no info) = (%v, %v), want (nil, nil)", u, err)
	}

	// Route info present and token bound → ruleset proxy.
	r := httptest.NewRequest(http.MethodGet, "https://api.github.com/", nil)
	r = PrepareForwardProxyInfo(r, "10.0.0.1")
	SetForwardProxyIdentity(r, "tok-1", "", "proxy")
	out, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://api.github.com/user", nil)
	u, err := proxyFn(out)
	if err != nil || u == nil || u.Host != "tok-proxy:3128" {
		t.Fatalf("ProxyFunc(token info) = (%v, %v), want tok-proxy:3128", u, err)
	}

	// Route info present but nothing matches → ambient fallback.
	r2 := httptest.NewRequest(http.MethodGet, "https://api.github.com/", nil)
	r2 = PrepareForwardProxyInfo(r2, "10.0.0.1")
	out2, _ := http.NewRequestWithContext(r2.Context(), http.MethodGet, "https://api.github.com/user", nil)
	if u2, err := proxyFn(out2); err != nil || u2 != nil {
		t.Fatalf("ProxyFunc(unmatched info) = (%v, %v), want (nil, nil)", u2, err)
	}
}

func TestForwardProxyRouter_ReloadSwapsTable(t *testing.T) {
	store := &fpStore{rulesets: []*database.ForwardProxyRuleset{{
		Name: "sys", Algorithm: database.ForwardProxyAlgoRoundRobin, Enabled: true,
		Proxies: []database.ForwardProxyEntry{{URL: "http://old-proxy:3128"}},
		Rules:   []database.ForwardProxyRule{{Type: database.ForwardProxyRuleSystem}},
	}}}
	fr := NewForwardProxyRouter(store, nil)
	if err := fr.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if u, _, _ := fr.Select("", "", ""); u == nil || u.Host != "old-proxy:3128" {
		t.Fatalf("Select before swap = %v, want old-proxy:3128", u)
	}

	store.rulesets = nil
	if err := fr.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if u, _, layer := fr.Select("", "", ""); u != nil || layer != ForwardProxyLayerAmbient {
		t.Fatalf("Select after swap = (%v, %q), want ambient", u, layer)
	}
}

func TestForwardProxyRouter_ControlLayer(t *testing.T) {
	fr := reloadedRouter(t,
		&database.ForwardProxyRuleset{
			Name: "control-rs", Algorithm: database.ForwardProxyAlgoRoundRobin, Enabled: true,
			Proxies: []database.ForwardProxyEntry{{URL: "http://control-proxy:3128"}},
			Rules:   []database.ForwardProxyRule{{Type: database.ForwardProxyRuleControl}},
		},
		&database.ForwardProxyRuleset{
			Name: "sys-rs", Algorithm: database.ForwardProxyAlgoRoundRobin, Enabled: true,
			Proxies: []database.ForwardProxyEntry{{URL: "http://sys-proxy:3128"}},
			Rules:   []database.ForwardProxyRule{{Type: database.ForwardProxyRuleSystem}},
		},
	)

	// Control traffic uses the control rule ahead of system.
	u, ruleset, layer := fr.SelectControl()
	if u == nil || u.Host != "control-proxy:3128" || layer != ForwardProxyLayerControl || ruleset != "control-rs" {
		t.Fatalf("SelectControl() = (%v, %q, %q), want control-proxy via control layer", u, ruleset, layer)
	}

	// Regular traffic never matches the control rule.
	if u, _, layer := fr.Select("10.0.0.1", "", ""); u == nil || u.Host != "sys-proxy:3128" || layer != ForwardProxyLayerSystem {
		t.Fatalf("Select() = (%v, %q), want sys-proxy via system layer", u, layer)
	}
}

func TestForwardProxyRouter_ControlFallsBackToSystem(t *testing.T) {
	fr := reloadedRouter(t,
		&database.ForwardProxyRuleset{
			Name: "sys-rs", Algorithm: database.ForwardProxyAlgoRoundRobin, Enabled: true,
			Proxies: []database.ForwardProxyEntry{{URL: "http://sys-proxy:3128"}},
			Rules:   []database.ForwardProxyRule{{Type: database.ForwardProxyRuleSystem}},
		},
	)
	if u, _, layer := fr.SelectControl(); u == nil || u.Host != "sys-proxy:3128" || layer != ForwardProxyLayerSystem {
		t.Fatalf("SelectControl() = (%v, %q), want system fallback", u, layer)
	}

	empty := reloadedRouter(t)
	if u, _, layer := empty.SelectControl(); u != nil || layer != ForwardProxyLayerAmbient {
		t.Fatalf("SelectControl() on empty table = (%v, %q), want ambient", u, layer)
	}
}

func TestForwardProxyRouter_ControlTransportAndContext(t *testing.T) {
	fr := reloadedRouter(t,
		&database.ForwardProxyRuleset{
			Name: "control-rs", Algorithm: database.ForwardProxyAlgoRoundRobin, Enabled: true,
			Proxies: []database.ForwardProxyEntry{{URL: "http://control-proxy:3128"}},
			Rules:   []database.ForwardProxyRule{{Type: database.ForwardProxyRuleControl}},
		},
	)
	fr.ambient = func(*http.Request) (*url.URL, error) { return nil, nil }

	// The dedicated control transport routes without any context marker.
	ct := NewForwardProxyControlTransport(fr)
	bare := httptest.NewRequest(http.MethodGet, "https://api.github.com/app/installations", nil)
	if u, err := ct.Proxy(bare); err != nil || u == nil || u.Host != "control-proxy:3128" {
		t.Fatalf("control transport Proxy() = (%v, %v), want control-proxy:3128", u, err)
	}

	// WithForwardProxyControl overrides request-derived route info on the
	// shared transport (e.g. OAuth refresh inside a proxied request).
	r := httptest.NewRequest(http.MethodGet, "https://api.github.com/", nil)
	r = PrepareForwardProxyInfo(r, "10.0.0.1")
	SetForwardProxyIdentity(r, "tok-1", "", "proxy")
	ctlCtx := WithForwardProxyControl(r.Context())
	out, _ := http.NewRequestWithContext(ctlCtx, http.MethodPost, "https://github.com/login/oauth/access_token", nil)
	if u, err := fr.ProxyFunc()(out); err != nil || u == nil || u.Host != "control-proxy:3128" {
		t.Fatalf("ProxyFunc(control ctx) = (%v, %v), want control-proxy:3128", u, err)
	}
}

func TestForwardProxyRouter_NonGitHubControlDirectByDefault(t *testing.T) {
	// No rules at all → direct.
	empty := reloadedRouter(t)
	req := httptest.NewRequest(http.MethodHead, "https://mirror.internal/org/repo/releases/download/v1/a.tgz", nil)
	if u, err := empty.nonGitHubControlProxy(req); err != nil || u != nil {
		t.Fatalf("nonGitHubControlProxy(no rules) = (%v, %v), want direct (nil, nil)", u, err)
	}

	// Control rule without include_non_github → still direct, even though
	// GitHub-destined control traffic is routed.
	fr := reloadedRouter(t,
		&database.ForwardProxyRuleset{
			Name: "control-rs", Algorithm: database.ForwardProxyAlgoRoundRobin, Enabled: true,
			Proxies: []database.ForwardProxyEntry{{URL: "http://control-proxy:3128"}},
			Rules:   []database.ForwardProxyRule{{Type: database.ForwardProxyRuleControl}},
		},
	)
	if u, err := fr.nonGitHubControlProxy(req); err != nil || u != nil {
		t.Fatalf("nonGitHubControlProxy(control without flag) = (%v, %v), want direct", u, err)
	}
	if u, _, _ := fr.SelectControl(); u == nil || u.Host != "control-proxy:3128" {
		t.Fatalf("SelectControl() = %v, want control-proxy (GitHub-destined control still routed)", u)
	}

	// System rule alone never captures non-GitHub control calls.
	sys := reloadedRouter(t,
		&database.ForwardProxyRuleset{
			Name: "sys-rs", Algorithm: database.ForwardProxyAlgoRoundRobin, Enabled: true,
			Proxies: []database.ForwardProxyEntry{{URL: "http://sys-proxy:3128"}},
			Rules:   []database.ForwardProxyRule{{Type: database.ForwardProxyRuleSystem}},
		},
	)
	if u, err := sys.nonGitHubControlProxy(req); err != nil || u != nil {
		t.Fatalf("nonGitHubControlProxy(system only) = (%v, %v), want direct", u, err)
	}
}

func TestForwardProxyRouter_NonGitHubControlOptIn(t *testing.T) {
	fr := reloadedRouter(t,
		&database.ForwardProxyRuleset{
			Name: "control-rs", Algorithm: database.ForwardProxyAlgoRoundRobin, Enabled: true,
			Proxies: []database.ForwardProxyEntry{{URL: "http://control-proxy:3128"}},
			Rules:   []database.ForwardProxyRule{{Type: database.ForwardProxyRuleControl, IncludeNonGitHub: true}},
		},
	)
	req := httptest.NewRequest(http.MethodHead, "https://mirror.internal/org/repo/releases/download/v1/a.tgz", nil)
	if u, err := fr.nonGitHubControlProxy(req); err != nil || u == nil || u.Host != "control-proxy:3128" {
		t.Fatalf("nonGitHubControlProxy(opt-in) = (%v, %v), want control-proxy:3128", u, err)
	}

	// The transport constructor wires the same behaviour.
	nt := NewForwardProxyNonGitHubControlTransport(fr)
	if u, err := nt.Proxy(req); err != nil || u == nil || u.Host != "control-proxy:3128" {
		t.Fatalf("non-GitHub control transport Proxy() = (%v, %v), want control-proxy:3128", u, err)
	}
}
