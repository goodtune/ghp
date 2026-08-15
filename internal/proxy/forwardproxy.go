package proxy

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/metrics"
)

// Forward proxy selection layers, from most to least specific. The layer a
// request matched is exported as the `layer` label on
// ghp_forward_proxy_select_total. "ambient" means no ruleset matched and the
// upstream connection falls back to the process environment
// (HTTPS_PROXY/HTTP_PROXY/NO_PROXY via http.ProxyFromEnvironment).
const (
	ForwardProxyLayerToken   = "token"
	ForwardProxyLayerApp     = "app"
	ForwardProxyLayerNet     = "net"
	ForwardProxyLayerSystem  = "system"
	ForwardProxyLayerControl = "control"
	ForwardProxyLayerAmbient = "ambient"
	// ForwardProxyLayerDirect marks non-GitHub control calls (release HEAD
	// probes against the operator's mirror) sent with no proxy at all — the
	// default for those calls unless a control rule opts them in via
	// include_non_github.
	ForwardProxyLayerDirect = "direct"
	// ForwardProxyLayerHeader marks requests whose forward proxy was chosen
	// by the client via the X-GitHub-Proxy-Forward-* request headers
	// (requires forward_proxy.allow_request_header). Client choice beats
	// every ruleset layer.
	ForwardProxyLayerHeader = "header"
)

// Request headers a client may use to select the upstream forward proxy for
// a single request, when forward_proxy.allow_request_header is enabled.
// The HTTP and HTTPS headers are aliases accepting http:// or https:// proxy
// URLs; the SOCKS header accepts socks5:// or socks5h:// URLs. The headers
// are always stripped before the request is forwarded upstream.
const (
	ForwardProxyHeaderHTTP  = "X-GitHub-Proxy-Forward-HTTP"
	ForwardProxyHeaderHTTPS = "X-GitHub-Proxy-Forward-HTTPS"
	ForwardProxyHeaderSOCKS = "X-GitHub-Proxy-Forward-SOCKS"
)

// ExtractClientForwardProxy reads and strips the X-GitHub-Proxy-Forward-*
// headers from r. When enabled is false the headers are stripped and ignored
// (nil, nil). When enabled, at most one proxy may be specified across the
// three headers (duplicate identical values are tolerated); the value must
// be a valid proxy URL with a scheme matching its header family, a host, and
// no query string or fragment. A non-nil error means the request should be
// rejected with 400.
func ExtractClientForwardProxy(r *http.Request, enabled bool) (*url.URL, error) {
	type headerVal struct {
		header  string
		value   string
		schemes []string
	}
	vals := []headerVal{
		{ForwardProxyHeaderHTTP, r.Header.Get(ForwardProxyHeaderHTTP), []string{"http", "https"}},
		{ForwardProxyHeaderHTTPS, r.Header.Get(ForwardProxyHeaderHTTPS), []string{"http", "https"}},
		{ForwardProxyHeaderSOCKS, r.Header.Get(ForwardProxyHeaderSOCKS), []string{"socks5", "socks5h"}},
	}
	// Always strip: the headers are ghp-internal routing hints and must
	// never reach GitHub or any other upstream.
	r.Header.Del(ForwardProxyHeaderHTTP)
	r.Header.Del(ForwardProxyHeaderHTTPS)
	r.Header.Del(ForwardProxyHeaderSOCKS)

	if !enabled {
		return nil, nil
	}

	var chosen *headerVal
	for i := range vals {
		v := &vals[i]
		if v.value == "" {
			continue
		}
		if chosen != nil && chosen.value != v.value {
			return nil, fmt.Errorf("conflicting forward proxy headers: %s and %s specify different proxies", chosen.header, v.header)
		}
		if chosen == nil {
			chosen = v
		}
	}
	if chosen == nil {
		return nil, nil
	}

	u, err := url.Parse(chosen.value)
	if err != nil {
		return nil, fmt.Errorf("%s: malformed proxy URL", chosen.header)
	}
	schemeOK := false
	for _, s := range chosen.schemes {
		if u.Scheme == s {
			schemeOK = true
			break
		}
	}
	if !schemeOK {
		return nil, fmt.Errorf("%s: scheme must be one of %s", chosen.header, strings.Join(chosen.schemes, ", "))
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%s: host is required", chosen.header)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%s: query string and fragment are not allowed", chosen.header)
	}
	return u, nil
}

// compiledTarget is a validated upstream forward proxy within a ruleset.
type compiledTarget struct {
	u      *url.URL
	weight int
}

// compiledRuleset is the in-memory, validated form of a ForwardProxyRuleset.
// Selection state (the round-robin counter) lives here so it survives across
// requests but resets naturally on Reload.
type compiledRuleset struct {
	name        string
	algorithm   string
	targets     []compiledTarget
	totalWeight int
	rr          atomic.Uint64
}

// netRule binds a source CIDR to a ruleset.
type netRule struct {
	cidr    *net.IPNet
	ruleset *compiledRuleset
}

// routeTable is the immutable compiled snapshot the router serves selections
// from. A whole new table is built on Reload and swapped in under the lock,
// so in-flight selections never observe a partially-updated state.
type routeTable struct {
	byToken map[string]*compiledRuleset
	byApp   map[string]*compiledRuleset
	byNet   []netRule // sorted most-specific prefix first
	system  *compiledRuleset
	control *compiledRuleset // ghp's own control-plane traffic
	// controlNonGitHub extends the control ruleset to ghp control calls
	// targeting non-GitHub hosts; set from the winning control rule's
	// include_non_github flag.
	controlNonGitHub bool
}

// ForwardProxyRouter selects which upstream forward proxy (if any) an
// outbound GitHub request should egress through. Rulesets are runtime
// configuration loaded from the database; Reload rebuilds the in-memory
// route table. Selection precedence is most-specific first:
// token rule → app rule → net (CIDR) rule → system rule → ambient
// environment (http.ProxyFromEnvironment).
type ForwardProxyRouter struct {
	store  database.Store
	logger *slog.Logger

	// ambient is the fallback proxy function used when no ruleset matches.
	// Defaults to http.ProxyFromEnvironment; overridable for tests (that
	// function caches the process environment on first use).
	ambient func(*http.Request) (*url.URL, error)

	mu    sync.RWMutex
	table *routeTable
}

// NewForwardProxyRouter creates a router with an empty route table. Call
// Reload to populate it from the store.
func NewForwardProxyRouter(store database.Store, logger *slog.Logger) *ForwardProxyRouter {
	if logger == nil {
		logger = slog.Default()
	}
	return &ForwardProxyRouter{
		store:   store,
		logger:  logger,
		ambient: http.ProxyFromEnvironment,
		table:   &routeTable{byToken: map[string]*compiledRuleset{}, byApp: map[string]*compiledRuleset{}},
	}
}

// Reload rebuilds the route table from the store. Disabled rulesets, rulesets
// with no valid proxy target, and malformed rules are skipped with a warning —
// a bad ruleset must never take down egress for the rest of the system. When
// multiple rulesets bind the same token, app, or the system layer, the first
// by name wins deterministically and a warning is logged.
func (fr *ForwardProxyRouter) Reload(ctx context.Context) error {
	rulesets, err := fr.store.ListForwardProxyRulesets(ctx)
	if err != nil {
		return err
	}

	// ListForwardProxyRulesets orders by name; sort defensively so conflict
	// resolution stays deterministic even if a backend deviates.
	sort.Slice(rulesets, func(i, j int) bool { return rulesets[i].Name < rulesets[j].Name })

	table := &routeTable{
		byToken: map[string]*compiledRuleset{},
		byApp:   map[string]*compiledRuleset{},
	}
	active := 0
	for _, rs := range rulesets {
		if !rs.Enabled {
			continue
		}
		compiled := fr.compile(rs)
		if compiled == nil {
			continue
		}
		bound := false
		for _, rule := range rs.Rules {
			switch rule.Type {
			case database.ForwardProxyRuleToken:
				if existing, ok := table.byToken[rule.Value]; ok {
					fr.logger.Warn("forward proxy: token bound by multiple rulesets; first by name wins",
						"token_id", rule.Value, "kept", existing.name, "ignored", rs.Name)
					continue
				}
				table.byToken[rule.Value] = compiled
				bound = true
			case database.ForwardProxyRuleApp:
				if existing, ok := table.byApp[rule.Value]; ok {
					fr.logger.Warn("forward proxy: app bound by multiple rulesets; first by name wins",
						"app_record_id", rule.Value, "kept", existing.name, "ignored", rs.Name)
					continue
				}
				table.byApp[rule.Value] = compiled
				bound = true
			case database.ForwardProxyRuleNet:
				_, cidr, err := net.ParseCIDR(rule.Value)
				if err != nil {
					fr.logger.Warn("forward proxy: skipping invalid CIDR rule",
						"ruleset", rs.Name, "cidr", rule.Value, "error", err)
					continue
				}
				table.byNet = append(table.byNet, netRule{cidr: cidr, ruleset: compiled})
				bound = true
			case database.ForwardProxyRuleSystem:
				if table.system != nil {
					fr.logger.Warn("forward proxy: multiple system rulesets; first by name wins",
						"kept", table.system.name, "ignored", rs.Name)
					continue
				}
				table.system = compiled
				bound = true
			case database.ForwardProxyRuleControl:
				if table.control != nil && table.control != compiled {
					fr.logger.Warn("forward proxy: multiple control rulesets; first by name wins",
						"kept", table.control.name, "ignored", rs.Name)
					continue
				}
				table.control = compiled
				if rule.IncludeNonGitHub {
					table.controlNonGitHub = true
				}
				bound = true
			default:
				fr.logger.Warn("forward proxy: skipping unknown rule type",
					"ruleset", rs.Name, "type", rule.Type)
			}
		}
		if bound {
			active++
		}
	}

	// Most-specific CIDR wins; break prefix-length ties by ruleset name for
	// determinism.
	sort.SliceStable(table.byNet, func(i, j int) bool {
		li, _ := table.byNet[i].cidr.Mask.Size()
		lj, _ := table.byNet[j].cidr.Mask.Size()
		if li != lj {
			return li > lj
		}
		return table.byNet[i].ruleset.name < table.byNet[j].ruleset.name
	})

	fr.mu.Lock()
	fr.table = table
	fr.mu.Unlock()

	metrics.ForwardProxyRulesetsActive.Set(float64(active))
	fr.logger.Info("forward proxy route table reloaded",
		"rulesets", active,
		"token_rules", len(table.byToken),
		"app_rules", len(table.byApp),
		"net_rules", len(table.byNet),
		"system_rule", table.system != nil,
		"control_rule", table.control != nil)
	return nil
}

// compile validates a ruleset's targets and returns nil when none are usable.
func (fr *ForwardProxyRouter) compile(rs *database.ForwardProxyRuleset) *compiledRuleset {
	c := &compiledRuleset{name: rs.Name, algorithm: rs.Algorithm}
	for i, p := range rs.Proxies {
		u, err := url.Parse(p.URL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" && u.Scheme != "socks5h") {
			// Log a redacted form only: target URLs may embed proxy
			// credentials in the userinfo component.
			redacted := "(unparseable)"
			if err == nil {
				redacted = u.Redacted()
			}
			fr.logger.Warn("forward proxy: skipping invalid proxy target",
				"ruleset", rs.Name, "index", i, "url", redacted)
			continue
		}
		w := p.Weight
		if w < 1 {
			w = 1
		}
		c.targets = append(c.targets, compiledTarget{u: u, weight: w})
		c.totalWeight += w
	}
	if len(c.targets) == 0 {
		fr.logger.Warn("forward proxy: ruleset has no valid proxy targets; skipping", "ruleset", rs.Name)
		return nil
	}
	return c
}

// StartRefresh reloads the route table on the given interval until ctx is
// cancelled. Admin API mutations reload immediately on the instance that
// served them; the periodic refresh is what propagates changes to other
// instances in HA deployments.
func (fr *ForwardProxyRouter) StartRefresh(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := fr.Reload(ctx); err != nil {
					fr.logger.Warn("forward proxy: periodic reload failed", "error", err)
				}
			}
		}
	}()
}

// Select returns the forward proxy URL for a request, together with the name
// of the matched ruleset and the layer that matched. A nil URL with layer
// "ambient" means no ruleset applies and the caller should fall back to the
// process environment.
func (fr *ForwardProxyRouter) Select(clientIP, tokenID, appID string) (*url.URL, string, string) {
	fr.mu.RLock()
	table := fr.table
	fr.mu.RUnlock()

	if tokenID != "" {
		if rs, ok := table.byToken[tokenID]; ok {
			return rs.pick(clientIP), rs.name, ForwardProxyLayerToken
		}
	}
	if appID != "" {
		if rs, ok := table.byApp[appID]; ok {
			return rs.pick(clientIP), rs.name, ForwardProxyLayerApp
		}
	}
	if clientIP != "" && len(table.byNet) > 0 {
		if ip := net.ParseIP(clientIP); ip != nil {
			for _, nr := range table.byNet {
				if nr.cidr.Contains(ip) {
					return nr.ruleset.pick(clientIP), nr.ruleset.name, ForwardProxyLayerNet
				}
			}
		}
	}
	if table.system != nil {
		return table.system.pick(clientIP), table.system.name, ForwardProxyLayerSystem
	}
	return nil, "", ForwardProxyLayerAmbient
}

// SelectControl returns the forward proxy URL for ghp's own control-plane
// traffic (OAuth flows and token refresh, App installation token minting,
// username resolution, release redirect HEAD probes). Precedence: control
// rule → system rule → ambient. Token, app, and net layers never apply —
// control traffic is not attributable to a client.
func (fr *ForwardProxyRouter) SelectControl() (*url.URL, string, string) {
	fr.mu.RLock()
	table := fr.table
	fr.mu.RUnlock()

	if table.control != nil {
		return table.control.pick(""), table.control.name, ForwardProxyLayerControl
	}
	if table.system != nil {
		return table.system.pick(""), table.system.name, ForwardProxyLayerSystem
	}
	return nil, "", ForwardProxyLayerAmbient
}

// pick chooses a target according to the ruleset's algorithm. clientIP is
// only consulted by the sticky algorithm.
func (c *compiledRuleset) pick(clientIP string) *url.URL {
	if len(c.targets) == 1 {
		return c.targets[0].u
	}
	switch c.algorithm {
	case database.ForwardProxyAlgoWeighted:
		return c.pickByWeight(rand.IntN(c.totalWeight))
	case database.ForwardProxyAlgoSticky:
		h := fnv.New32a()
		h.Write([]byte(clientIP))
		return c.pickByWeight(int(h.Sum32() % uint32(c.totalWeight)))
	default: // round_robin
		n := c.rr.Add(1) - 1
		return c.targets[n%uint64(len(c.targets))].u
	}
}

// pickByWeight maps a point in [0, totalWeight) onto the cumulative weight
// distribution of the targets.
func (c *compiledRuleset) pickByWeight(point int) *url.URL {
	for _, t := range c.targets {
		if point < t.weight {
			return t.u
		}
		point -= t.weight
	}
	return c.targets[len(c.targets)-1].u
}

// ProxyFunc returns a per-request proxy selection function suitable for
// http.Transport.Proxy. It reads the request identity (client IP, token ID,
// app record ID) from the outbound request's context — populated by the
// server middleware and the token-resolving handlers on the inbound request,
// and inherited by outbound requests created with the inbound context — and
// falls back to http.ProxyFromEnvironment when no ruleset matches or the
// request carries no route info (e.g. internal OAuth refresh calls).
func (fr *ForwardProxyRouter) ProxyFunc() func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		info := ForwardProxyInfoFromContext(req.Context())
		if info == nil {
			return fr.ambient(req)
		}
		if info.Control {
			return fr.controlProxy(req)
		}
		// A client-specified proxy (validated at the edge, feature-gated by
		// forward_proxy.allow_request_header) beats every ruleset layer —
		// the client may know something the operator's rules cannot. It is
		// only honoured once a ghx_/gha_ token has been resolved: without
		// the identity gate, an unauthenticated caller on the passthrough
		// path could use the header to make ghp dial arbitrary internal
		// host:port targets (SSRF/port-scan). Unauthenticated requests fall
		// through to normal ruleset selection.
		if info.ClientProxy != nil && info.TokenID != "" {
			metrics.ObserveDecision(metrics.StageForwardProxySelection, info.TokenType, 0)
			metrics.ForwardProxySelectTotal.WithLabelValues("", ForwardProxyLayerHeader).Inc()
			metrics.ForwardProxyClientSpecifiedTotal.WithLabelValues(info.ClientProxy.Scheme, info.TokenType).Inc()
			return info.ClientProxy, nil
		}
		start := time.Now()
		u, ruleset, layer := fr.Select(info.ClientIP, info.TokenID, info.AppID)
		metrics.ObserveDecision(metrics.StageForwardProxySelection, info.TokenType, time.Since(start))
		metrics.ForwardProxySelectTotal.WithLabelValues(ruleset, layer).Inc()
		if u == nil {
			return fr.ambient(req)
		}
		return u, nil
	}
}

// controlProxy resolves the egress proxy for a control-plane request and
// records the routing decision.
func (fr *ForwardProxyRouter) controlProxy(req *http.Request) (*url.URL, error) {
	start := time.Now()
	u, ruleset, layer := fr.SelectControl()
	metrics.ObserveDecision(metrics.StageForwardProxySelection, "", time.Since(start))
	metrics.ForwardProxySelectTotal.WithLabelValues(ruleset, layer).Inc()
	if u == nil {
		return fr.ambient(req)
	}
	return u, nil
}

// ControlProxyFunc returns a proxy selection function that always routes as
// control-plane traffic, regardless of request context. Use it for internal
// clients whose destination is GitHub (App installation token minting,
// username resolution, OAuth login flows).
func (fr *ForwardProxyRouter) ControlProxyFunc() func(*http.Request) (*url.URL, error) {
	return fr.controlProxy
}

// nonGitHubControlProxy resolves the egress proxy for ghp control calls that
// target non-GitHub hosts (release redirect HEAD probes against the
// operator's mirror). Those hosts are typically internal, so the default is
// DIRECT — no proxy at all, not even the ambient environment. A control rule
// with include_non_github=true opts them into the control ruleset instead.
func (fr *ForwardProxyRouter) nonGitHubControlProxy(_ *http.Request) (*url.URL, error) {
	fr.mu.RLock()
	table := fr.table
	fr.mu.RUnlock()

	start := time.Now()
	if table.control != nil && table.controlNonGitHub {
		u := table.control.pick("")
		metrics.ObserveDecision(metrics.StageForwardProxySelection, "", time.Since(start))
		metrics.ForwardProxySelectTotal.WithLabelValues(table.control.name, ForwardProxyLayerControl).Inc()
		return u, nil
	}
	metrics.ObserveDecision(metrics.StageForwardProxySelection, "", time.Since(start))
	metrics.ForwardProxySelectTotal.WithLabelValues("", ForwardProxyLayerDirect).Inc()
	return nil, nil
}

// NewForwardProxyTransport returns an http.Transport cloned from
// http.DefaultTransport whose Proxy function consults the router per request.
// All outbound GitHub transports (API proxy, github.com passthrough,
// codeload, Copilot) share one instance so connection pools are reused per
// selected proxy.
func NewForwardProxyTransport(fr *ForwardProxyRouter) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = fr.ProxyFunc()
	return t
}

// NewForwardProxyControlTransport returns a transport that routes every
// request as control-plane traffic (control rule → system rule → ambient).
// It is installed on ghp's internal clients so operators can pin the proxy's
// own GitHub traffic to a dedicated egress path.
func NewForwardProxyControlTransport(fr *ForwardProxyRouter) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = fr.ControlProxyFunc()
	return t
}

// NewForwardProxyNonGitHubControlTransport returns a transport for ghp
// control calls whose destination is not GitHub (release redirect HEAD
// probes). Requests are sent direct unless a control rule sets
// include_non_github, in which case they follow the control ruleset.
func NewForwardProxyNonGitHubControlTransport(fr *ForwardProxyRouter) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = fr.nonGitHubControlProxy
	return t
}
