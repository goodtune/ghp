package proxy

import (
	"context"
	"hash/fnv"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sort"
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
	ForwardProxyLayerAmbient = "ambient"
)

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
		"system_rule", table.system != nil)
	return nil
}

// compile validates a ruleset's targets and returns nil when none are usable.
func (fr *ForwardProxyRouter) compile(rs *database.ForwardProxyRuleset) *compiledRuleset {
	c := &compiledRuleset{name: rs.Name, algorithm: rs.Algorithm}
	for _, p := range rs.Proxies {
		u, err := url.Parse(p.URL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" && u.Scheme != "socks5h") {
			fr.logger.Warn("forward proxy: skipping invalid proxy target",
				"ruleset", rs.Name, "url", p.URL)
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
