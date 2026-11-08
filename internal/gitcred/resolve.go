package gitcred

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"
	"time"

	"github.com/goodtune/ghp/internal/asciiutil"
	"github.com/goodtune/ghp/internal/permissions"
	"github.com/goodtune/ghp/internal/token"
)

// Token types and setting defaults.
const (
	TypeAgent     = "agent"
	TypeProxy     = "proxy"
	DefaultType   = TypeAgent
	DefaultScopes = "contents:write"
	DefaultTTL    = "1h"
)

// msgAgentForbidden replaces a 403 from the agent-path API calls: those
// endpoints need the ghp admin role, and proxy tokens do not.
const msgAgentForbidden = "the ghp server refused the agent-token request (agent tokens need the ghp admin role); use --type proxy or set GHP_GIT_CM_TYPE=proxy"

// Settings are the raw helper settings after flag > env > default
// precedence has picked a source for each one.
type Settings struct {
	Type, App, Scopes, TTL string // raw values, "" = default
	ScopesExplicit         bool   // came from --scopes or GHP_GIT_CM_SCOPES
	AppFromEnv             bool   // App came from GHP_GIT_CM_APP, not --app
	TypeFromFlag           bool   // Type came from --type
}

// Plan is the validated form of Settings.
type Plan struct {
	Type           string
	App            string
	Scopes         map[string]string // requested
	ScopesExplicit bool
	TTL            time.Duration
}

// Resolved is what a mint needs once the app, installation and effective
// scopes are known.
type Resolved struct {
	Type           string
	AppRecordID    string
	AppName        string
	InstallationID int64
	Scopes         map[string]string // effective
}

// ParseSettings validates s and applies the defaults.
func ParseSettings(s Settings) (Plan, error) {
	typ := s.Type
	if typ == "" {
		typ = DefaultType
	}
	if typ != TypeAgent && typ != TypeProxy {
		return Plan{}, fmt.Errorf("invalid token type %q (want agent or proxy)", typ)
	}

	app := s.App
	if typ == TypeProxy && app != "" {
		// An exported GHP_GIT_CM_APP must not break a helper line that
		// says --type proxy; any other app/proxy combination is a mistake.
		if !s.AppFromEnv || !s.TypeFromFlag {
			return Plan{}, errors.New("--app is only valid with --type agent")
		}
		app = ""
	}

	// An empty value means the default, so it is never explicit.
	rawScopes := s.Scopes
	explicit := s.ScopesExplicit && rawScopes != ""
	if rawScopes == "" {
		rawScopes = DefaultScopes
	}
	scopes, err := token.ParseScopeString(rawScopes)
	if err != nil {
		return Plan{}, fmt.Errorf("invalid scopes: %w", err)
	}

	rawTTL := s.TTL
	if rawTTL == "" {
		rawTTL = DefaultTTL
	}
	if rawTTL == "never" {
		return Plan{}, errors.New("--ttl never is not allowed: cached tokens must expire")
	}
	ttl, err := time.ParseDuration(rawTTL)
	if err != nil || ttl <= 0 {
		return Plan{}, fmt.Errorf("invalid --ttl %q (want a positive duration such as 1h or 90m)", rawTTL)
	}

	return Plan{Type: typ, App: app, Scopes: scopes, ScopesExplicit: explicit, TTL: ttl}, nil
}

// agentForbiddenError reports a 403 on the agent path with a hint to use
// proxy tokens, while errors.Is(err, ErrForbidden) still holds.
type agentForbiddenError struct{ cause error }

func (e *agentForbiddenError) Error() string { return msgAgentForbidden }
func (e *agentForbiddenError) Unwrap() error { return e.cause }

func agentPathError(err error) error {
	if errors.Is(err, ErrForbidden) {
		return &agentForbiddenError{cause: err}
	}
	return err
}

// Resolve turns a plan into mint parameters for target t. Proxy plans need
// no API call; agent plans pick the app, the owner's installation and the
// scopes that installation can grant.
func Resolve(ctx context.Context, c *Client, p Plan, t Target) (Resolved, error) {
	switch p.Type {
	case TypeProxy:
		return Resolved{Type: TypeProxy, Scopes: maps.Clone(p.Scopes)}, nil
	case TypeAgent:
	default:
		return Resolved{}, fmt.Errorf("invalid token type %q (want agent or proxy)", p.Type)
	}

	apps, err := c.ListApps(ctx)
	if err != nil {
		return Resolved{}, agentPathError(err)
	}
	app, err := SelectApp(apps, p.App)
	if err != nil {
		return Resolved{}, err
	}
	insts, err := c.ListInstallations(ctx, app.ID)
	if err != nil {
		return Resolved{}, agentPathError(err)
	}
	inst, err := SelectInstallation(insts, t.Owner, app.Name)
	if err != nil {
		return Resolved{}, err
	}
	scopes, err := EffectiveScopes(p.Scopes, inst.Permissions, p.ScopesExplicit, t.Owner)
	if err != nil {
		return Resolved{}, err
	}
	return Resolved{
		Type:           TypeAgent,
		AppRecordID:    app.ID,
		AppName:        app.Name,
		InstallationID: inst.ID,
		Scopes:         scopes,
	}, nil
}

func appNames(apps []App) string {
	names := make([]string, len(apps))
	for i, a := range apps {
		names[i] = a.Name
	}
	return strings.Join(names, ", ")
}

// SelectApp picks the app whose ID or Name equals selector (ASCII case
// folding). An empty selector picks the default app, else the only app.
func SelectApp(apps []App, selector string) (App, error) {
	if len(apps) == 0 {
		return App{}, errors.New("no GitHub Apps are configured on the ghp server; use --type proxy or ask an admin to add one")
	}
	if selector != "" {
		for _, a := range apps {
			if asciiutil.EqualFold(a.ID, selector) || asciiutil.EqualFold(a.Name, selector) {
				return a, nil
			}
		}
		return App{}, fmt.Errorf("GitHub App %q not found; available apps: %s", selector, appNames(apps))
	}
	for _, a := range apps {
		if a.IsDefault {
			return a, nil
		}
	}
	if len(apps) == 1 {
		return apps[0], nil
	}
	return App{}, fmt.Errorf("several GitHub Apps are configured and none is the default; set --app or GHP_GIT_CM_APP to one of: %s", appNames(apps))
}

// SelectInstallation picks the installation whose account login equals
// owner (ASCII case folding).
func SelectInstallation(insts []Installation, owner, appName string) (Installation, error) {
	for _, inst := range insts {
		if asciiutil.EqualFold(inst.Account.Login, owner) {
			return inst, nil
		}
	}
	return Installation{}, fmt.Errorf("GitHub App %q has no installation for %q; install it there or choose another app with --app", appName, owner)
}

// scopeLevels ranks permission levels; anything else counts as no grant.
var scopeLevels = map[string]int{"read": 1, "write": 2, "admin": 3}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// EffectiveScopes checks each requested scope against the installation's
// permissions, using the GitHub App names permissions.ForGitHubApp maps it
// to. A missing permission is always an error. A lower grant is an error
// for explicit scopes; defaulted scopes are lowered to the lowest granted
// level instead.
func EffectiveScopes(requested, granted map[string]string, explicit bool, owner string) (map[string]string, error) {
	out := make(map[string]string, len(requested))
	for _, p := range sortedKeys(requested) {
		l := requested[p]
		if scopeLevels[l] == 0 {
			return nil, fmt.Errorf("invalid scope level %q for %s", l, p)
		}
		effective := l
		effectiveRank := scopeLevels[l]
		needs := permissions.ForGitHubApp(map[string]string{p: l})
		for _, gp := range sortedKeys(needs) {
			have := granted[gp]
			haveRank := scopeLevels[have]
			if haveRank == 0 {
				return nil, fmt.Errorf("installation for %q does not grant %s, needed for %s:%s", owner, gp, p, l)
			}
			if haveRank >= scopeLevels[needs[gp]] {
				continue
			}
			if explicit {
				return nil, fmt.Errorf("installation for %q grants %s:%s but %s:%s was requested; lower --scopes or GHP_GIT_CM_SCOPES", owner, gp, have, p, l)
			}
			if haveRank < effectiveRank {
				effective, effectiveRank = have, haveRank
			}
		}
		out[p] = effective
	}
	return out, nil
}
