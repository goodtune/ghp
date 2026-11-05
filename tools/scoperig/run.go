package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/goodtune/ghp/tools/scoperig/exec"
	"github.com/goodtune/ghp/tools/scoperig/fixtures"
	"github.com/goodtune/ghp/tools/scoperig/redact"
	"github.com/goodtune/ghp/tools/scoperig/report"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
	"github.com/goodtune/ghp/tools/scoperig/tokens"
)

// exitError carries a process exit code with its cause.
type exitError struct {
	code int
	err  error
	// plain marks a message known to hold no secret. redact.Pattern also
	// matches variable names such as GHP_SERVER_URL, so such messages are
	// printed unredacted to stay readable.
	plain bool
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit status %d", e.code)
	}
	return e.err.Error()
}
func (e *exitError) Unwrap() error { return e.err }

// runDeps are the injectable collaborators of runRig.
type runDeps struct {
	HTTP  *http.Client
	Now   func() time.Time
	RunID func() string // default: UTC "20060102T1504Z" + "-" + 4 hex chars
	Exec  func(kind string) (exec.Executor, error)
	// Pace converts the instance token-create rate into the delay between
	// creates. Default tokens.Pace.
	Pace func(ratePerMin int) time.Duration
	// Out receives progress, warnings and leftover token ids (never values).
	Out io.Writer
	// OnManager, if set, is called once the token manager exists (the CLI
	// uses it to wire the second-signal handler).
	OnManager func(*tokens.Manager)
}

func (d *runDeps) defaults() {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.RunID == nil {
		now := d.Now
		d.RunID = func() string { return newRunID(now()) }
	}
	if d.Exec == nil {
		d.Exec = exec.For
	}
	if d.Pace == nil {
		d.Pace = tokens.Pace
	}
	if d.Out == nil {
		d.Out = io.Discard
	}
}

func newRunID(t time.Time) string {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return t.UTC().Format("20060102T1504Z") + "-" + hex.EncodeToString(b[:])
}

// loadTree loads and statically validates the rig tree. It needs no
// environment and makes no network call.
func loadTree(root string) (*scenario.Tree, []error) {
	t, err := scenario.Load(root)
	if err != nil {
		return nil, []error{err}
	}
	return t, scenario.Validate(t, nil)
}

// selectScenarios applies --only (path.Match on the ID) and --skip-known.
func selectScenarios(t *scenario.Tree, only string, skipKnown bool) ([]*scenario.Scenario, error) {
	var out []*scenario.Scenario
	for _, s := range t.Scenarios {
		if only != "" {
			ok, err := path.Match(only, s.ID)
			if err != nil {
				return nil, fmt.Errorf("--only %q: %w", only, err)
			}
			if !ok {
				continue
			}
		}
		if skipKnown && s.KnownIssue != "" {
			continue
		}
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func repoRef(s string) scenario.RepoRef {
	o, n, _ := strings.Cut(s, "/")
	return scenario.RepoRef{Owner: o, Name: n}
}

// runRig executes spec §3.5 steps 1-9 (writing is the caller's job). The
// returned error is an *exitError (code 3) for validation, config and
// preflight failures; in that case no report is returned. Tokens created by
// the run are revoked exactly once, before runRig returns, even on panic or
// cancellation.
func runRig(ctx context.Context, c *Config, deps runDeps) (rep *report.Report, err error) {
	deps.defaults()
	out := deps.Out

	// 1. Load and validate.
	tree, verrs := loadTree(c.Root)
	if len(verrs) > 0 {
		return nil, &exitError{code: 3, err: fmt.Errorf("validation failed: %w", errors.Join(verrs...))}
	}
	selected, err := selectScenarios(tree, c.Only, c.SkipKnown)
	if err != nil {
		return nil, &exitError{code: 3, err: err}
	}

	// 2. Preflight (first network use).
	if err := c.RequireServer(); err != nil {
		return nil, &exitError{code: 3, err: fmt.Errorf("%w: %v", ErrPreflight, err), plain: true}
	}
	hc := deps.HTTP
	if hc == nil {
		if hc, err = c.HTTPClient(); err != nil {
			return nil, &exitError{code: 3, err: err}
		}
	}
	version, err := Preflight(ctx, c, hc)
	if err != nil {
		return nil, &exitError{code: 3, err: err}
	}

	runID := deps.RunID()
	started := deps.Now().UTC()
	pace := time.Duration(0)
	if c.TokenCreateRate > 0 {
		pace = deps.Pace(c.TokenCreateRate)
	}
	mgr := tokens.NewManager(c.ServerURL, c.UserToken, runID, hc, pace)
	if deps.OnManager != nil {
		deps.OnManager(mgr)
	}

	rep = &report.Report{
		RunID: runID, StartedAt: started.Format(time.RFC3339),
		Instance: c.Instance.Host, GHPVersion: version,
	}
	var results []report.ScenarioResult

	// 8. Revoke all (registered first so it runs on every exit path).
	defer func() {
		p := recover()
		rctx := context.WithoutCancel(ctx)
		leftover, rerr := mgr.RevokeAllErr(rctx)
		if rerr != nil {
			fmt.Fprintf(out, "revoke: %s\n", redact.String(rerr.Error()))
		}
		if still, verr := mgr.VerifyNoneLeft(rctx); verr != nil {
			fmt.Fprintf(out, "verify revocation: %s\n", redact.String(verr.Error()))
			if len(leftover) == 0 && mgr.Created() > 0 {
				// Fail closed: unverified is not revoked.
				leftover = append(leftover, "unverified")
			}
		} else {
			leftover = unionSorted(leftover, still)
		}
		if len(leftover) > 0 {
			fmt.Fprintf(out, "leftover token ids (revoke them or let the next sweep): %s\n", strings.Join(leftover, " "))
		}
		if rep != nil {
			rep.Tokens.Created = mgr.Created()
			rep.Tokens.Revoked = max(mgr.Created()-len(leftover), 0)
			rep.Tokens.LeftoverIDs = append([]string{}, leftover...)
			rep.Claims = report.RollUp(tree, results)
			rep.Summary = report.Summarise(tree, rep.Claims)
		}
		if p != nil {
			panic(p)
		}
	}()

	// 3. Sweep.
	if swept, err := mgr.Sweep(ctx); err != nil {
		fmt.Fprintf(out, "sweep: %s\n", redact.String(err.Error()))
	} else if len(swept) > 0 {
		fmt.Fprintf(out, "sweep: revoked %d leftover token(s): %s\n", len(swept), strings.Join(swept, " "))
	}

	vars := &scenario.Vars{
		RunID: runID, Host: c.Instance.Host,
		RepoA: repoRef(c.RepoA), RepoB: repoRef(c.RepoB), RepoW: repoRef(c.RepoW),
		Fixture:  map[string]scenario.FixtureVals{},
		Instance: c.Instance,
		Step:     map[string]map[string]string{},
	}

	// 4. Create profile tokens (paced by the manager): open first, then
	// every profile the selected scenarios use, sorted.
	failAll := func(msg string) {
		for _, s := range selected {
			results = append(results, report.ScenarioResult{ID: s.ID, Claim: s.Claim, KnownIssue: s.KnownIssue,
				Status: report.StatusError, Detail: msg, Error: msg})
		}
	}
	openProf, ok := tree.Profiles["open"]
	if !ok {
		return nil, &exitError{code: 3, err: errors.New("profiles.yaml: profile \"open\" is required")}
	}
	open, err := mgr.Create(ctx, openProf, vars)
	if err != nil {
		failAll(redact.String("create open token: " + err.Error()))
		return rep, nil
	}
	handles := map[string]tokens.Handle{"open": open}
	profErr := map[string]string{}
	for _, name := range profilesUsed(selected) {
		if name == "open" {
			continue
		}
		h, err := mgr.Create(ctx, tree.Profiles[name], vars)
		if err != nil {
			profErr[name] = redact.String(err.Error())
			continue
		}
		handles[name] = h
	}

	// 5. Capability probe.
	caps, err := ProbeCapabilities(ctx, c, hc, open, vars)
	if err != nil {
		rep = nil
		return nil, &exitError{code: 3, err: err}
	}

	// 6. Fixture discovery.
	api := &handleAPI{hc: hc, base: "https://" + c.Instance.Host + "/api/v3", tok: open}
	fixErr := map[string]string{}
	for _, k := range []struct {
		key  string
		repo string
		ref  *scenario.RepoRef
	}{{"A", c.RepoA, &vars.RepoA}, {"B", c.RepoB, &vars.RepoB}, {"W", c.RepoW, &vars.RepoW}} {
		ref, fv, err := fixtures.Discover(ctx, api, k.repo)
		if ref.Owner != "" {
			*k.ref = ref
		}
		vars.Fixture[k.key] = fv
		if err != nil {
			fixErr[k.key] = redact.String(err.Error())
		}
	}

	env := &exec.RunEnv{
		Vars: vars, HTTP: hc,
		APIBase:        "https://" + c.Instance.Host + "/api/v3",
		GraphQL:        "https://" + c.Instance.Host + "/api/graphql",
		Mgmt:           c.ServerURL,
		Tokens:         mgr,
		Open:           open,
		Profiles:       handles,
		GHPath:         c.GHPath,
		Session:        c.UserToken,
		InstallationID: c.InstallationID,
	}
	if c.Verbose {
		env.Verbose = out
	}

	// 7. Run scenarios sequentially, sorted by ID.
	stop := false
	for _, s := range selected {
		var r report.ScenarioResult
		switch {
		case stop:
			r = errResult(s, "not run: stopped after first failure (--keep-going=false)")
		case ctx.Err() != nil:
			r = errResult(s, "not run: interrupted")
		default:
			r = runScenario(ctx, s, env, deps, caps, handles, profErr, fixErr)
		}
		results = append(results, r)
		if !c.KeepGoing && (r.Status == report.StatusFail || r.Status == report.StatusError || r.Status == report.StatusKnownChanged) {
			stop = true
		}
	}
	return rep, nil
}

func errResult(s *scenario.Scenario, msg string) report.ScenarioResult {
	msg = redact.String(msg)
	return report.ScenarioResult{ID: s.ID, Claim: s.Claim, KnownIssue: s.KnownIssue,
		Status: report.StatusError, Detail: msg, Error: msg}
}

func runScenario(ctx context.Context, s *scenario.Scenario, env *exec.RunEnv, deps runDeps,
	caps Capabilities, handles map[string]tokens.Handle, profErr, fixErr map[string]string) report.ScenarioResult {
	var missing []string
	for _, req := range s.Requires {
		if !caps[req] {
			missing = append(missing, req)
		}
	}
	if len(missing) > 0 {
		reason := "requires " + strings.Join(missing, ", ")
		return report.ScenarioResult{ID: s.ID, Claim: s.Claim, KnownIssue: s.KnownIssue,
			Status: report.StatusGap, Detail: reason, GapReason: reason}
	}
	if msg, ok := profErr[s.Profile]; ok {
		return errResult(s, msg)
	}
	for _, k := range fixtureKeys(s) {
		if msg, ok := fixErr[k]; ok {
			return errResult(s, msg)
		}
	}
	tok, ok := handles[s.Profile]
	if !ok && s.Kind != "token_api" {
		return errResult(s, fmt.Sprintf("no token for profile %q", s.Profile))
	}
	ex, err := deps.Exec(s.Kind)
	if err != nil {
		return errResult(s, err.Error())
	}
	env.Vars.Step = map[string]map[string]string{}
	obs, rerr := ex.Run(ctx, s, tok, env)

	var r report.ScenarioResult
	var sf exec.StepFailure
	switch {
	case errors.As(rerr, &sf) && obs != nil:
		r = report.NewResult(s, obs, nil)
		if s.KnownIssue == "" && r.Status != report.StatusError {
			r.Status = report.StatusFail
			r.Detail = sf.Error()
		}
	default:
		r = report.NewResult(s, obs, rerr)
	}
	r.Residue = exec.RunCleanup(ctx, s, env)
	return r
}

// fixtureKeys guesses which fixture repos s depends on from its templates.
func fixtureKeys(s *scenario.Scenario) []string {
	raw, err := yaml.Marshal(s)
	if err != nil {
		return []string{"A", "B", "W"}
	}
	var keys []string
	for _, k := range []string{"A", "B", "W"} {
		if bytes.Contains(raw, []byte(".Fixture."+k)) || bytes.Contains(raw, []byte(".Repo"+k)) || s.Repo == k {
			keys = append(keys, k)
		}
	}
	return keys
}

func profilesUsed(ss []*scenario.Scenario) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if s.Profile != "" && !seen[s.Profile] {
			seen[s.Profile] = true
			out = append(out, s.Profile)
		}
	}
	sort.Strings(out)
	return out
}

func unionSorted(a, b []string) []string {
	m := map[string]bool{}
	for _, x := range append(append([]string{}, a...), b...) {
		m[x] = true
	}
	out := make([]string, 0, len(m))
	for x := range m {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

// handleAPI implements fixtures.API with a token Handle, so the token value
// never leaves the tokens package.
type handleAPI struct {
	hc   *http.Client
	base string
	tok  tokens.Handle
}

func (a *handleAPI) Do(ctx context.Context, method, p string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+p, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	a.tok.Authorize(req)
	resp, err := a.hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, b, err
}

var _ fixtures.API = (*handleAPI)(nil)
