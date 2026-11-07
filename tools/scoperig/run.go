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
	"os"
	osexec "os/exec"
	"path"
	"runtime/debug"
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
	// GHVersion reads the gh version for the report ("" when unknown).
	// Default: `gh --version` via ghPath.
	GHVersion func(ctx context.Context, ghPath string) string
	// RigCommit is the VCS revision the rig binary was built from ("" when
	// unknown). Default: the binary's build info.
	RigCommit func() string
	// RigVersion is the version in the User-Agent. Default exec.RigVersion.
	RigVersion func() string
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
	if d.GHVersion == nil {
		d.GHVersion = ghVersion
	}
	if d.RigCommit == nil {
		d.RigCommit = rigCommit
	}
	if d.RigVersion == nil {
		d.RigVersion = exec.RigVersion
	}
}

// ghVersion runs `gh --version` with a short timeout and returns the
// MAJOR.MINOR.PATCH version, or "" if gh is missing or unreadable.
func ghVersion(ctx context.Context, ghPath string) string {
	if ghPath == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := osexec.CommandContext(ctx, ghPath, "--version")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "GH_NO_UPDATE_NOTIFIER=1"}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	v, err := parseGHVersion(string(out))
	if err != nil {
		return ""
	}
	return v
}

// rigCommit returns the vcs.revision from the binary's build info (with a
// "-dirty" suffix for a modified tree), or "" when it was not stamped (for
// example under go run).
func rigCommit() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	var rev string
	dirty := false
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev != "" && dirty {
		rev += "-dirty"
	}
	return rev
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

// configVars is PlaceholderVars with the configured instance host and
// fixture repositories: the Vars that config load makes known before any
// request. Values that only discovery provides (login, repository ids,
// fixture numbers) stay placeholders.
func configVars(c *Config) *scenario.Vars {
	v := scenario.PlaceholderVars()
	if c.Instance.Host != "" {
		v.Host, v.Instance.Host = c.Instance.Host, c.Instance.Host
	}
	if c.Instance.DefaultDuration > 0 {
		v.Instance.DefaultDuration = c.Instance.DefaultDuration
	}
	if c.Instance.MaxDuration > 0 {
		v.Instance.MaxDuration = c.Instance.MaxDuration
	}
	for _, r := range []struct {
		spec string
		ref  *scenario.RepoRef
	}{{c.RepoA, &v.RepoA}, {c.RepoB, &v.RepoB}, {c.RepoW, &v.RepoW}} {
		if rr := repoRef(r.spec); rr.Owner != "" && rr.Name != "" {
			r.ref.Owner, r.ref.Name = rr.Owner, rr.Name
		}
	}
	return v
}

func repoRef(s string) scenario.RepoRef {
	o, n, _ := strings.Cut(s, "/")
	return scenario.RepoRef{Owner: o, Name: n}
}

// endOfRunTimeout bounds each end-of-run sweep and verification call; it
// matches the token manager's revoke timeout.
const endOfRunTimeout = 60 * time.Second

// runRig executes spec §3.5 steps 1-9 (writing is the caller's job). The
// returned error is an *exitError (code 3) for validation, config and
// preflight failures (no report is returned), and code 2 for a failed
// startup sweep. Tokens created by
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
	// Validate again with the real host and fixture repositories, before
	// any request: static validation uses PlaceholderVars, so a rule that
	// depends on Vars could pass there and differ at run time.
	if verrs := scenario.Validate(tree, configVars(c)); len(verrs) > 0 {
		return nil, &exitError{code: 3, err: fmt.Errorf("validation with the configured host and fixtures failed: %w", errors.Join(verrs...))}
	}
	selected, err := selectScenarios(tree, c.Only, c.SkipKnown)
	if err != nil {
		return nil, &exitError{code: 3, err: err}
	}
	if c.Only != "" && len(selected) == 0 {
		return nil, &exitError{code: 3, err: errors.New("--only matched no scenarios")}
	}

	// 2. Preflight (first network use).
	if err := c.RequireServer(); err != nil {
		return nil, &exitError{code: 3, err: fmt.Errorf("%w: %v", ErrPreflight, err)}
	}
	hc := deps.HTTP
	if hc == nil {
		if hc, err = c.HTTPClient(); err != nil {
			return nil, &exitError{code: 3, err: err}
		}
	}
	// Every rig request, preflight included, carries the run id in its
	// User-Agent so the run can be isolated in the instance's logs.
	runID := deps.RunID()
	hc = exec.WithUserAgent(hc, exec.UserAgent(deps.RigVersion(), runID))
	version, err := Preflight(ctx, c, hc)
	if err != nil {
		return nil, &exitError{code: 3, err: err}
	}

	started := deps.Now().UTC()
	pace := deps.Pace(c.TokenCreateRate)
	mgr := tokens.NewManager(c.ServerURL, c.UserToken, runID, hc, pace)
	if deps.OnManager != nil {
		deps.OnManager(mgr)
	}

	rep = &report.Report{
		RunID: runID, StartedAt: started.Format(time.RFC3339),
		Instance: c.Instance.Host, GHPVersion: version,
		GHVersion: deps.GHVersion(ctx, c.GHPath), RigCommit: deps.RigCommit(),
	}
	var results []report.ScenarioResult

	// 8. Revoke all (registered first so it runs on every exit path).
	defer func() {
		p := recover()
		rctx := context.WithoutCancel(ctx)
		leftover, rerr := mgr.RevokeAllErr(rctx)
		if rerr != nil {
			_, _ = fmt.Fprintf(out, "revoke: %s\n", redact.String(rerr.Error()))
		}
		// Backstop: revoke anything the server holds under this run's exact
		// session id that the manager never recorded (a create whose
		// response was lost). Tracked tokens revoked above are skipped.
		tracked := map[string]bool{}
		for _, id := range leftover {
			tracked[id] = true
		}
		untracked := 0
		sessionUnverified := false
		// Bound the backstop sweep and verification like RevokeAllErr, so
		// a hung management API cannot stall the exit path.
		sctx, scancel := context.WithTimeout(rctx, endOfRunTimeout)
		defer scancel()
		swept, sweepFailed, sserr := mgr.SweepSession(sctx)
		if sserr != nil {
			_, _ = fmt.Fprintf(out, "end-of-run session sweep: %s\n", redact.String(sserr.Error()))
			sessionUnverified = true
		}
		for _, id := range append(append([]string{}, swept...), sweepFailed...) {
			if !tracked[id] {
				untracked++
			}
		}
		if len(swept) > 0 {
			_, _ = fmt.Fprintf(out, "end-of-run session sweep: revoked %d token(s): %s\n", len(swept), strings.Join(swept, " "))
			leftover = without(leftover, swept)
		}
		leftover = unionSorted(leftover, sweepFailed)
		vctx, vcancel := context.WithTimeout(rctx, endOfRunTimeout)
		defer vcancel()
		if still, verr := mgr.VerifyNoneLeft(vctx); verr != nil || sessionUnverified {
			if verr != nil {
				_, _ = fmt.Fprintf(out, "verify revocation: %s\n", redact.String(verr.Error()))
			} else {
				leftover = unionSorted(leftover, still)
			}
			if len(leftover) == 0 && (sessionUnverified || mgr.Created() > 0) {
				// Fail closed: unverified is not revoked.
				leftover = append(leftover, "unverified")
			}
		} else {
			leftover = unionSorted(leftover, still)
		}
		if len(leftover) > 0 {
			_, _ = fmt.Fprintf(out, "leftover token ids (revoke them or let the next sweep): %s\n", strings.Join(leftover, " "))
		}
		err = escalateOnLeftover(err, leftover)
		if rep != nil {
			created := mgr.Created() + untracked
			rep.Tokens.Created = created
			rep.Tokens.Revoked = max(created-len(leftover), 0)
			rep.Tokens.LeftoverIDs = append([]string{}, leftover...)
			rep.Claims = report.RollUp(tree, results)
			rep.Summary = report.Summarise(tree, rep.Claims)
		}
		if p != nil {
			panic(p)
		}
	}()

	// 3. Sweep.
	// A failed sweep is an operational error: stale tokens from an earlier
	// run may still be live. The revoke defer above still runs.
	swept, serr := mgr.Sweep(ctx)
	if serr != nil {
		return rep, &exitError{code: 2, err: fmt.Errorf("sweep: %s", redact.String(serr.Error()))}
	}
	if len(swept) > 0 {
		_, _ = fmt.Fprintf(out, "sweep: revoked %d leftover token(s): %s\n", len(swept), strings.Join(swept, " "))
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
	vars.ProfileIDs = map[string]string{"open": open.ID()}
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
		vars.ProfileIDs[name] = h.ID()
	}

	// 5. Capability probe.
	caps, err := ProbeCapabilities(ctx, c, hc, open, vars)
	if err != nil {
		rep = nil
		return nil, &exitError{code: 3, err: err}
	}
	// Repo W receives every write; apply the fixtures safety guard to it
	// now that the login is known, before any scenario runs.
	if c.RepoW != "" {
		if err := fixtures.CheckSafe(c.RepoW, vars.Login); err != nil {
			rep = nil
			return nil, &exitError{code: 3, err: err}
		}
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

// escalateOnLeftover turns a could-not-start error (exit 3) into exit 2 when
// tokens were left live: a live token outranks a could-not-start error.
// Other errors, and a nil error, pass through unchanged (a nil error with
// leftovers is reported through the report's LeftoverIDs and ExitCode).
func escalateOnLeftover(err error, leftover []string) error {
	if len(leftover) == 0 {
		return err
	}
	var ee *exitError
	if errors.As(err, &ee) && ee.code == 3 {
		return &exitError{code: 2, err: fmt.Errorf("%w; token revocation failed", ee.err)}
	}
	return err
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
	// Expand every expectation with the live Vars before any request: a
	// template that cannot expand is a scenario error found before the
	// request, not an ERROR that hides a classified result after it.
	if err := scenario.CheckExpands(s, env.Vars); err != nil {
		return errResult(s, "not run: expand expectations: "+err.Error())
	}
	obs, rerr := ex.Run(ctx, s, tok, env)

	// Expand templated matchers (e.g. json: {"$.login": "{{.Login}}"}) again
	// after the run, so step captures are available, and classify against a
	// copy. Captures a stopped run never reached keep their placeholder, so
	// this cannot fail once CheckExpands passed.
	sc := *s
	cv := scenario.CaptureVars(s, env.Vars)
	var xerr error
	if sc.Expect, xerr = scenario.ExpandExpect(s.VerdictExpect(), cv); xerr == nil {
		sc.Observed, xerr = scenario.ExpandExpect(s.Observed, cv)
	}
	if xerr != nil {
		r := errResult(s, "expand expectations: "+xerr.Error())
		r.Residue = exec.RunCleanup(ctx, s, env)
		return r
	}
	s = &sc

	var r report.ScenarioResult
	var sf exec.StepFailure
	switch {
	case errors.As(rerr, &sf) && obs != nil:
		// A failed step is never PASS, KNOWN or KNOWN-FIXED: the step's
		// response must not be classified against the scenario's
		// expect:/observed:, or a regression could hide behind them.
		r = report.NewResult(s, obs, nil)
		if r.Status != report.StatusError {
			r.Status = report.StatusFail
			if s.KnownIssue != "" {
				r.Status = report.StatusKnownChanged
			}
			r.Detail = sf.Error()
		}
	default:
		r = report.NewResult(s, obs, rerr)
	}
	r.Residue = exec.RunCleanup(ctx, s, env)
	return r
}

// fixtureKeys guesses which fixture repos s depends on from its templates.
// It is a substring heuristic over the marshalled scenario: a reference to
// .Fixture.X or .RepoX (or repo: X) means fixture X. A false positive only
// turns a runnable scenario into ERROR when that fixture failed discovery;
// a false negative lets the scenario run and fail on its own request.
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

// without returns a minus every element of b.
func without(a, b []string) []string {
	drop := map[string]bool{}
	for _, x := range b {
		drop[x] = true
	}
	out := make([]string, 0, len(a))
	for _, x := range a {
		if !drop[x] {
			out = append(out, x)
		}
	}
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
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, b, err
}

var _ fixtures.API = (*handleAPI)(nil)
