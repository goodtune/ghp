// Package exec runs scope regression rig scenarios against a GHP instance
// and turns each response into an expect.Observation.
package exec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/goodtune/ghp/tools/scoperig/expect"
	"github.com/goodtune/ghp/tools/scoperig/redact"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
	"github.com/goodtune/ghp/tools/scoperig/tokens"
)

// MaxBody caps every stored observation body.
const MaxBody = 64 << 10

// RequestTimeout bounds each REST, GraphQL and token API request.
const RequestTimeout = 30 * time.Second

// RunEnv is the shared state for executing scenarios.
type RunEnv struct {
	Vars     *scenario.Vars
	HTTP     *http.Client
	APIBase  string // https://<host>/api/v3
	GraphQL  string // https://<host>/api/graphql
	Mgmt     string // GHP_SERVER_URL (token API, sessions)
	Tokens   *tokens.Manager
	Open     tokens.Handle // for cleanup
	Profiles map[string]tokens.Handle
	GHPath   string
	Verbose  io.Writer // nil unless --verbose; receives redacted exchanges
	// Session is the management session token, used for token_api GETs.
	Session string
	// InstallationID is the typed value for "$int:InstallationID".
	InstallationID int64
	// CAFile is GHP_RIG_CA_FILE ("" for the system roots), passed to git.
	CAFile string
	// GHPPath is the ghp CLI for git_credential scenarios.
	GHPPath string
	// AgentAppRecordID is the app record git_credential mints against.
	AgentAppRecordID string
}

// Executor runs one kind of scenario.
type Executor interface {
	Kind() string
	Run(ctx context.Context, s *scenario.Scenario, tok tokens.Handle, env *RunEnv) (*expect.Observation, error)
}

// StepFailure reports that a step's own Expect did not hold. It is a
// scenario failure, not a rig error.
type StepFailure struct {
	Step     string
	Mismatch []error
}

func (f StepFailure) Error() string {
	msgs := make([]string, len(f.Mismatch))
	for i, e := range f.Mismatch {
		msgs[i] = e.Error()
	}
	return redact.String(fmt.Sprintf("step %q: %s", f.Step, strings.Join(msgs, "; ")))
}

// For returns the executor for kind.
func For(kind string) (Executor, error) {
	switch kind {
	case "rest":
		return restExecutor{}, nil
	case "graphql":
		return graphqlExecutor{}, nil
	case "token_api":
		return tokenAPIExecutor{}, nil
	case "gh":
		return GH{}, nil
	case "git":
		return Git{}, nil
	case "git_credential":
		return GitCredential{}, nil
	}
	return nil, fmt.Errorf("exec: no executor for kind %q", kind)
}

// methodOf returns the upper-case method; empty means GET (as in validation).
func methodOf(m string) string {
	m = strings.ToUpper(strings.TrimSpace(m))
	if m == "" {
		return http.MethodGet
	}
	return m
}

// IntVarNames lists the names accepted after "$int:" in request bodies.
var IntVarNames = []string{"InstallationID", "RepoA.ID", "RepoB.ID", "RepoW.ID"}

const intPrefix = "$int:"

// ResolveInt returns the typed value for a "$int:" name.
func ResolveInt(name string, v *scenario.Vars, installationID int64) (int64, error) {
	switch name {
	case "InstallationID":
		return installationID, nil
	case "RepoA.ID":
		return v.RepoA.ID, nil
	case "RepoB.ID":
		return v.RepoB.ID, nil
	case "RepoW.ID":
		return v.RepoW.ID, nil
	}
	return 0, fmt.Errorf("unknown typed value %q (want one of %s)", intPrefix+name, strings.Join(IntVarNames, ", "))
}

// prepareBody expands templates and replaces "$int:Name" strings with int64.
func prepareBody(x any, env *RunEnv) (any, error) {
	e, err := scenario.ExpandAny(x, env.Vars)
	if err != nil {
		return nil, err
	}
	return typed(e, env)
}

func typed(x any, env *RunEnv) (any, error) {
	switch t := x.(type) {
	case string:
		if name, ok := strings.CutPrefix(t, intPrefix); ok {
			return ResolveInt(name, env.Vars, env.InstallationID)
		}
		return t, nil
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			r, err := typed(e, env)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			r, err := typed(e, env)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	}
	return x, nil
}

// send performs the request built by build. A transport error (no HTTP
// response: connection reset, HTTP/2 GOAWAY, EOF, including through a
// forward proxy) is retried up to TransportRetries times with backoff, but
// only when re-sending cannot duplicate a write (see retryable). A
// transport error left after that is returned as a rig error, so the
// scenario is ERROR, never FAIL or KNOWN-CHANGED. Product responses are
// never retried. The response body is capped at MaxBody and redacted.
func send(ctx context.Context, env *RunEnv, build func(ctx context.Context) (*http.Request, error)) (*expect.Observation, error) {
	client := env.HTTP
	if client == nil {
		client = &http.Client{Timeout: RequestTimeout}
	}
	var lastErr error
	attempts := 0
	for attempt := 0; attempt <= TransportRetries; attempt++ {
		if attempt > 0 && !sleepCtx(ctx, transportBackoff(attempt)) {
			break
		}
		attempts++
		rctx, cancel := context.WithTimeout(ctx, RequestTimeout)
		req, err := build(rctx)
		if err != nil {
			cancel()
			return nil, err
		}
		started := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			lastErr = fmt.Errorf("%s %s: %s", req.Method, req.URL.RequestURI(), redact.String(err.Error()))
			if ctx.Err() != nil {
				break
			}
			if !retryable(ctx, req.Method, err) {
				if IsTransportError(err) {
					return nil, fmt.Errorf("transport error: %w (not retried: the write may have been applied)", lastErr)
				}
				return nil, lastErr
			}
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		cancel()
		if rerr != nil {
			lastErr = fmt.Errorf("%s %s: read body: %s", req.Method, req.URL.RequestURI(), redact.String(rerr.Error()))
			// The status arrived, so the request reached the server: only
			// an idempotent request may be re-sent.
			if ctx.Err() == nil && IsTransportError(rerr) && isIdempotent(ctx, req.Method) {
				continue
			}
			return nil, lastErr
		}
		obs := &expect.Observation{Status: resp.StatusCode, Header: redact.Header(resp.Header), Body: redact.Bytes(body),
			RequestedAt: started, RespondedAt: time.Now()}
		verbose(env, req.Method, req.URL.RequestURI(), obs)
		return obs, nil
	}
	if lastErr != nil && attempts > 1 {
		return nil, fmt.Errorf("transport error after %d attempts: %w", attempts, lastErr)
	}
	return nil, lastErr
}

func verbose(env *RunEnv, method, uri string, obs *expect.Observation) {
	if env.Verbose == nil {
		return
	}
	_, _ = fmt.Fprintf(env.Verbose, "%s %s -> %d\n%s\n", method, redact.String(uri), obs.Status, obs.Body)
}

// jsonBytes JSON-encodes body; a nil body gives nil bytes.
func jsonBytes(body any) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encode body: %w", err)
	}
	return b, nil
}

func bodyReader(b []byte) io.Reader {
	if b == nil {
		return nil
	}
	return bytes.NewReader(b)
}

// capture stores each "$.path" value of obs.Body into Vars.Step[step].
// Vars.Step is not locked: the runner executes scenarios sequentially.
func capture(env *RunEnv, step string, c map[string]string, obs *expect.Observation) error {
	if len(c) == 0 {
		return nil
	}
	if env.Vars.Step == nil {
		env.Vars.Step = map[string]map[string]string{}
	}
	if env.Vars.Step[step] == nil {
		env.Vars.Step[step] = map[string]string{}
	}
	for name, path := range c {
		val, err := expect.JSONPath(obs.Body, path)
		if err != nil {
			return fmt.Errorf("step %q: capture %s: %w", step, name, err)
		}
		env.Vars.Step[step][name] = val
	}
	return nil
}

// checkStep applies a step's own Expect unless it is the scenario's verdict
// expectation (the rest shorthand's single step), which the runner
// classifies itself.
//
// Templates in the step's Expect are expanded with the Vars as they stand
// (earlier steps' captures included); the runner has already checked that
// they expand (scenario.CheckExpands).
func checkStep(s *scenario.Scenario, r *scenario.Request, obs *expect.Observation, env *RunEnv) error {
	if r.Expect == nil || r.Expect == s.VerdictExpect() {
		return nil
	}
	want, err := scenario.ExpandExpect(r.Expect, scenario.CaptureVars(s, env.Vars))
	if err != nil {
		return fmt.Errorf("step %q: expand expect: %w", r.Name, err)
	}
	if errs := expect.Match(want, obs); len(errs) > 0 {
		return StepFailure{Step: r.Name, Mismatch: errs}
	}
	return nil
}

// RunCleanup runs every cleanup request, even after a failed scenario, and
// returns one residue entry per cleanup that did not succeed.
func RunCleanup(ctx context.Context, s *scenario.Scenario, env *RunEnv) (residue []string) {
	ctx = context.WithoutCancel(ctx)
	for i := range s.Cleanup {
		r := &s.Cleanup[i]
		where := fmt.Sprintf("cleanup[%d] %s %s", i, methodOf(r.Method), r.Path)
		var obs *expect.Observation
		var err error
		if s.Kind == "token_api" {
			obs, err = tokenAPIRequest(ctx, r, env.Open, env)
		} else {
			obs, err = restRequest(ctx, r, env.Open, env)
		}
		switch {
		case err != nil:
			residue = append(residue, redact.String(where+": "+err.Error()))
		case obs.Status == http.StatusNotFound || (obs.Status >= 200 && obs.Status < 300):
			if r.Expect != nil {
				want, xerr := scenario.ExpandExpect(r.Expect, scenario.CaptureVars(s, env.Vars))
				if xerr != nil {
					residue = append(residue, redact.String(where+": expand expect: "+xerr.Error()))
					continue
				}
				if errs := expect.Match(want, obs); len(errs) > 0 {
					residue = append(residue, redact.String(where+": "+errors.Join(errs...).Error()))
				}
			}
		default:
			residue = append(residue, redact.String(fmt.Sprintf("%s: status %d", where, obs.Status)))
		}
	}
	return residue
}

// retryable reports whether a request that failed with err may be re-sent:
// only for a transport error, and only when the request is idempotent (a
// safe method, or marked with withIdempotent) or the error proves nothing
// was sent (the dial failed).
func retryable(ctx context.Context, method string, err error) bool {
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	return IsTransportError(err) && isIdempotent(ctx, method)
}
