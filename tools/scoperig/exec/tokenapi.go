package exec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/goodtune/ghp/tools/scoperig/expect"
	"github.com/goodtune/ghp/tools/scoperig/redact"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
	"github.com/goodtune/ghp/tools/scoperig/tokens"
)

type tokenAPIExecutor struct{}

func (tokenAPIExecutor) Kind() string { return "token_api" }

// Run runs Steps then Request. Poll applies to the step named "probe", or
// to Request when no step has that name.
func (tokenAPIExecutor) Run(ctx context.Context, s *scenario.Scenario, tok tokens.Handle, env *RunEnv) (*expect.Observation, error) {
	reqs := make([]*scenario.Request, 0, len(s.Steps)+1)
	for i := range s.Steps {
		reqs = append(reqs, &s.Steps[i])
	}
	if s.Request != nil {
		reqs = append(reqs, s.Request)
	}
	if len(reqs) == 0 {
		return nil, fmt.Errorf("scenario %s: token_api needs a request", s.ID)
	}
	pollIdx := len(reqs) - 1
	for i, r := range reqs {
		if r.Name == "probe" {
			pollIdx = i
		}
	}
	var obs *expect.Observation
	for i, r := range reqs {
		var err error
		if s.Poll != nil && i == pollIdx {
			want := r.Expect
			if want == nil {
				want = s.Expect
			}
			obs, err = poll(ctx, s.Poll, want, func() (*expect.Observation, error) { return tokenAPIRequest(ctx, r, tok, env) })
		} else {
			obs, err = tokenAPIRequest(ctx, r, tok, env)
		}
		if err != nil {
			return nil, err
		}
		if err := checkStep(s, r, obs); err != nil {
			return obs, err
		}
		if err := capture(env, r.Name, r.Capture, obs); err != nil {
			return obs, err
		}
	}
	return obs, nil
}

// poll repeats do every interval until want matches or timeout passes, and
// returns the last observation.
func poll(ctx context.Context, p *scenario.Poll, want *scenario.Expect, do func() (*expect.Observation, error)) (*expect.Observation, error) {
	interval, err := time.ParseDuration(p.Interval)
	if err != nil {
		return nil, fmt.Errorf("poll interval: %w", err)
	}
	timeout, err := time.ParseDuration(p.Timeout)
	if err != nil {
		return nil, fmt.Errorf("poll timeout: %w", err)
	}
	deadline := time.Now().Add(timeout)
	for {
		obs, err := do()
		if err != nil {
			return nil, err
		}
		if len(expect.Match(want, obs)) == 0 || !time.Now().Add(interval).Before(deadline) {
			return obs, nil
		}
		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return obs, ctx.Err()
		case <-t.C:
		}
	}
}

// tokenAPIRequest dispatches one token_api request:
// POST /api/tokens -> Manager.CreateRaw; DELETE /api/tokens/{id} ->
// Manager.Revoke; /api/v3/... -> proxy host with tok; other /api/tokens
// requests -> management host with the session token.
func tokenAPIRequest(ctx context.Context, r *scenario.Request, tok tokens.Handle, env *RunEnv) (*expect.Observation, error) {
	path, err := scenario.Expand(r.Path, env.Vars)
	if err != nil {
		return nil, err
	}
	method := methodOf(r.Method)
	switch {
	case method == http.MethodPost && path == "/api/tokens":
		var body map[string]any
		if r.Body != nil {
			b, err := prepareBody(r.Body, env)
			if err != nil {
				return nil, err
			}
			m, ok := b.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("POST /api/tokens: body must be a map")
			}
			body = m
		}
		status, resp, err := env.Tokens.CreateRaw(ctx, body)
		if err != nil {
			return nil, fmt.Errorf("POST /api/tokens: %s", redact.String(err.Error()))
		}
		return jsonObservation(env, method, path, status, resp)
	case method == http.MethodDelete && strings.HasPrefix(path, "/api/tokens/"):
		id := strings.TrimPrefix(path, "/api/tokens/")
		if id == "" || strings.ContainsAny(id, "/?") {
			return nil, fmt.Errorf("DELETE %s: bad token id", path)
		}
		if err := env.Tokens.Revoke(ctx, id); err != nil {
			return nil, fmt.Errorf("DELETE %s: %s", path, redact.String(err.Error()))
		}
		// Synthetic observation: Revoke succeeded, so report 200 with no headers.
		return jsonObservation(env, method, path, http.StatusOK, map[string]any{"id": id})
	case strings.HasPrefix(path, "/api/v3/"):
		return verbatimRequest(ctx, env.APIBase, strings.TrimPrefix(path, "/api/v3"), r, tok.Authorize, env)
	default:
		return verbatimRequest(ctx, env.Mgmt, path, r, sessionAuth(env.Session), env)
	}
}

func jsonObservation(env *RunEnv, method, path string, status int, resp map[string]any) (*expect.Observation, error) {
	var b []byte
	if resp != nil {
		var err error
		if b, err = json.Marshal(resp); err != nil {
			return nil, err
		}
	}
	if len(b) > MaxBody {
		b = b[:MaxBody]
	}
	obs := &expect.Observation{Status: status, Header: http.Header{}, Body: redact.Bytes(b)}
	verbose(env, method, path, obs)
	return obs, nil
}

// sessionAuth authorises management API requests with the session token.
func sessionAuth(session string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+session) }
}
