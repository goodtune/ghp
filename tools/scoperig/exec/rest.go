package exec

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/goodtune/ghp/tools/scoperig/expect"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
	"github.com/goodtune/ghp/tools/scoperig/tokens"
)

type restExecutor struct{}

func (restExecutor) Kind() string { return "rest" }

func (restExecutor) Run(ctx context.Context, s *scenario.Scenario, tok tokens.Handle, env *RunEnv) (*expect.Observation, error) {
	s.Normalise()
	return runSteps(ctx, s, tok, env, restRequest)
}

type stepFunc func(ctx context.Context, r *scenario.Request, tok tokens.Handle, env *RunEnv) (*expect.Observation, error)

// runSteps runs the steps in order, capturing values, and returns the last
// observation. A failed step expectation stops the run with a StepFailure.
func runSteps(ctx context.Context, s *scenario.Scenario, tok tokens.Handle, env *RunEnv, do stepFunc) (*expect.Observation, error) {
	if len(s.Steps) == 0 {
		return nil, fmt.Errorf("scenario %s: no steps", s.ID)
	}
	var obs *expect.Observation
	for i := range s.Steps {
		r := &s.Steps[i]
		var err error
		obs, err = do(ctx, r, tok, env)
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

// restRequest sends r to APIBase with the path sent verbatim (no cleaning).
func restRequest(ctx context.Context, r *scenario.Request, tok tokens.Handle, env *RunEnv) (*expect.Observation, error) {
	path, err := scenario.Expand(r.Path, env.Vars)
	if err != nil {
		return nil, err
	}
	return verbatimRequest(ctx, env.APIBase, path, r, tok.Authorize, env)
}

// verbatimRequest sends r to base+path, setting URL.Opaque so that "..",
// case and percent-encoding reach the server exactly as written.
func verbatimRequest(ctx context.Context, base, path string, r *scenario.Request, auth func(*http.Request), env *RunEnv) (*expect.Observation, error) {
	bu, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("base url: %w", err)
	}
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("path %q must start with /", path)
	}
	opaque := strings.TrimRight(bu.Path, "/") + path
	hdrs, err := scenario.ExpandAny(r.Headers, env.Vars)
	if err != nil {
		return nil, err
	}
	h, ok := hdrs.(map[string]string)
	if !ok && hdrs != nil {
		return nil, fmt.Errorf("headers: expanded to %T, want map[string]string", hdrs)
	}
	var body []byte
	if r.Body != nil {
		b, err := prepareBody(r.Body, env)
		if err != nil {
			return nil, err
		}
		if body, err = jsonBytes(b); err != nil {
			return nil, err
		}
	}
	method := methodOf(r.Method)
	return send(ctx, env, func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, method, bu.Scheme+"://"+bu.Host+"/", bodyReader(body))
		if err != nil {
			return nil, err
		}
		req.URL.Path = ""
		req.URL.Opaque = opaque
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		auth(req)
		for k, v := range h {
			req.Header.Set(k, v)
		}
		return req, nil
	})
}
