package exec

import (
	"context"
	"fmt"
	"net/http"

	"github.com/goodtune/ghp/tools/scoperig/expect"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
	"github.com/goodtune/ghp/tools/scoperig/tokens"
)

type graphqlExecutor struct{}

func (graphqlExecutor) Kind() string { return "graphql" }

// Run posts the scenario query, or each step body, to the GraphQL endpoint.
func (graphqlExecutor) Run(ctx context.Context, s *scenario.Scenario, tok tokens.Handle, env *RunEnv) (*expect.Observation, error) {
	if len(s.Steps) == 0 {
		q, err := scenario.Expand(s.Query, env.Vars)
		if err != nil {
			return nil, err
		}
		payload := map[string]any{"query": q}
		if s.Variables != nil {
			v, err := prepareBody(map[string]any(s.Variables), env)
			if err != nil {
				return nil, err
			}
			payload["variables"] = v
		}
		r := &scenario.Request{Method: http.MethodPost, Headers: s.Headers}
		return postGraphQL(ctx, r, payload, tok, env)
	}
	return runSteps(ctx, s, tok, env, func(ctx context.Context, r *scenario.Request, tok tokens.Handle, env *RunEnv) (*expect.Observation, error) {
		if methodOf(r.Method) != http.MethodPost {
			return nil, fmt.Errorf("graphql step %q: method %s not allowed (POST only)", r.Name, methodOf(r.Method))
		}
		b, err := prepareBody(r.Body, env)
		if err != nil {
			return nil, err
		}
		return postGraphQL(ctx, r, b, tok, env)
	})
}

func postGraphQL(ctx context.Context, r *scenario.Request, payload any, tok tokens.Handle, env *RunEnv) (*expect.Observation, error) {
	body, err := jsonBytes(payload)
	if err != nil {
		return nil, err
	}
	hdrs, err := scenario.ExpandAny(r.Headers, env.Vars)
	if err != nil {
		return nil, err
	}
	return send(ctx, env, func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, env.GraphQL, bodyReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		tok.Authorize(req)
		if h, ok := hdrs.(map[string]string); ok {
			for k, v := range h {
				req.Header.Set(k, v)
			}
		}
		return req, nil
	})
}
