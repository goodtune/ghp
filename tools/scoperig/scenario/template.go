package scenario

import (
	"encoding/base64"
	"fmt"
	"strings"
	"text/template"
	"time"
)

// RepoRef identifies a GitHub repository.
type RepoRef struct {
	Owner, Name string
	ID          int64  // GitHub database ID
	NodeID      string // GraphQL global node ID, e.g. for repositoryId
}

// String returns "owner/name".
func (r RepoRef) String() string { return r.Owner + "/" + r.Name }

// FixtureVals holds the seeded objects in one fixture repository.
type FixtureVals struct {
	IssueNumber, PRNumber                          int
	ReleaseID                                      int64
	Branch, Label, PRTitle, IssueTitle, ReleaseTag string
}

// InstanceVals describes the GHP instance under test.
type InstanceVals struct {
	Host                         string
	DefaultDuration, MaxDuration time.Duration
}

// AgentVals identifies the GitHub App installation agent profiles mint
// against (instance.agent_installation). Neither value is a secret.
type AgentVals struct {
	AppRecordID    string // GHP app record UUID
	InstallationID int64
}

// Vars is the data passed to every scenario template.
type Vars struct {
	RunID, Host, Login  string
	RepoA, RepoB, RepoW RepoRef
	Fixture             map[string]FixtureVals // keys "A", "B", "W"
	Instance            InstanceVals
	Agent               AgentVals
	Step                map[string]map[string]string // step name -> capture name -> value
	ProfileIDs          map[string]string            // profile name -> minted token id (not the token value)
}

var funcs = template.FuncMap{
	"add": func(d time.Duration, s string) (time.Duration, error) {
		e, err := time.ParseDuration(s)
		if err != nil {
			return 0, err
		}
		return d + e, nil
	},
	"upper": strings.ToUpper,
	// base64 encodes s with standard padding, for Basic credentials.
	"base64": func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) },
}

// Expand renders s as a text/template with v. Missing keys are errors.
func Expand(s string, v *Vars) (string, error) {
	if !strings.Contains(s, "{{") {
		return s, nil
	}
	t, err := template.New("").Funcs(funcs).Option("missingkey=error").Parse(s)
	if err != nil {
		return "", fmt.Errorf("parse %q: %w", s, err)
	}
	var b strings.Builder
	if err := t.Execute(&b, v); err != nil {
		return "", fmt.Errorf("expand %q: %w", s, err)
	}
	return b.String(), nil
}

// ExpandAny returns a copy of x with every string inside maps and slices
// expanded. Other values are returned unchanged. The input is not mutated.
func ExpandAny(x any, v *Vars) (any, error) {
	switch t := x.(type) {
	case string:
		return Expand(t, v)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			r, err := ExpandAny(e, v)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	case map[string]string:
		out := make(map[string]string, len(t))
		for k, e := range t {
			r, err := Expand(e, v)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			r, err := ExpandAny(e, v)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	case []string:
		out := make([]string, len(t))
		for i, e := range t {
			r, err := Expand(e, v)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	default:
		return x, nil
	}
}

// ExpandExpect returns a copy of e with every string matcher (json values,
// header values, body/stdout/stderr substrings) expanded. nil stays nil.
func ExpandExpect(e *Expect, v *Vars) (*Expect, error) {
	if e == nil {
		return nil, nil
	}
	out := *e
	strs := func(in []string) ([]string, error) {
		if in == nil {
			return nil, nil
		}
		r, err := ExpandAny(in, v)
		if err != nil {
			return nil, err
		}
		return r.([]string), nil
	}
	m := func(in map[string]string) (map[string]string, error) {
		if in == nil {
			return nil, nil
		}
		r, err := ExpandAny(in, v)
		if err != nil {
			return nil, err
		}
		return r.(map[string]string), nil
	}
	var err error
	if out.JSON, err = m(e.JSON); err != nil {
		return nil, err
	}
	if out.Header, err = m(e.Header); err != nil {
		return nil, err
	}
	if out.BodyContains, err = strs(e.BodyContains); err != nil {
		return nil, err
	}
	if out.BodyNotContains, err = strs(e.BodyNotContains); err != nil {
		return nil, err
	}
	if out.StdoutContains, err = strs(e.StdoutContains); err != nil {
		return nil, err
	}
	if out.StderrContains, err = strs(e.StderrContains); err != nil {
		return nil, err
	}
	if e.ExpiresWithin != nil {
		w := *e.ExpiresWithin
		if w.Min, err = Expand(w.Min, v); err != nil {
			return nil, err
		}
		if w.Max, err = Expand(w.Max, v); err != nil {
			return nil, err
		}
		out.ExpiresWithin = &w
	}
	return &out, nil
}

// capturePlaceholder stands in for a step capture that has not run yet.
const capturePlaceholder = "0"

// CaptureVars returns a shallow copy of v whose Step map holds v's captured
// values plus a placeholder for every capture name s declares that has not
// been captured yet (steps, cleanup and request). Expanding with it fails
// only for template errors and missing non-capture keys, never because a
// step has not run (or stopped early). v is not modified.
func CaptureVars(s *Scenario, v *Vars) *Vars {
	out := *v
	out.Step = make(map[string]map[string]string, len(v.Step))
	for name, caps := range v.Step {
		m := make(map[string]string, len(caps))
		for k, val := range caps {
			m[k] = val
		}
		out.Step[name] = m
	}
	reqs := append(append([]Request{}, s.Steps...), s.Cleanup...)
	if s.Request != nil {
		reqs = append(reqs, *s.Request)
	}
	for _, r := range reqs {
		if len(r.Capture) == 0 {
			continue
		}
		if out.Step[r.Name] == nil {
			out.Step[r.Name] = map[string]string{}
		}
		for c := range r.Capture {
			if _, ok := out.Step[r.Name][c]; !ok {
				out.Step[r.Name][c] = capturePlaceholder
			}
		}
	}
	return &out
}

// CheckExpands expands every expectation of s (verdict expect, observed,
// each step's and the request's expect) with CaptureVars(s, v) and returns
// the first error. The runner calls it before any request, so a template
// that cannot expand with the live Vars stops the scenario before it sends
// anything, instead of turning a classified result into ERROR afterwards.
func CheckExpands(s *Scenario, v *Vars) error {
	cv := CaptureVars(s, v)
	check := func(where string, e *Expect) error {
		if _, err := ExpandExpect(e, cv); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		return nil
	}
	if err := check("expect", s.VerdictExpect()); err != nil {
		return err
	}
	if err := check("observed", s.Observed); err != nil {
		return err
	}
	for i := range s.Steps {
		if err := check(fmt.Sprintf("steps[%d] expect", i), s.Steps[i].Expect); err != nil {
			return err
		}
	}
	if s.Request != nil {
		if err := check("request expect", s.Request.Expect); err != nil {
			return err
		}
	}
	for i := range s.Cleanup {
		if err := check(fmt.Sprintf("cleanup[%d] expect", i), s.Cleanup[i].Expect); err != nil {
			return err
		}
	}
	return nil
}
