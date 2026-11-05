package scenario

import (
	"fmt"
	"strings"
	"text/template"
	"time"
)

// RepoRef identifies a GitHub repository.
type RepoRef struct {
	Owner, Name string
	ID          int64
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
	Host, ManagementHost         string
	DefaultDuration, MaxDuration time.Duration
}

// Vars is the data passed to every scenario template.
type Vars struct {
	RunID, Host, Login  string
	RepoA, RepoB, RepoW RepoRef
	Fixture             map[string]FixtureVals // keys "A", "B", "W"
	Instance            InstanceVals
	Step                map[string]map[string]string // step name -> capture name -> value
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
