package scenario

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// Load reads root/claims.yaml, root/profiles.yaml and root/scenarios/*.yaml.
// Unknown fields and duplicate IDs or names are errors. Scenarios are
// normalised and returned sorted by ID.
func Load(root string) (*Tree, error) {
	var claims []Claim
	if err := decodeFile(filepath.Join(root, "claims.yaml"), &claims); err != nil {
		return nil, err
	}
	var profiles []Profile
	if err := decodeFile(filepath.Join(root, "profiles.yaml"), &profiles); err != nil {
		return nil, err
	}
	tree := &Tree{
		Claims:    make(map[string]Claim, len(claims)),
		Profiles:  make(map[string]Profile, len(profiles)),
		Scenarios: make([]*Scenario, 0),
	}
	for _, c := range claims {
		if c.ID == "" {
			return nil, fmt.Errorf("claims.yaml: claim with empty id")
		}
		if _, dup := tree.Claims[c.ID]; dup {
			return nil, fmt.Errorf("claims.yaml: duplicate claim id %q", c.ID)
		}
		tree.Claims[c.ID] = c
	}
	for _, p := range profiles {
		if p.Name == "" {
			return nil, fmt.Errorf("profiles.yaml: profile with empty name")
		}
		if _, dup := tree.Profiles[p.Name]; dup {
			return nil, fmt.Errorf("profiles.yaml: duplicate profile name %q", p.Name)
		}
		tree.Profiles[p.Name] = p
	}

	files, err := filepath.Glob(filepath.Join(root, "scenarios", "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("glob scenarios: %w", err)
	}
	sort.Strings(files)
	seen := make(map[string]string)
	for _, f := range files {
		var list []*Scenario
		if err := decodeFile(f, &list); err != nil {
			return nil, err
		}
		for i, s := range list {
			if s == nil {
				return nil, fmt.Errorf("%s: entry %d is empty", f, i)
			}
			if s.ID == "" {
				return nil, fmt.Errorf("%s: entry %d has empty id", f, i)
			}
			if prev, dup := seen[s.ID]; dup {
				return nil, fmt.Errorf("%s: duplicate scenario id %q (first in %s)", f, s.ID, prev)
			}
			seen[s.ID] = f
			s.File = f
			s.Normalise()
			tree.Scenarios = append(tree.Scenarios, s)
		}
	}
	sort.Slice(tree.Scenarios, func(i, j int) bool { return tree.Scenarios[i].ID < tree.Scenarios[j].ID })
	return tree, nil
}

// decodeFile strictly decodes a single YAML document into out.
func decodeFile(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return nil // empty file
		}
		return fmt.Errorf("%s: %w", path, err)
	}
	// A second document would be silently dropped; reject it.
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		return fmt.Errorf("%s: more than one YAML document", path)
	}
	return nil
}

// Normalise converts the rest shorthand (Method/Path/Headers/Body/Expect)
// into a single step when Steps is empty. It is idempotent. Expect moves to
// the step and is cleared on the scenario, so a runner cannot read a stale
// copy; VerdictExpect returns it for classification. The other shorthand
// fields on the scenario are left as-is.
func (s *Scenario) Normalise() {
	if s.Kind != "rest" || len(s.Steps) > 0 || (s.Method == "" && s.Path == "") {
		return
	}
	s.Steps = []Request{{
		Method:  s.Method,
		Path:    s.Path,
		Vhost:   s.Vhost,
		Headers: s.Headers,
		Body:    s.Body,
		Expect:  s.Expect,
	}}
	s.Expect = nil
	s.shorthand = true
}

// Shorthand reports whether Steps was built from the rest shorthand fields.
func (s *Scenario) Shorthand() bool { return s.shorthand }

// VerdictExpect is the expectation the scenario's final observation is
// classified against: Expect, or for the rest shorthand (where Normalise
// moved it into the single step) that step's Expect.
func (s *Scenario) VerdictExpect() *Expect {
	if s.Expect == nil && s.shorthand && len(s.Steps) == 1 {
		return s.Steps[0].Expect
	}
	return s.Expect
}
