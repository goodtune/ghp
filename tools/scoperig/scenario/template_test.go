package scenario

import (
	"strings"
	"testing"
	"time"
)

func testVars() *Vars {
	return &Vars{
		RunID: "run1",
		RepoA: RepoRef{Owner: "o", Name: "a", ID: 1},
		RepoB: RepoRef{Owner: "o", Name: "b", ID: 2},
		RepoW: RepoRef{Owner: "o", Name: "w", ID: 3},
		Fixture: map[string]FixtureVals{
			"A": {PRNumber: 7, IssueNumber: 3},
		},
		Instance: InstanceVals{MaxDuration: 168 * time.Hour},
		Step:     map[string]map[string]string{"create": {"number": "42"}},
	}
}

func TestExpand(t *testing.T) {
	tests := []struct {
		name, in, want string
		wantErr        bool
	}{
		{"repo", "{{.RepoA}}", "o/a", false},
		{"owner", "{{.RepoA.Owner}}", "o", false},
		{"fixture", "{{.Fixture.A.PRNumber}}", "7", false},
		{"add", `{{add .Instance.MaxDuration "1h"}}`, "169h0m0s", false},
		{"upper", `{{upper .RepoA.Name}}`, "A", false},
		{"step", "{{.Step.create.number}}", "42", false},
		{"plain", "/user", "/user", false},
		{"unknown field", "{{.Nope}}", "", true},
		{"unknown map key", "{{.Fixture.Z.PRNumber}}", "", true},
		{"unknown step", "{{.Step.missing.x}}", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Expand(tt.in, testVars())
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Expand(%q) = %q, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Expand(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("Expand(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestExpandAny(t *testing.T) {
	in := map[string]any{
		"title": "scoperig {{.RunID}}",
		"list":  []any{"{{.RepoB}}", 5, true},
		"n":     map[string]any{"x": "{{.RepoW.Name}}"},
	}
	out, err := ExpandAny(in, testVars())
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if m["title"] != "scoperig run1" {
		t.Errorf("title = %v", m["title"])
	}
	l := m["list"].([]any)
	if l[0] != "o/b" || l[1] != 5 || l[2] != true {
		t.Errorf("list = %v", l)
	}
	if m["n"].(map[string]any)["x"] != "w" {
		t.Errorf("nested = %v", m["n"])
	}
	if in["title"] != "scoperig {{.RunID}}" {
		t.Error("input was mutated")
	}
	if _, err := ExpandAny([]any{"{{.Bad}}"}, testVars()); err == nil || !strings.Contains(err.Error(), "Bad") {
		t.Errorf("want error naming Bad, got %v", err)
	}
}

func TestExpand_ProfileIDs(t *testing.T) {
	v := testVars()
	v.ProfileIDs = map[string]string{"lifecycle-revoke": "11111111-2222-3333-4444-555555555555"}
	got, err := Expand(`/api/tokens/{{index .ProfileIDs "lifecycle-revoke"}}`, v)
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if want := "/api/tokens/11111111-2222-3333-4444-555555555555"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExpandExpect(t *testing.T) {
	v := &Vars{Login: "octo", RepoA: RepoRef{Owner: "o", Name: "a"}}
	if got, err := ExpandExpect(nil, v); err != nil || got != nil {
		t.Fatalf("nil: %v %v", got, err)
	}
	in := &Expect{
		Status:         200,
		JSON:           map[string]string{"$.login": "{{.Login}}", "$.full_name": "{{.RepoA}}"},
		BodyContains:   []string{"{{.RepoA.Name}}"},
		Header:         map[string]string{"X": "{{.Login}}"},
		StdoutContains: []string{"{{.RepoA}}"},
		StderrContains: []string{"plain"},
	}
	got, err := ExpandExpect(in, v)
	if err != nil {
		t.Fatal(err)
	}
	if got.JSON["$.login"] != "octo" || got.JSON["$.full_name"] != "o/a" || got.BodyContains[0] != "a" ||
		got.Header["X"] != "octo" || got.StdoutContains[0] != "o/a" || got.StderrContains[0] != "plain" || got.Status != 200 {
		t.Errorf("got %+v", got)
	}
	if in.JSON["$.login"] != "{{.Login}}" {
		t.Errorf("input mutated")
	}
	if _, err := ExpandExpect(&Expect{JSON: map[string]string{"$.x": "{{.Nope}}"}}, v); err == nil {
		t.Errorf("missing key: want error")
	}
}
