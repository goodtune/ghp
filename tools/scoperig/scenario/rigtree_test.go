package scenario

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// TestRigTree loads the checked-in rig/ tree and checks it is complete.
func TestRigTree(t *testing.T) {
	tree, err := Load("../../../rig")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, e := range Validate(tree, PlaceholderVars()) {
		t.Errorf("validate: %v", e)
	}

	want := make(map[string]bool)
	for i := 1; i <= 54; i++ {
		want[fmt.Sprintf("C%d", i)] = true
	}
	for i := 1; i <= 10; i++ {
		want[fmt.Sprintf("GAP-A%d", i)] = true
	}
	got := make(map[string]string) // normalised key -> claim id
	for id := range tree.Claims {
		key := claimKey(id)
		if prev, dup := got[key]; dup {
			t.Errorf("claims %q and %q both map to %s", prev, id, key)
		}
		got[key] = id
	}
	var missing, extra []string
	for k := range want {
		if _, ok := got[k]; !ok {
			missing = append(missing, k)
		}
	}
	for k, id := range got {
		if !want[k] {
			extra = append(extra, id)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 || len(extra) > 0 {
		t.Errorf("claim set mismatch: missing %v, extra %v", missing, extra)
	}

	if n := len(tree.Profiles); n != 13 {
		t.Errorf("profiles: got %d, want 13", n)
	}

	testable := map[string]string{"C42": "never", "C53": "never", "C45": "manual", "C54": "manual"}
	for k, id := range got {
		c := tree.Claims[id]
		w, ok := testable[k]
		if !ok {
			w = "periodic"
		}
		if c.Testable != w {
			t.Errorf("%s: testable %q, want %q", id, c.Testable, w)
		}
		if c.Iteration < 1 || c.Iteration > 4 {
			t.Errorf("%s: iteration %d out of range", id, c.Iteration)
		}
		if c.Doc == "" || c.Claim == "" {
			t.Errorf("%s: doc and claim are required", id)
		}
	}
	checkScenarioCoverage(t, tree)

	for _, suffix := range []string{"-C42", "-C53"} {
		if id := findSuffix(tree, suffix); id == "" || tree.Claims[id].Testable != "never" {
			t.Errorf("claim *%s must exist with testable never", suffix)
		}
	}
	for _, suffix := range []string{"-C45", "-C54"} {
		if id := findSuffix(tree, suffix); id == "" || tree.Claims[id].Testable != "manual" {
			t.Errorf("claim *%s must exist with testable manual", suffix)
		}
	}
}

// claimKey maps "REPO-C05" to "C5" and leaves "GAP-A1" unchanged.
func claimKey(id string) string {
	if strings.HasPrefix(id, "GAP-") {
		return id
	}
	i := strings.LastIndex(id, "-C")
	if i < 0 {
		return id
	}
	n := strings.TrimLeft(id[i+2:], "0")
	return "C" + n
}

func findSuffix(tree *Tree, suffix string) string {
	for id := range tree.Claims {
		if strings.HasSuffix(id, suffix) {
			return id
		}
	}
	return ""
}

// task18Claims are the iteration-1 REST, lifecycle, border and misc claims
// (spec section 7) with the minimum scenario count each must have.
var task18Claims = map[string]int{
	"REPO-C05": 1, "REPO-C06": 3, "REPO-C07": 2, "REPO-C10": 1,
	"PERM-C11": 1, "PERM-C12": 1, "PERM-C13": 2, "PERM-C14": 2, "PERM-C15": 2, "PERM-C16": 1,
	"OPEN-C20": 3, "OPEN-C21": 1,
	"LIFE-C37": 2, "LIFE-C38": 1, "LIFE-C40": 1,
	"BORDER-C43": 3, "BORDER-C44": 1, "MISC-C52": 1,
	// batch 4
	"PERM-C17": 1, "PERM-C19": 2, "REPO-C09": 2, "TOK-C01": 3, "LIFE-C41": 1, "BORDER-C47": 1,
}

// checkScenarioCoverage asserts that every iteration-1 claim that is not a
// GAP, GQL or GH claim has scenarios, and that every scenario with a
// non-GET step either declares requires: [repo_w_push] or is token_api.
func checkScenarioCoverage(t *testing.T, tree *Tree) {
	t.Helper()
	count := make(map[string]int)
	for _, s := range tree.Scenarios {
		count[s.Claim]++
		if !strings.HasPrefix(s.ID, s.Claim+".") || len(s.ID) == len(s.Claim)+1 {
			t.Errorf("scenario %q: id must be <claim>.<slug> for claim %q", s.ID, s.Claim)
		}
		if s.Kind == "token_api" {
			continue
		}
		write, succeeds := false, false
		for _, r := range append(append([]Request{}, s.Steps...), s.Cleanup...) {
			if m := strings.ToUpper(strings.TrimSpace(r.Method)); m != "" && m != "GET" && m != "HEAD" {
				write = true
				if r.Expect != nil && expectsSuccess(r.Expect) {
					succeeds = true
				}
			}
		}
		if s.Kind == "graphql" {
			continue // graphql uses POST for reads; the mutation rule covers writes
		}
		if write && !contains(s.Requires, "repo_w_push") {
			t.Errorf("scenario %q has a non-GET step but does not require repo_w_push", s.ID)
		}
		if succeeds && len(s.Cleanup) == 0 {
			t.Errorf("scenario %q expects a successful write but has no cleanup", s.ID)
		}
	}
	for id, c := range tree.Claims {
		if c.Iteration != 1 || c.Testable != "periodic" {
			continue
		}
		if strings.HasPrefix(id, "GAP-") || strings.HasPrefix(id, "GQL-") || strings.HasPrefix(id, "GH-") {
			continue
		}
		if count[id] == 0 {
			t.Errorf("iteration-1 claim %s has no scenario", id)
		}
	}
	for id, n := range task18Claims {
		if count[id] < n {
			t.Errorf("claim %s: got %d scenarios, want >= %d", id, count[id], n)
		}
	}
}

func contains(xs []string, x string) bool {
	for _, e := range xs {
		if e == x {
			return true
		}
	}
	return false
}

// task19Claims are the iteration-1 GraphQL claims (spec section 7) with the
// minimum scenario count each must have.
var task19Claims = map[string]int{
	"GQL-C24": 1, "GQL-C25": 2, "GQL-C26": 4, "GQL-C27": 1, "GQL-C28": 2,
	"GQL-C29": 1, "GQL-C31": 2, "GQL-C32": 1, "GQL-C33": 1,
	// batch 4. GAP-A9 counts generated scenarios: the gh 2.102.0 corpus has
	// 19 queries, each replayed for three profiles (57 scenarios); 19 is a
	// floor of one per query, not the exact generated total.
	"GQL-C22": 2, "GQL-C23": 2, "GQL-C30": 1, "GQL-C34": 1, "GQL-C35": 3, "GQL-C36": 6,
	"GAP-A4": 3, "GAP-A9": 19,
}

// task19Scenarios are scenario IDs that other code refers to by name
// (validator allowlists and probe exceptions), so they must exist exactly.
var task19Scenarios = []string{
	"GQL-C28.mixed-literal-and-variable",
	"GQL-C31.createissue-ro-denied",
	"GQL-C31.createissue-rw-allowed",
	"GQL-C30.unmapped-mutation-denied",
	"GAP-A1.delete-ref-contents-ro",
	"GAP-A2.repositories-by-id",
	"GAP-A3.github-vhost-archive",
	"GAP-A6.agent-mint",
	"GAP-A7.dotdot-path",
}

// TestRigTreeTask19 checks GraphQL and GAP probe coverage.
func TestRigTreeTask19(t *testing.T) {
	tree, err := Load("../../../rig")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	count := make(map[string]int)
	byID := make(map[string]*Scenario)
	for _, s := range tree.Scenarios {
		count[s.Claim]++
		byID[s.ID] = s
	}
	for id, n := range task19Claims {
		if count[id] < n {
			t.Errorf("claim %s: got %d scenarios, want >= %d", id, count[id], n)
		}
	}
	for _, id := range task19Scenarios {
		if byID[id] == nil {
			t.Errorf("scenario %s is missing", id)
		}
	}
	for _, s := range tree.Scenarios {
		if strings.HasPrefix(s.Claim, "GQL-") && s.Kind != "graphql" {
			t.Errorf("scenario %s: GQL claims must use kind graphql", s.ID)
		}
		if strings.HasPrefix(s.Claim, "GAP-") && s.KnownIssue != "" && s.Observed == nil {
			t.Errorf("scenario %s: known_issue without observed", s.ID)
		}
		// Every 403 expectation must assert that GHP (not GitHub) denied.
		for _, e := range scenarioExpects(s) {
			if e.Status == 403 && (e.GHPDenial == nil || !*e.GHPDenial) && strings.HasPrefix(s.Claim, "GQL-") {
				t.Errorf("scenario %s: 403 expectation without ghp_denial: true", s.ID)
			}
		}
	}
	if s := byID["GQL-C31.createissue-rw-allowed"]; s != nil {
		if !contains(s.Requires, "repo_w_push") || len(s.Cleanup) == 0 {
			t.Errorf("%s: must require repo_w_push and close the issue in cleanup", s.ID)
		}
	}
	if s := byID["GAP-A3.github-vhost-archive"]; s != nil {
		if s.Vhost != "github.com" || !contains(s.Requires, "github_vhost") {
			t.Errorf("%s: must use vhost github.com and require github_vhost", s.ID)
		}
	}
	if s := byID["GAP-A6.agent-mint"]; s != nil {
		if s.Kind != "token_api" || !contains(s.Requires, "agent_installation") {
			t.Errorf("%s: must be token_api and require agent_installation", s.ID)
		}
	}
}

func scenarioExpects(s *Scenario) []*Expect {
	out := []*Expect{s.Expect}
	for i := range s.Steps {
		out = append(out, s.Steps[i].Expect)
	}
	if s.Request != nil {
		out = append(out, s.Request.Expect)
	}
	var nn []*Expect
	for _, e := range out {
		if e != nil {
			nn = append(nn, e)
		}
	}
	return nn
}

// TestRigTreeTask20 checks the gh command matrix (GH-C51): 11 commands x
// profiles open, perm-ro and repo-A, all kind gh against repository A, with
// no gh writes.
func TestRigTreeTask20(t *testing.T) {
	tree, err := Load("../../../rig")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	slugs := []string{"repo-view", "pr-list", "pr-view", "pr-status", "pr-checks", "issue-list",
		"issue-view", "release-list", "label-list", "run-list", "api-viewer"}
	want := map[string]bool{}
	for _, slug := range slugs {
		for _, p := range []string{"open", "perm-ro", "repo-A"} {
			want["GH-C51."+slug+"."+p] = true
		}
	}
	n := 0
	for _, s := range tree.Scenarios {
		if s.Claim != "GH-C51" {
			continue
		}
		n++
		if !want[s.ID] {
			t.Errorf("unexpected GH-C51 scenario %s", s.ID)
		}
		delete(want, s.ID)
		if s.Kind != "gh" || s.Repo != "A" {
			t.Errorf("%s: kind=%q repo=%q, want gh/A", s.ID, s.Kind, s.Repo)
		}
		if !strings.HasSuffix(s.ID, "."+s.Profile) {
			t.Errorf("%s: profile %q does not match id", s.ID, s.Profile)
		}
		// repo-A is denied by design (root node(id:) is cross-repository).
		if strings.Contains(s.ID, ".pr-checks.") && s.Profile != "repo-A" {
			// The fixture PR has no checks, so gh pr checks exits 1.
			if s.Expect == nil || s.Expect.ExitCode == nil || *s.Expect.ExitCode != 1 {
				t.Errorf("%s: want exit_code: 1", s.ID)
			}
		}
	}
	if n != 33 {
		t.Errorf("GH-C51 scenarios: got %d, want 33", n)
	}
	for id := range want {
		t.Errorf("missing scenario %s", id)
	}
}

// expectsSuccess reports whether e accepts a 2xx status, either as status
// or as any entry of status_in.
func expectsSuccess(e *Expect) bool {
	if e.Status >= 200 && e.Status < 300 {
		return true
	}
	for _, c := range e.StatusIn {
		if c >= 200 && c < 300 {
			return true
		}
	}
	return false
}

func TestExpectsSuccess(t *testing.T) {
	cases := []struct {
		e    Expect
		want bool
	}{
		{Expect{Status: 201}, true},
		{Expect{Status: 403}, false},
		{Expect{StatusIn: []int{403, 404}}, false},
		{Expect{StatusIn: []int{403, 204}}, true},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%+v", tc.e), func(t *testing.T) {
			if got := expectsSuccess(&tc.e); got != tc.want {
				t.Errorf("expectsSuccess(%+v) = %v, want %v", tc.e, got, tc.want)
			}
		})
	}
}
