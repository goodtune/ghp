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
	for i := 1; i <= 9; i++ {
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

	if n := len(tree.Profiles); n != 11 {
		t.Errorf("profiles: got %d, want 11", n)
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
	"LIFE-C37": 1, "LIFE-C38": 1, "LIFE-C40": 1,
	"BORDER-C43": 3, "BORDER-C44": 1, "MISC-C52": 1,
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
				if r.Expect != nil && r.Expect.Status >= 200 && r.Expect.Status < 300 {
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
