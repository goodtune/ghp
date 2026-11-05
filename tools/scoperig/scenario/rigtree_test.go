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
