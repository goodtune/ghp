// Package corpus builds the checked-in gh request corpus (rig/corpus/gh/...)
// from GH_DEBUG=api captures. Only the request side is kept: REST method and
// path with placeholders, and sanitised GraphQL query, variables and
// operation name. Response bodies are never written.
package corpus

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/goodtune/ghp/tools/scoperig/ghdebug"
	"github.com/goodtune/ghp/tools/scoperig/redact"
)

// Profiles are the token profiles every GraphQL entry carries an expectation for.
var Profiles = []string{"open", "perm-ro", "repo"}

// File is one corpus file: the requests one gh command makes.
type File struct {
	GHVersion string   `json:"gh_version"`
	Command   string   `json:"command"`
	REST      []string `json:"rest"`
	GraphQL   []Entry  `json:"graphql"`
	// SkippedInterleaved lists exchanges left out because gh's debug output
	// for them overlapped another request ("METHOD /path [operation]").
	SkippedInterleaved []string `json:"skipped_interleaved,omitempty"`
}

// Entry is one GraphQL request and its expected verdict per profile.
type Entry struct {
	Operation string                 `json:"operation"`
	Body      Body                   `json:"body"`
	Expect    map[string]Expectation `json:"expect"`
}

// Body is the GraphQL request body as sent to /graphql.
type Body struct {
	Query         string         `json:"query"`
	Variables     map[string]any `json:"variables"`
	OperationName string         `json:"operationName,omitempty"`
}

// Expectation is the expected verdict for one profile.
type Expectation struct {
	Verdict    string `json:"verdict"`
	KnownIssue string `json:"known_issue,omitempty"`
	Current    string `json:"current,omitempty"`
}

var numberedParents = map[string]bool{"pulls": true, "issues": true, "releases": true}

// Build makes the corpus file for one command. owner and repo are the real
// repository the capture was taken against; they are replaced with OWNER and
// REPO, and Build fails if either survives. When prev has an entry with the
// same operation, its expectations are kept; otherwise every profile is
// "allow".
func Build(version, command, owner, repo string, ex []ghdebug.Exchange, prev *File) (File, error) {
	f := File{GHVersion: version, Command: command, REST: make([]string, 0), GraphQL: make([]Entry, 0)}
	ident := identPattern(owner, repo)
	if ident != nil && ident.MatchString(command) {
		return File{}, fmt.Errorf("corpus: owner or repo remains in command %q", command)
	}
	seenREST := map[string]bool{}
	seenGQL := map[string]bool{}
	for _, e := range ex {
		path := e.Path
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
		if e.Interleaved {
			s := e.Method + " " + placeholderPath(path, owner, repo)
			if e.GraphQL != nil && e.GraphQL.OperationName != "" {
				s += " " + e.GraphQL.OperationName
			}
			f.SkippedInterleaved = append(f.SkippedInterleaved, s)
			continue
		}
		if e.GraphQL == nil {
			s := e.Method + " " + placeholderPath(path, owner, repo)
			if ident != nil && ident.MatchString(s) {
				return File{}, fmt.Errorf("corpus: owner or repo remains in REST path %q", s)
			}
			if !seenREST[s] {
				seenREST[s] = true
				f.REST = append(f.REST, s)
			}
			continue
		}
		g, err := ghdebug.Sanitise(*e.GraphQL, owner, repo)
		if err != nil {
			return File{}, err
		}
		if g.Variables == nil {
			g.Variables = map[string]any{}
		}
		g.Variables = replaceNodeIDs(g.Variables).(map[string]any)
		op := g.OperationName
		if op == "" {
			op = "(anonymous)"
		}
		ent := Entry{Operation: op, Body: Body{Query: g.Query, Variables: g.Variables, OperationName: g.OperationName}}
		key, err := json.Marshal(ent.Body)
		if err != nil {
			return File{}, err
		}
		if containsNodeID(key) {
			return File{}, fmt.Errorf("corpus: GraphQL node ID remains in %s request body", op)
		}
		if seenGQL[string(key)] {
			continue
		}
		seenGQL[string(key)] = true
		ent.Expect = expectFor(op, prev)
		f.GraphQL = append(f.GraphQL, ent)
	}
	return f, nil
}

func expectFor(op string, prev *File) map[string]Expectation {
	out := make(map[string]Expectation, len(Profiles))
	if prev != nil {
		for _, p := range prev.GraphQL {
			if p.Operation == op && p.Expect != nil {
				for k, v := range p.Expect {
					out[k] = v
				}
				break
			}
		}
	}
	for _, p := range Profiles {
		if _, ok := out[p]; !ok {
			out[p] = Expectation{Verdict: "allow"}
		}
	}
	return out
}

// placeholderPath replaces the owner and repo after /repos/, any other
// segment equal to the owner, and numeric ids after pulls|issues|releases.
func placeholderPath(path, owner, repo string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		switch {
		case i >= 2 && segs[i-1] == "repos" && strings.EqualFold(s, owner):
			segs[i] = "OWNER"
		case i >= 3 && segs[i-2] == "repos" && strings.EqualFold(s, repo):
			segs[i] = "REPO"
		case i >= 1 && numberedParents[segs[i-1]] && isNumber(s):
			segs[i] = "1"
		case owner != "" && strings.EqualFold(s, owner):
			segs[i] = "OWNER"
		}
	}
	return strings.Join(segs, "/")
}

func isNumber(s string) bool {
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}

func identPattern(owner, repo string) *regexp.Regexp {
	var alts []string
	for _, s := range []string{owner, repo} {
		if s != "" {
			alts = append(alts, regexp.QuoteMeta(s))
		}
	}
	if len(alts) == 0 {
		return nil
	}
	return regexp.MustCompile(`(?i)(^|[^a-z0-9_])(` + strings.Join(alts, "|") + `)($|[^a-z0-9_])`)
}

// Marshal encodes f with two-space indentation and a trailing newline. Map
// keys are sorted by encoding/json, so output is deterministic. It refuses to
// return output that contains a token-shaped string.
func Marshal(f File) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	if redact.Contains(buf.Bytes()) {
		return nil, fmt.Errorf("corpus: token-shaped string in output for %q", f.Command)
	}
	return buf.Bytes(), nil
}

// NodeIDPlaceholder replaces GraphQL global node IDs, which encode the real
// upstream object.
const NodeIDPlaceholder = "NODE_ID"

var (
	nextNodeID   = regexp.MustCompile(`^[A-Z][A-Za-z]*_k[a-z][A-Za-z0-9_-]+$`)
	legacyNodeID = regexp.MustCompile(`^[A-Za-z0-9+/]{16,}={0,2}$`)
	legacyPrefix = regexp.MustCompile(`^[0-9]+:`)
	// nodeIDInText finds next-format node IDs anywhere in marshalled text.
	nodeIDInText = regexp.MustCompile(`\b[A-Z][A-Za-z]*_k[a-z][A-Za-z0-9_-]+`)
	// legacyInText finds base64 runs in marshalled text for decoding checks.
	legacyInText = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)
)

func isNodeID(s string) bool {
	if nextNodeID.MatchString(s) {
		return true
	}
	if !legacyNodeID.MatchString(s) {
		return false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		if dec, err := enc.DecodeString(s); err == nil && legacyPrefix.Match(dec) {
			return true
		}
	}
	return false
}

// replaceNodeIDs walks v and replaces node-ID-shaped strings with NODE_ID.
func replaceNodeIDs(v any) any {
	switch t := v.(type) {
	case string:
		if isNodeID(t) {
			return NodeIDPlaceholder
		}
		return t
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = replaceNodeIDs(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = replaceNodeIDs(x)
		}
		return out
	default:
		return v
	}
}

// containsNodeID reports whether b holds a node-ID-shaped string anywhere.
func containsNodeID(b []byte) bool {
	if nodeIDInText.Match(b) {
		return true
	}
	for _, m := range legacyInText.FindAll(b, -1) {
		if isNodeID(string(m)) {
			return true
		}
	}
	return false
}

// CommandName turns a capture name ("api_repos_cli_cli") into a command
// ("api repos OWNER REPO"): the first segment equal to owner becomes OWNER,
// then segments equal to repo become REPO (case-insensitive).
func CommandName(capture, owner, repo string) string {
	segs := strings.Split(capture, "_")
	ownerDone := false
	for i, s := range segs {
		switch {
		case !ownerDone && owner != "" && strings.EqualFold(s, owner):
			segs[i] = "OWNER"
			ownerDone = true
		case repo != "" && strings.EqualFold(s, repo):
			segs[i] = "REPO"
		case owner != "" && strings.EqualFold(s, owner):
			segs[i] = "OWNER"
		}
	}
	return strings.Join(segs, " ")
}
