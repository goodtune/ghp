package main

// scoperig oracle: run the real gh against github.com with GH_DEBUG=api and
// refresh the request corpus under rig/corpus/gh/<version>/.
//
// This is the only part of the rig that talks to GitHub directly. It uses the
// operator's existing gh login, runs read-only commands only, one at a time
// (so GH_DEBUG exchanges never interleave), and keeps the raw captures (which
// hold the operator's credential in the Authorization header) in a 0700 temp
// directory that is always removed.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	osexec "os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/goodtune/ghp/tools/scoperig/corpus"
	"github.com/goodtune/ghp/tools/scoperig/ghdebug"
	"github.com/goodtune/ghp/tools/scoperig/redact"
)

// oracleTimeout bounds one gh invocation in oracle mode.
const oracleTimeout = 120 * time.Second

// oracleTarget is the public github.com repository the matrix runs against.
type oracleTarget struct {
	Owner, Name string
	PR, Issue   int
}

// oracleCommand is one capture: its name (the corpus file name before
// CommandName placeholders) and the read-only gh arguments.
type oracleCommand struct {
	Name string
	Args []string
}

// oracleMatrix is the 19 commands of the 2.102.0 seed corpus. Every command
// is read-only; pr create runs with --dry-run outside any git checkout, so
// gh has nothing to push and creates nothing.
func oracleMatrix(t oracleTarget) []oracleCommand {
	slug := t.Owner + "/" + t.Name
	pr, issue := strconv.Itoa(t.PR), strconv.Itoa(t.Issue)
	return []oracleCommand{
		{"api_graphql_viewer", []string{"api", "graphql", "-f", "query={viewer{login}}"}},
		{"api_repos_" + t.Owner + "_" + t.Name, []string{"api", "repos/" + slug}},
		{"api_user", []string{"api", "user"}},
		{"auth_status", []string{"auth", "status", "--hostname", "github.com"}},
		{"issue_list", []string{"issue", "list"}},
		{"issue_view", []string{"issue", "view", issue}},
		{"label_list", []string{"label", "list"}},
		{"pr_checks", []string{"pr", "checks", pr}},
		{"pr_create_dryrun", []string{"pr", "create", "--dry-run", "--title", "scoperig oracle", "--body", "scoperig oracle", "--head", "scoperig-oracle"}},
		{"pr_diff", []string{"pr", "diff", pr}},
		{"pr_list", []string{"pr", "list"}},
		{"pr_status", []string{"pr", "status"}},
		{"pr_view", []string{"pr", "view", pr}},
		{"release_list", []string{"release", "list"}},
		{"repo_list", []string{"repo", "list", t.Owner, "--limit", "30"}},
		{"repo_view", []string{"repo", "view"}},
		{"run_list", []string{"run", "list"}},
		{"search_prs", []string{"search", "prs", "--repo", slug, "--limit", "30"}},
		{"workflow_list", []string{"workflow", "list"}},
	}
}

type oracleOpts struct {
	GHPath    string
	Version   string // "auto" reads `gh --version`
	Repo      string // owner/name on github.com
	PR, Issue int
	OutRoot   string // e.g. rig/corpus/gh
	// ConfigDir is the operator's real gh config dir; only hosts.yml is read.
	ConfigDir string
	// MkdirTemp creates the private working directory (os.MkdirTemp when nil).
	MkdirTemp func(dir, pattern string) (string, error)
	// Log receives progress and gh exit warnings (discarded when nil).
	Log io.Writer
}

// ghConfigDir mirrors gh's own lookup: $GH_CONFIG_DIR, $XDG_CONFIG_HOME/gh,
// then ~/.config/gh.
func ghConfigDir(getenv func(string) string) (string, error) {
	if d := getenv("GH_CONFIG_DIR"); d != "" {
		return d, nil
	}
	if d := getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "gh"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "gh"), nil
}

// runOracle captures every matrix command, builds the corpus files and,
// only if every file is clean, writes them to <OutRoot>/<version>/. It
// returns a diff of operation and field names against the previous version.
func runOracle(ctx context.Context, o oracleOpts) (string, error) {
	owner, name, ok := strings.Cut(o.Repo, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return "", fmt.Errorf("oracle: repo %q is not owner/name", o.Repo)
	}
	if o.PR <= 0 || o.Issue <= 0 {
		return "", errors.New("oracle: --pr and --issue must be positive")
	}
	if o.MkdirTemp == nil {
		o.MkdirTemp = os.MkdirTemp
	}
	logw := o.Log
	if logw == nil {
		logw = io.Discard
	}
	hosts, err := os.ReadFile(filepath.Join(o.ConfigDir, "hosts.yml"))
	if err != nil {
		return "", fmt.Errorf("oracle: read gh hosts.yml (is gh logged in to github.com?): %w", err)
	}

	tmp, err := o.MkdirTemp("", "scoperig-oracle-")
	if err != nil {
		return "", fmt.Errorf("oracle: temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if err := os.Chmod(tmp, 0o700); err != nil {
		return "", fmt.Errorf("oracle: temp dir: %w", err)
	}
	for _, d := range []string{"cfg", "cache", "work", "raw"} {
		if err := os.Mkdir(filepath.Join(tmp, d), 0o700); err != nil {
			return "", fmt.Errorf("oracle: temp dir: %w", err)
		}
	}
	if err := os.WriteFile(filepath.Join(tmp, "cfg", "hosts.yml"), hosts, 0o600); err != nil {
		return "", fmt.Errorf("oracle: copy hosts.yml: %w", err)
	}
	env := oracleEnv(tmp, o.Repo)

	version := o.Version
	if version == "" || version == "auto" {
		var stdout bytes.Buffer
		if _, err := runOracleGH(ctx, o.GHPath, tmp, env, []string{"--version"}, &stdout, io.Discard); err != nil {
			return "", fmt.Errorf("oracle: gh --version: %w", err)
		}
		if version, err = parseGHVersion(stdout.String()); err != nil {
			return "", err
		}
	} else if _, ok := parseSemver(version); !ok {
		return "", fmt.Errorf("oracle: --gh-version %q is not MAJOR.MINOR.PATCH", version)
	}
	_, _ = fmt.Fprintf(logw, "oracle: gh %s against github.com/%s\n", version, o.Repo)

	// Capture serially: GH_DEBUG output from parallel runs would be useless
	// for diffing and gh itself interleaves concurrent requests.
	matrix := oracleMatrix(oracleTarget{Owner: owner, Name: name, PR: o.PR, Issue: o.Issue})
	for _, c := range matrix {
		raw, err := os.OpenFile(filepath.Join(tmp, "raw", c.Name+".txt"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return "", fmt.Errorf("oracle: %w", err)
		}
		exit, err := runOracleGH(ctx, o.GHPath, tmp, env, c.Args, io.Discard, raw)
		if cerr := raw.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return "", fmt.Errorf("oracle: %s: %w", c.Name, err)
		}
		if exit != 0 {
			_, _ = fmt.Fprintf(logw, "oracle: warning: gh %s exited %d (captured requests are still used)\n", strings.Join(c.Args[:2], " "), exit)
		}
	}

	outDir := filepath.Join(o.OutRoot, version)
	prevVer, err := prevVersionDir(o.OutRoot, version)
	if err != nil {
		return "", err
	}
	type result struct {
		path string
		data []byte
		file corpus.File
		prev *corpus.File // previous version, for the diff
	}
	var results []result
	for _, c := range matrix {
		command := corpus.CommandName(c.Name, owner, name)
		base := strings.ReplaceAll(command, " ", "_") + ".json"
		ex, err := parseCapture(filepath.Join(tmp, "raw", c.Name+".txt"))
		if err != nil {
			return "", fmt.Errorf("oracle: %s: %s", c.Name, redact.String(err.Error()))
		}
		// Expectations come from this version's file if it exists (a re-run),
		// else from the previous version's.
		var older *corpus.File
		if prevVer != "" {
			if older, err = loadCorpusFile(filepath.Join(o.OutRoot, prevVer, base)); err != nil {
				return "", err
			}
		}
		keep := older
		if same, err := loadCorpusFile(filepath.Join(outDir, base)); err != nil {
			return "", err
		} else if same != nil {
			keep = same
		}
		f, err := corpus.Build(version, command, owner, name, ex, keep)
		if err != nil {
			return "", fmt.Errorf("oracle: %s: refusing to write: %s", c.Name, redact.String(err.Error()))
		}
		b, err := corpus.Marshal(f)
		if err != nil {
			return "", fmt.Errorf("oracle: %s: refusing to write: %s", c.Name, redact.String(err.Error()))
		}
		if redact.Contains(b) {
			return "", fmt.Errorf("oracle: %s: token-shaped string in output; refusing to write", c.Name)
		}
		results = append(results, result{filepath.Join(outDir, base), b, f, older})
	}

	// Write only after every file built cleanly.
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}
	var diff strings.Builder
	if prevVer == "" {
		fmt.Fprintf(&diff, "no previous version under %s; every operation is new\n", o.OutRoot)
	} else {
		fmt.Fprintf(&diff, "changes from %s to %s:\n", prevVer, version)
	}
	for _, r := range results {
		if err := os.WriteFile(r.path, r.data, 0o644); err != nil {
			return "", err
		}
		diff.WriteString(corpusDiff(r.prev, r.file))
	}
	return diff.String(), nil
}

// oracleEnv builds gh's environment from scratch: no inherited GH_* or
// GITHUB_* variable reaches gh (so GH_TOKEN, GH_HOST and GH_ENTERPRISE_TOKEN
// cannot redirect it), and the only credential is the copied hosts.yml.
func oracleEnv(tmp, repo string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + filepath.Join(tmp, "work"),
		"TMPDIR=" + os.TempDir(),
		"GH_CONFIG_DIR=" + filepath.Join(tmp, "cfg"),
		"XDG_CACHE_HOME=" + filepath.Join(tmp, "cache"),
		"GH_REPO=" + repo,
		"GH_DEBUG=api",
		"GH_PROMPT_DISABLED=1",
		"NO_COLOR=1",
		"GH_NO_UPDATE_NOTIFIER=1",
		"GH_PAGER=cat",
		"PAGER=cat",
		"GIT_CEILING_DIRECTORIES=" + tmp,
	}
	if ca := os.Getenv("SSL_CERT_FILE"); ca != "" {
		env = append(env, "SSL_CERT_FILE="+ca)
	}
	return env
}

// runOracleGH runs one gh command in tmp/work and returns its exit code.
// A non-zero exit is not an error; failing to start or timing out is.
func runOracleGH(ctx context.Context, ghPath, tmp string, env, args []string, stdout, stderr io.Writer) (int, error) {
	rctx, cancel := context.WithTimeout(ctx, oracleTimeout)
	defer cancel()
	cmd := osexec.CommandContext(rctx, ghPath, args...)
	cmd.Dir = filepath.Join(tmp, "work")
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if rctx.Err() != nil {
		return 0, fmt.Errorf("gh timed out: %w", rctx.Err())
	}
	var ee *osexec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee):
		return ee.ExitCode(), nil
	default:
		return 0, errors.New(redact.String(err.Error()))
	}
}

var ghVersionLine = regexp.MustCompile(`(?m)^gh version (\d+\.\d+\.\d+)\b`)

// parseGHVersion reads the version from `gh --version` output.
func parseGHVersion(s string) (string, error) {
	m := ghVersionLine.FindStringSubmatch(s)
	if m == nil {
		return "", errors.New("oracle: cannot read a MAJOR.MINOR.PATCH version from gh --version; pass --gh-version")
	}
	return m[1], nil
}

func parseSemver(s string) ([3]int, bool) {
	var v [3]int
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

func semverLess(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// prevVersionDir returns the highest MAJOR.MINOR.PATCH directory under root
// that is below version, or "" if there is none.
func prevVersionDir(root, version string) (string, error) {
	cur, ok := parseSemver(version)
	if !ok {
		return "", fmt.Errorf("oracle: version %q is not MAJOR.MINOR.PATCH", version)
	}
	ents, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	best, bestV := "", [3]int{}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		v, ok := parseSemver(e.Name())
		if !ok || !semverLess(v, cur) {
			continue
		}
		if best == "" || semverLess(bestV, v) {
			best, bestV = e.Name(), v
		}
	}
	return best, nil
}

func parseCapture(name string) ([]ghdebug.Exchange, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return ghdebug.Parse(f)
}

func loadCorpusFile(path string) (*corpus.File, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f corpus.File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("oracle: %s: %w", path, err)
	}
	return &f, nil
}

// corpusDiff lists added and removed REST requests, operations and field
// names for one command (sorted set differences). Empty when unchanged.
func corpusDiff(prev *corpus.File, cur corpus.File) string {
	var old corpus.File
	if prev != nil {
		old = *prev
	}
	var lines []string
	add := func(kind string, a, b map[string]bool) {
		for _, s := range setMinus(b, a) {
			lines = append(lines, fmt.Sprintf("  + %s %s", kind, s))
		}
		for _, s := range setMinus(a, b) {
			lines = append(lines, fmt.Sprintf("  - %s %s", kind, s))
		}
	}
	add("rest", toSet(old.REST), toSet(cur.REST))
	oldOps, curOps := map[string]bool{}, map[string]bool{}
	for _, e := range old.GraphQL {
		oldOps[e.Operation] = true
	}
	for _, e := range cur.GraphQL {
		curOps[e.Operation] = true
	}
	add("operation", oldOps, curOps)
	add("field", fieldNames(old), fieldNames(cur))
	if len(lines) == 0 {
		return ""
	}
	return cur.Command + ":\n" + strings.Join(lines, "\n") + "\n"
}

func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func setMinus(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

var (
	gqlString     = regexp.MustCompile(`"""[\s\S]*?"""|"(?:\\.|[^"\\])*"`)
	gqlComment    = regexp.MustCompile(`#[^\n]*`)
	gqlArgs       = regexp.MustCompile(`\([^()]*\)`)
	gqlTypeCond   = regexp.MustCompile(`\b(?:on|fragment|query|mutation|subscription)\s+[_A-Za-z]\w*`)
	gqlSpread     = regexp.MustCompile(`\.\.\.\s*[_A-Za-z]\w*`)
	gqlAlias      = regexp.MustCompile(`[_A-Za-z]\w*\s*:`)
	gqlDirective  = regexp.MustCompile(`@[_A-Za-z]\w*`)
	gqlIdentifier = regexp.MustCompile(`[_A-Za-z]\w*`)
)

// fieldNames approximates the selected field names in every query of f
// without a GraphQL parser: strings, comments, argument lists, aliases,
// directives, fragment spreads and type conditions are stripped and the
// remaining identifiers are taken as field names. It is a review aid only.
func fieldNames(f corpus.File) map[string]bool {
	out := map[string]bool{}
	for _, e := range f.GraphQL {
		q := gqlComment.ReplaceAllString(gqlString.ReplaceAllString(e.Body.Query, " "), " ")
		for {
			n := gqlArgs.ReplaceAllString(q, " ")
			if n == q {
				break
			}
			q = n
		}
		q = gqlTypeCond.ReplaceAllString(q, " ")
		q = gqlSpread.ReplaceAllString(q, " ")
		q = gqlAlias.ReplaceAllString(q, " ")
		q = gqlDirective.ReplaceAllString(q, " ")
		for _, id := range gqlIdentifier.FindAllString(q, -1) {
			switch id {
			case "query", "mutation", "subscription", "fragment", "on":
				continue
			}
			out[id] = true
		}
	}
	return out
}

type oracleFlags struct {
	ghPath, version, repo, out string
	pr, issue                  int
}

func newOracleCmd(stdout, stderr io.Writer, getenv func(string) string) *cobra.Command {
	f := &oracleFlags{}
	cmd := &cobra.Command{
		Use:   "oracle",
		Short: "Capture real gh requests against github.com and refresh rig/corpus/gh (read-only, uses your gh login)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			gh := f.ghPath
			if gh == "" {
				gh = getenv("GHP_RIG_GH")
			}
			if gh == "" {
				p, err := osexec.LookPath("gh")
				if err != nil {
					return &exitError{code: 3, err: errors.New("oracle: gh not found; set --gh or GHP_RIG_GH")}
				}
				gh = p
			}
			cfg, err := ghConfigDir(getenv)
			if err != nil {
				return &exitError{code: 3, err: err}
			}
			diff, err := runOracle(cmd.Context(), oracleOpts{
				GHPath: gh, Version: f.version, Repo: f.repo, PR: f.pr, Issue: f.issue,
				OutRoot: f.out, ConfigDir: cfg, Log: stderr,
			})
			if err != nil {
				return &exitError{code: 3, err: err}
			}
			_, _ = fmt.Fprint(stdout, redact.String(diff))
			return nil
		},
	}
	cmd.Flags().StringVar(&f.ghPath, "gh", "", "gh binary (default $GHP_RIG_GH, then gh on PATH)")
	cmd.Flags().StringVar(&f.version, "gh-version", "auto", `corpus version directory; "auto" reads gh --version`)
	cmd.Flags().StringVar(&f.repo, "oracle-repo", "cli/cli", "public github.com repository (owner/name) to run the read-only commands against")
	cmd.Flags().IntVar(&f.pr, "pr", 1, "pull request number in --oracle-repo for pr view/checks/diff")
	cmd.Flags().IntVar(&f.issue, "issue", 1, "issue number in --oracle-repo for issue view")
	cmd.Flags().StringVar(&f.out, "out", "rig/corpus/gh", "corpus root; files go to <out>/<version>/")
	return cmd
}
