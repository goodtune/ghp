package exec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/goodtune/ghp/tools/scoperig/expect"
	"github.com/goodtune/ghp/tools/scoperig/ghdebug"
	"github.com/goodtune/ghp/tools/scoperig/redact"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
	"github.com/goodtune/ghp/tools/scoperig/tokens"
)

// GHTimeout bounds one gh invocation.
const GHTimeout = 60 * time.Second

// maxGHStderr caps the raw stderr kept for parsing the GH_DEBUG=api log.
// gh's debug log holds every request and response body, so it is much larger
// than the stored Stderr (MaxBody). Output beyond 8 MiB is discarded: later
// exchanges are then missing from Observation.Exchanges, and a denial that
// only appears past the cap is not seen. Scenarios are single commands, so
// this is far above what a run produces.
const maxGHStderr = 8 << 20

// GH runs `gh` scenarios. Each run gets a fresh config dir, cache dir and
// working directory (not a git checkout, so GH_HOST is honoured), and the
// child environment is built from scratch so no inherited GH_* or GITHUB_*
// variable (in particular GH_TOKEN/GITHUB_TOKEN) reaches gh. The token is
// passed only in the environment, never on the command line.
//
// SSL_CERT_FILE is passed through from the rig's own environment when set,
// but Go ignores it on macOS (it uses the system keychain), so there the rig
// relies on the system trust store.
type GH struct{}

// Kind implements Executor.
func (GH) Kind() string { return "gh" }

// ghEnv builds the child environment. repo is "owner/name" or "".
func ghEnv(host, repo string, tok tokens.Handle, tmp string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + tmp,
		"TMPDIR=" + os.TempDir(),
		"GH_HOST=" + host,
		"GH_CONFIG_DIR=" + filepath.Join(tmp, "cfg"),
		"XDG_CACHE_HOME=" + filepath.Join(tmp, "cache"),
		"GH_DEBUG=api",
		"GH_PROMPT_DISABLED=1",
		"NO_COLOR=1",
		"GH_NO_UPDATE_NOTIFIER=1",
		"GH_PAGER=cat",
		"PAGER=cat",
		"GIT_CEILING_DIRECTORIES=" + tmp,
	}
	if repo != "" {
		env = append(env, "GH_REPO="+host+"/"+repo)
	}
	if ca := os.Getenv("SSL_CERT_FILE"); ca != "" {
		env = append(env, "SSL_CERT_FILE="+ca)
	}
	return append(env, tok.GHEnv()...)
}

// Run implements Executor.
func (GH) Run(ctx context.Context, s *scenario.Scenario, tok tokens.Handle, env *RunEnv) (*expect.Observation, error) {
	if env.GHPath == "" {
		return nil, fmt.Errorf("scenario %s: gh path not set", s.ID)
	}
	host := env.Vars.Host
	if host == "" {
		host = env.Vars.Instance.Host
	}
	var repo string
	switch s.Repo {
	case "A":
		repo = env.Vars.RepoA.Owner + "/" + env.Vars.RepoA.Name
	case "B":
		repo = env.Vars.RepoB.Owner + "/" + env.Vars.RepoB.Name
	case "W":
		repo = env.Vars.RepoW.Owner + "/" + env.Vars.RepoW.Name
	case "":
	default:
		return nil, fmt.Errorf("scenario %s: unknown repo %q", s.ID, s.Repo)
	}
	args := make([]string, len(s.Args))
	for i, a := range s.Args {
		e, err := scenario.Expand(a, env.Vars)
		if err != nil {
			return nil, fmt.Errorf("scenario %s: arg %d: %w", s.ID, i, err)
		}
		args[i] = e
	}

	// A transport error (no HTTP response for some request) is retried with
	// a fresh gh run when every logged request is idempotent; one left
	// after TransportRetries is a rig error (ERROR), never FAIL or
	// KNOWN-CHANGED, because gh's output then describes the connection,
	// not the product.
	for attempt := 0; ; attempt++ {
		obs, err := runGHOnce(ctx, s, args, host, repo, tok, env)
		if err != nil {
			return nil, err
		}
		line := ""
		if *obs.GHExit != 0 {
			line = ghTransportFailure(obs.Stderr)
		}
		if line == "" {
			return obs, nil
		}
		if !ghRetryable(obs) {
			return nil, fmt.Errorf("scenario %s: gh transport error during a write (not retried: the write may have been applied): %s", s.ID, line)
		}
		if attempt >= TransportRetries {
			return nil, fmt.Errorf("scenario %s: gh transport error after %d attempts: %s", s.ID, attempt+1, line)
		}
		if env.Verbose != nil {
			_, _ = fmt.Fprintf(env.Verbose, "gh transport error, retrying (%d/%d): %s\n", attempt+1, TransportRetries, line)
		}
		if !sleepCtx(ctx, transportBackoff(attempt+1)) {
			return nil, fmt.Errorf("scenario %s: gh transport error: %s (%w)", s.ID, line, ctx.Err())
		}
	}
}

// runGHOnce runs gh once in a fresh temporary home and work directory.
func runGHOnce(ctx context.Context, s *scenario.Scenario, args []string, host, repo string, tok tokens.Handle, env *RunEnv) (*expect.Observation, error) {
	tmp, err := os.MkdirTemp("", "scoperig-gh-")
	if err != nil {
		return nil, fmt.Errorf("gh temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	for _, d := range []string{"cfg", "cache", "work"} {
		if err := os.Mkdir(filepath.Join(tmp, d), 0o700); err != nil {
			return nil, fmt.Errorf("gh temp dir: %w", err)
		}
	}

	// gh pr status reads the current branch from git, and fails outside a
	// checkout. Make the work dir an empty repo (no remotes; GH_REPO names
	// the base repo) whose HEAD is the fixture branch.
	if b := env.Vars.Fixture[s.Repo].Branch; repo != "" && b != "" {
		if err := gitInit(ctx, filepath.Join(tmp, "work"), tmp, b); err != nil {
			return nil, fmt.Errorf("scenario %s: %w", s.ID, err)
		}
	}

	rctx, cancel := context.WithTimeout(ctx, GHTimeout)
	defer cancel()
	cmd := osexec.CommandContext(rctx, env.GHPath, args...)
	cmd.Dir = filepath.Join(tmp, "work")
	cmd.Env = ghEnv(host, repo, tok, tmp)
	SetProcessGroup(cmd)
	cmd.WaitDelay = 2 * time.Second
	stdout := &capWriter{max: MaxBody}
	stderr := &capWriter{max: maxGHStderr}
	cmd.Stdout, cmd.Stderr = stdout, stderr

	runErr := cmd.Run()
	if rctx.Err() != nil {
		return nil, fmt.Errorf("scenario %s: gh timed out: %w", s.ID, rctx.Err())
	}
	var exitErr *osexec.ExitError
	exit := 0
	switch {
	case runErr == nil:
	case errors.As(runErr, &exitErr):
		exit = exitErr.ExitCode()
	default:
		return nil, fmt.Errorf("scenario %s: run gh: %s", s.ID, redact.String(runErr.Error()))
	}

	exchanges, err := ghdebug.Parse(bytes.NewReader(stderr.buf.Bytes()))
	if err != nil {
		return nil, fmt.Errorf("scenario %s: %w", s.ID, err)
	}
	obs := &expect.Observation{
		GHExit:    &exit,
		Stdout:    string(redact.Bytes(stdout.buf.Bytes())),
		Stderr:    capString(redact.String(stripDebug(stderr.buf.String())), MaxBody),
		Exchanges: exchanges,
		// Exchanges past the cap are missing, so the run cannot be shown
		// to be idempotent.
		GHStderrTruncated: stderr.truncated,
	}
	if d := ghdebug.FirstDenied(exchanges); d != nil {
		obs.Status = d.Status
	}
	if env.Verbose != nil {
		_, _ = fmt.Fprintf(env.Verbose, "gh %s -> exit %d, status %d\n%s\n", redact.String(strings.Join(args, " ")), exit, obs.Status, obs.Stderr)
	}
	return obs, nil
}

// stripDebug removes the GH_DEBUG=api log line by line and keeps every
// other line, so gh's own messages survive wherever they appear (before,
// between or after requests, and after a request with no "* Request took"
// line). A debug line is a "* ", "> " or "< " line, or a line inside an
// exchange's request headers, request body, "GraphQL query:" block or
// response body. Each block ends at its blank line (gh prints one after
// headers and after each body; pretty-printed JSON has none), so a message
// that follows a response body without a "took" line is kept.
//
// "* " and "> " lines are always removed, in every state: gh never starts
// one of its own messages with either prefix. "* Request at" and
// "* Request took" end any open block, including an unterminated
// "GraphQL query:" block, so a capture cut short cannot swallow the rest
// of stderr.
func stripDebug(s string) string {
	const (
		out      = iota // not inside an exchange block
		reqHdr          // after "> " lines
		reqBody         // request body (or waiting for it)
		gql             // inside "GraphQL query:" up to "GraphQL variables:"
		respHdr         // after "< " lines
		respBody        // response body (or waiting for it)
	)
	state := out
	inBody := false
	var keep strings.Builder
	for _, l := range strings.SplitAfter(s, "\n") {
		line := strings.TrimRight(l, "\r\n")
		switch {
		case state == gql && !strings.HasPrefix(line, "* Request at ") && !strings.HasPrefix(line, "* Request took "):
			if strings.HasPrefix(line, "GraphQL variables:") {
				state, inBody = reqBody, true
			}
			continue
		case strings.HasPrefix(line, "* "):
			if strings.HasPrefix(line, "* Request at ") || strings.HasPrefix(line, "* Request took ") {
				state, inBody = out, false
			}
			continue
		case strings.HasPrefix(line, "> "):
			state = reqHdr
			continue
		case strings.HasPrefix(line, "< "):
			state = respHdr
			continue
		case line == "":
			switch {
			case state == reqHdr:
				state, inBody = reqBody, false
			case state == respHdr:
				state, inBody = respBody, false
			case (state == reqBody || state == respBody) && inBody:
				state, inBody = out, false
			case state == out:
				keep.WriteString(l)
			}
			continue
		case state == reqBody && !inBody && line == "GraphQL query:":
			state = gql
			continue
		case state == reqBody || state == respBody:
			inBody = true
			continue
		}
		keep.WriteString(l)
	}
	return keep.String()
}

func capString(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// capWriter keeps the first max bytes and discards the rest.
type capWriter struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	room := w.max - w.buf.Len()
	switch {
	case len(p) <= room:
		w.buf.Write(p)
	case room > 0:
		w.buf.Write(p[:room])
		w.truncated = true
	case len(p) > 0:
		w.truncated = true
	}
	return len(p), nil
}

// gitInit makes dir an empty git repository whose HEAD is refs/heads/branch.
func gitInit(ctx context.Context, dir, home, branch string) error {
	cmd := osexec.CommandContext(ctx, "git", "init", "-q", dir)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "GIT_CONFIG_NOSYSTEM=1"}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git init: %v: %s", err, strings.TrimSpace(string(out)))
	}
	cmd = osexec.CommandContext(ctx, "git", "-C", dir, "symbolic-ref", "HEAD", "refs/heads/"+branch)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "GIT_CONFIG_NOSYSTEM=1"}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git symbolic-ref: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
