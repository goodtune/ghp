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

	tmp, err := os.MkdirTemp("", "scoperig-gh-")
	if err != nil {
		return nil, fmt.Errorf("gh temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)
	for _, d := range []string{"cfg", "cache", "work"} {
		if err := os.Mkdir(filepath.Join(tmp, d), 0o700); err != nil {
			return nil, fmt.Errorf("gh temp dir: %w", err)
		}
	}

	rctx, cancel := context.WithTimeout(ctx, GHTimeout)
	defer cancel()
	cmd := osexec.CommandContext(rctx, env.GHPath, args...)
	cmd.Dir = filepath.Join(tmp, "work")
	cmd.Env = ghEnv(host, repo, tok, tmp)
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
	}
	if d := ghdebug.FirstDenied(exchanges); d != nil {
		obs.Status = d.Status
	}
	if env.Verbose != nil {
		fmt.Fprintf(env.Verbose, "gh %s -> exit %d, status %d\n%s\n", redact.String(strings.Join(args, " ")), exit, obs.Status, obs.Stderr)
	}
	return obs, nil
}

// stripDebug removes the GH_DEBUG=api log (from the first "* Request at "
// line to the last "* Request took " line) and keeps gh's own messages.
func stripDebug(s string) string {
	lines := strings.SplitAfter(s, "\n")
	first, last := -1, -1
	for i, l := range lines {
		if strings.HasPrefix(l, "* Request at ") && first < 0 {
			first = i
		}
		if strings.HasPrefix(l, "* Request took ") {
			last = i
		}
	}
	if first < 0 {
		return s
	}
	if last < first {
		return strings.Join(lines[:first], "")
	}
	return strings.Join(lines[:first], "") + strings.Join(lines[last+1:], "")
}

func capString(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// capWriter keeps the first max bytes and discards the rest.
type capWriter struct {
	buf bytes.Buffer
	max int
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := w.max - w.buf.Len(); room > 0 {
		if len(p) > room {
			w.buf.Write(p[:room])
		} else {
			w.buf.Write(p)
		}
	}
	return len(p), nil
}
