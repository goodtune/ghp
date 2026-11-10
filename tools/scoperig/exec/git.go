package exec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	osexec "os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/goodtune/ghp/tools/scoperig/expect"
	"github.com/goodtune/ghp/tools/scoperig/redact"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
	"github.com/goodtune/ghp/tools/scoperig/tokens"
)

// GitTimeout bounds one git invocation.
const GitTimeout = 120 * time.Second

// Git runs kind git scenarios (GIT-C48): a clone or a push through the
// instance's github.com virtual host, as a git client that resolves
// github.com to the instance would. Each run gets a throwaway HOME, no
// system config and no credential helper. The token reaches git only
// through an http.extraHeader in a 0600 gitconfig file inside that HOME
// (GIT_CONFIG_GLOBAL), never on the command line or in the environment.
// Redirects are not followed, so the header cannot reach another host.
type Git struct{}

// Kind implements Executor.
func (Git) Kind() string { return "git" }

// gitStatusRE matches the HTTP status git prints for a failed request.
var gitStatusRE = regexp.MustCompile(`The requested URL returned error: (\d{3})`)

// lookupHost resolves the instance host for http.curloptResolve (a variable
// for tests).
var lookupHost = net.DefaultResolver.LookupHost

// gitTarget returns the clone URL for owner/name on the github.com vhost and
// the curl resolve entry that sends it to the instance address.
func gitTarget(ctx context.Context, apiBase, owner, name string) (cloneURL, resolve string, err error) {
	bu, err := url.Parse(apiBase)
	if err != nil {
		return "", "", fmt.Errorf("base url: %w", err)
	}
	if bu.Scheme != "https" {
		return "", "", errors.New("kind git needs an https instance URL")
	}
	host, port := bu.Hostname(), bu.Port()
	if port == "" {
		port = "443"
	}
	addr := host
	if net.ParseIP(host) == nil {
		addrs, err := lookupHost(ctx, host)
		if err != nil || len(addrs) == 0 {
			return "", "", fmt.Errorf("resolve %s: %v", host, err)
		}
		addr = addrs[0]
	}
	if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
		addr = "[" + addr + "]"
	}
	authority := "github.com"
	if port != "443" {
		authority += ":" + port
	}
	return "https://" + authority + "/" + owner + "/" + name + ".git", "github.com:" + port + ":" + addr, nil
}

// gitEnv builds the child environment. globalConfig is the
// GIT_CONFIG_GLOBAL file.
func gitEnv(home, caFile, globalConfig string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"TMPDIR=" + os.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + globalConfig,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=",
		"SSH_ASKPASS=",
		"GIT_CEILING_DIRECTORIES=" + home,
		"LC_ALL=C",
	}
	if caFile != "" {
		env = append(env, "GIT_SSL_CAINFO="+caFile)
	}
	return env
}

// writeGitConfig writes config entries ("section.key", value) to a new
// 0600 gitconfig file at path, quoting each value.
func writeGitConfig(path string, config [][2]string) error {
	var b strings.Builder
	for _, kv := range config {
		i := strings.LastIndexByte(kv[0], '.')
		if i <= 0 || strings.ContainsAny(kv[1], "\n\r\x00") {
			return fmt.Errorf("bad git config entry %q", kv[0])
		}
		v := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(kv[1])
		fmt.Fprintf(&b, "[%s]\n\t%s = \"%s\"\n", kv[0][:i], kv[0][i+1:], v)
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

// gitConfigEntries is the configuration every rig git network command
// uses: no credential helper, github.com resolved to the instance, the
// token header, and no redirects (the header must not follow one).
func gitConfigEntries(resolve, header string) [][2]string {
	return [][2]string{
		{"credential.helper", ""},
		{"http.curloptResolve", resolve},
		{"http.extraHeader", header},
		{"http.followRedirects", "false"},
		{"protocol.version", "2"},
	}
}

// runGit runs git with args in dir and returns the exit code and the
// capped, redacted stdout and stderr. err is a rig error (git missing,
// timeout).
func runGit(ctx context.Context, dir string, env []string, args ...string) (int, string, string, error) {
	rctx, cancel := context.WithTimeout(ctx, GitTimeout)
	defer cancel()
	cmd := osexec.CommandContext(rctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = env
	SetProcessGroup(cmd)
	cmd.WaitDelay = 2 * time.Second
	stdout, stderr := &capWriter{max: MaxBody}, &capWriter{max: MaxBody}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if rctx.Err() != nil {
		return 0, "", "", fmt.Errorf("git %s timed out: %w", args[0], rctx.Err())
	}
	exit := 0
	var exitErr *osexec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		exit = exitErr.ExitCode()
	default:
		return 0, "", "", fmt.Errorf("run git: %s", redact.String(err.Error()))
	}
	return exit, string(redact.Bytes(stdout.buf.Bytes())), redact.String(stderr.buf.String()), nil
}

// Run implements Executor.
func (Git) Run(ctx context.Context, s *scenario.Scenario, tok tokens.Handle, env *RunEnv) (*expect.Observation, error) {
	var ref scenario.RepoRef
	switch s.Repo {
	case "A":
		ref = env.Vars.RepoA
	case "B":
		ref = env.Vars.RepoB
	case "W":
		ref = env.Vars.RepoW
	default:
		return nil, fmt.Errorf("scenario %s: unknown repo %q", s.ID, s.Repo)
	}
	// Defence in depth behind validation: never write to A or B.
	if s.GitOp == "push" && s.Repo != "W" {
		return nil, fmt.Errorf("scenario %s: git push only to W", s.ID)
	}
	cloneURL, resolve, err := gitTarget(ctx, env.APIBase, ref.Owner, ref.Name)
	if err != nil {
		return nil, fmt.Errorf("scenario %s: %w", s.ID, err)
	}
	config := gitConfigEntries(resolve, tok.GitExtraHeader())

	for attempt := 0; ; attempt++ {
		obs, err := runGitOnce(ctx, s, cloneURL, config, env)
		if err != nil {
			return nil, err
		}
		line := ""
		if *obs.GHExit != 0 && obs.Status == 0 {
			line = ghTransportFailure(obs.Stderr)
		}
		if line == "" {
			return obs, nil
		}
		// A push may have been applied; only a clone is retried.
		if s.GitOp != "clone" {
			return nil, fmt.Errorf("scenario %s: git transport error during a push (not retried: the write may have been applied): %s", s.ID, line)
		}
		if attempt >= TransportRetries {
			return nil, fmt.Errorf("scenario %s: git transport error after %d attempts: %s", s.ID, attempt+1, line)
		}
		if !sleepCtx(ctx, transportBackoff(attempt+1)) {
			return nil, fmt.Errorf("scenario %s: git transport error: %s (%w)", s.ID, line, ctx.Err())
		}
	}
}

func runGitOnce(ctx context.Context, s *scenario.Scenario, cloneURL string, config [][2]string, env *RunEnv) (*expect.Observation, error) {
	home, err := os.MkdirTemp("", "scoperig-git-")
	if err != nil {
		return nil, fmt.Errorf("git temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(home) }()
	netCfg, localCfg := filepath.Join(home, "net.gitconfig"), filepath.Join(home, "local.gitconfig")
	if err := writeGitConfig(netCfg, config); err != nil {
		return nil, fmt.Errorf("scenario %s: %w", s.ID, err)
	}
	if err := writeGitConfig(localCfg, nil); err != nil {
		return nil, fmt.Errorf("scenario %s: %w", s.ID, err)
	}
	genv := gitEnv(home, env.CAFile, netCfg)
	// Local commands get no token or resolve entry.
	lenv := gitEnv(home, "", localCfg)
	work := filepath.Join(home, "work")

	var exit int
	var stdout, stderr string
	started := time.Now()
	switch s.GitOp {
	case "clone":
		exit, stdout, stderr, err = runGit(ctx, home, genv, "clone", "--quiet", "--depth", "1", "--no-tags", cloneURL, work)
	case "push":
		branch, xerr := scenario.Expand(s.Branch, env.Vars)
		if xerr != nil {
			return nil, fmt.Errorf("scenario %s: branch: %w", s.ID, xerr)
		}
		for _, args := range [][]string{
			{"init", "--quiet", work},
			{"-C", work, "-c", "user.name=scoperig", "-c", "user.email=scoperig@users.noreply.github.com",
				"commit", "--quiet", "--allow-empty", "-m", "scoperig " + env.Vars.RunID},
		} {
			code, _, serr, rerr := runGit(ctx, home, lenv, args...)
			if rerr != nil {
				return nil, fmt.Errorf("scenario %s: %w", s.ID, rerr)
			}
			if code != 0 {
				return nil, fmt.Errorf("scenario %s: git %s: exit %d: %s", s.ID, args[0], code, strings.TrimSpace(serr))
			}
		}
		exit, stdout, stderr, err = runGit(ctx, work, genv, "push", "--quiet", "--no-verify", cloneURL, "HEAD:refs/heads/"+branch)
	default:
		return nil, fmt.Errorf("scenario %s: unknown git_op %q", s.ID, s.GitOp)
	}
	if err != nil {
		return nil, fmt.Errorf("scenario %s: %w", s.ID, err)
	}
	obs := &expect.Observation{GHExit: &exit, Stdout: stdout, Stderr: stderr, RequestedAt: started, RespondedAt: time.Now()}
	if m := gitStatusRE.FindStringSubmatch(stderr); m != nil {
		obs.Status, _ = strconv.Atoi(m[1])
	}
	if env.Verbose != nil {
		_, _ = fmt.Fprintf(env.Verbose, "git %s %s -> exit %d, status %d\n%s\n", s.GitOp, redact.String(cloneURL), exit, obs.Status, stderr)
	}
	return obs, nil
}
