package exec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/goodtune/ghp/internal/asciiutil"
	"github.com/goodtune/ghp/tools/scoperig/expect"
	"github.com/goodtune/ghp/tools/scoperig/redact"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
	"github.com/goodtune/ghp/tools/scoperig/tokens"
)

// GitCredentialTimeout bounds one `ghp auth git-credential` invocation.
const GitCredentialTimeout = 60 * time.Second

// gitCredSessionPrefix is the session_id prefix of tokens the helper mints.
const gitCredSessionPrefix = "git-credential:"

// GitCredential runs kind git_credential scenarios (CRED-C55): the
// `ghp auth git-credential` helper from env.GHPPath, with a throwaway HOME,
// the file cache tier, agent tokens from the rig's agent installation app
// (never the instance's default app), and the session from the rig's own
// GHP_SERVER_URL and GHP_USER_TOKEN in the environment (no config file, so
// no dotvault). For repo W it runs get, get (cache hit), uses the token on
// W and A, erase, get, clear, and returns a JSON summary of what it saw as
// the observation body. Every token it finds is revoked before it returns.
// Token values never leave the function: the summary holds only a prefix.
type GitCredential struct{}

// Kind implements Executor.
func (GitCredential) Kind() string { return "git_credential" }

type listedGitCredToken struct {
	ID           string          `json:"id"`
	SessionID    string          `json:"session_id"`
	TokenType    string          `json:"token_type"`
	TokenPrefix  string          `json:"token_prefix"`
	AppID        string          `json:"app_id"`
	Repositories json.RawMessage `json:"repositories"`
	RevokedAt    *string         `json:"revoked_at"`
}

// gitCredSummary is the observation body. Fields stay at their zero value
// when the flow stopped before reaching them.
type gitCredSummary struct {
	GetExit            int             `json:"get_exit"`
	FirstMinted        int             `json:"first_minted"`
	TokenPrefix        string          `json:"token_prefix"`
	Username           string          `json:"username"`
	TokenType          string          `json:"token_type"`
	Repositories       json.RawMessage `json:"repositories"`
	SecondGetExit      int             `json:"second_get_exit"`
	SecondGetSameToken bool            `json:"second_get_same_token"`
	SecondGetMinted    int             `json:"second_get_minted"`
	WStatus            int             `json:"w_status"`
	AStatus            int             `json:"a_status"`
	EraseExit          int             `json:"erase_exit"`
	EraseRevoked       bool            `json:"erase_revoked"`
	ThirdGetMinted     int             `json:"third_get_minted"`
	ClearExit          int             `json:"clear_exit"`
	ClearOutput        string          `json:"clear_output"`
	ClearRevoked       bool            `json:"clear_revoked"`
	// ForeignNewTokens counts helper-session tokens that appeared during
	// the flow but do not match a password this run's helper returned (for
	// example the operator's own helper running concurrently). They are
	// never revoked or counted as minted.
	ForeignNewTokens int    `json:"foreign_new_tokens"`
	Stopped          string `json:"stopped,omitempty"`
}

// Run implements Executor.
func (GitCredential) Run(ctx context.Context, s *scenario.Scenario, _ tokens.Handle, env *RunEnv) (obs *expect.Observation, err error) {
	switch {
	case env.GHPPath == "":
		return nil, fmt.Errorf("scenario %s: ghp path not set (GHP_RIG_GHP)", s.ID)
	case env.AgentAppRecordID == "":
		return nil, fmt.Errorf("scenario %s: agent installation app not set", s.ID)
	case s.Repo != "W":
		return nil, fmt.Errorf("scenario %s: git_credential runs only for repo W", s.ID)
	}
	home, err := os.MkdirTemp("", "scoperig-gitcred-")
	if err != nil {
		return nil, fmt.Errorf("git_credential temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(home) }()

	var sum gitCredSummary
	// Backstop: revoke every token attributed to this run, whatever happened.
	var found []string
	defer func() {
		rctx := context.WithoutCancel(ctx)
		var errs []error
		for _, id := range found {
			if rerr := env.Tokens.Revoke(rctx, id); rerr != nil {
				errs = append(errs, rerr)
			}
		}
		if len(errs) > 0 && err == nil {
			obs, err = nil, fmt.Errorf("scenario %s: revoke helper tokens: %s", s.ID, redact.String(errors.Join(errs...).Error()))
		}
	}()

	w := env.Vars.RepoW
	// attribute returns the new tokens that are provably this run's: the
	// listed token_prefix is a prefix of the password the helper returned,
	// the repositories are exactly [W] and the app is the agent app. Only
	// these are counted and revoked; other new helper-session tokens are
	// counted in ForeignNewTokens and left alone.
	attribute := func(before, after []listedGitCredToken, pw string) []listedGitCredToken {
		var mine []listedGitCredToken
		for _, t := range newGitCredTokens(before, after) {
			if matchesGitCred(t, pw, w.String(), env.AgentAppRecordID) {
				mine = append(mine, t)
				found = append(found, t.ID)
			} else {
				sum.ForeignNewTokens++
			}
		}
		return mine
	}
	request := "protocol=https\nhost=github.com\npath=" + w.Owner + "/" + w.Name + ".git\n"
	var stderr strings.Builder
	helper := func(op, stdin string) (int, string, error) {
		code, out, serr, herr := runGitCredHelper(ctx, env, home, op, stdin)
		if serr != "" {
			stderr.WriteString(op + ": " + serr + "\n")
		}
		return code, out, herr
	}
	finish := func(stopped string) (*expect.Observation, error) {
		sum.Stopped = stopped
		body, merr := json.Marshal(sum)
		if merr != nil {
			return nil, merr
		}
		exit := 0
		return &expect.Observation{Status: http.StatusOK, Header: http.Header{}, Body: body, GHExit: &exit,
			Stdout: sum.ClearOutput, Stderr: capString(redact.String(stderr.String()), MaxBody)}, nil
	}

	before, err := listGitCredTokens(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("scenario %s: %w", s.ID, err)
	}
	// 1. get mints a token pinned to W.
	code, out, err := helper("get", request+"\n")
	if err != nil {
		return nil, fmt.Errorf("scenario %s: %w", s.ID, err)
	}
	sum.GetExit = code
	after, err := listGitCredTokens(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("scenario %s: %w", s.ID, err)
	}
	cred := parseCredential(out)
	pw := cred["password"]
	minted := attribute(before, after, pw)
	sum.FirstMinted = len(minted)
	if code != 0 || pw == "" || len(minted) != 1 {
		return finish("first get")
	}
	sum.TokenPrefix, sum.Username = tokenPrefix(pw), cred["username"]
	sum.TokenType, sum.Repositories = minted[0].TokenType, minted[0].Repositories
	id1 := minted[0].ID

	// 2. A second get is a cache hit: same token, nothing minted.
	code, out, err = helper("get", request+"\n")
	if err != nil {
		return nil, fmt.Errorf("scenario %s: %w", s.ID, err)
	}
	sum.SecondGetExit = code
	pw2 := parseCredential(out)["password"]
	sum.SecondGetSameToken = sameToken(pw, pw2)
	after2, err := listGitCredTokens(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("scenario %s: %w", s.ID, err)
	}
	sum.SecondGetMinted = len(attribute(after, after2, pw2))

	// 3. The token reads W and is refused on A.
	auth := func(r *http.Request) { r.Header.Set("Authorization", "token "+pw) }
	for _, c := range []struct {
		ref scenario.RepoRef
		dst *int
	}{{w, &sum.WStatus}, {env.Vars.RepoA, &sum.AStatus}} {
		o, rerr := verbatimRequest(ctx, env.APIBase, "/repos/"+url.PathEscape(c.ref.Owner)+"/"+url.PathEscape(c.ref.Name),
			&scenario.Request{Method: http.MethodGet}, auth, env)
		if rerr != nil {
			return nil, fmt.Errorf("scenario %s: %w", s.ID, rerr)
		}
		*c.dst = o.Status
	}

	// 4. erase revokes it on the server.
	code, _, err = helper("erase", request+"username="+cred["username"]+"\npassword="+pw+"\n\n")
	if err != nil {
		return nil, fmt.Errorf("scenario %s: %w", s.ID, err)
	}
	sum.EraseExit = code
	if sum.EraseRevoked, err = gitCredRevoked(ctx, env, id1); err != nil {
		return nil, fmt.Errorf("scenario %s: %w", s.ID, err)
	}

	// 5. get mints a new token; clear revokes it.
	before3, err := listGitCredTokens(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("scenario %s: %w", s.ID, err)
	}
	_, out, err = helper("get", request+"\n")
	if err != nil {
		return nil, fmt.Errorf("scenario %s: %w", s.ID, err)
	}
	after3, err := listGitCredTokens(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("scenario %s: %w", s.ID, err)
	}
	minted = attribute(before3, after3, parseCredential(out)["password"])
	sum.ThirdGetMinted = len(minted)
	code, out, err = helper("clear", "")
	if err != nil {
		return nil, fmt.Errorf("scenario %s: %w", s.ID, err)
	}
	sum.ClearExit, sum.ClearOutput = code, strings.TrimSpace(redact.String(out))
	if len(minted) != 1 {
		return finish("third get")
	}
	if sum.ClearRevoked, err = gitCredRevoked(ctx, env, minted[0].ID); err != nil {
		return nil, fmt.Errorf("scenario %s: %w", s.ID, err)
	}
	return finish("")
}

// runGitCredHelper runs `<ghp> auth git-credential <op>` with stdin.
func runGitCredHelper(ctx context.Context, env *RunEnv, home, op, stdin string) (int, string, string, error) {
	rctx, cancel := context.WithTimeout(ctx, GitCredentialTimeout)
	defer cancel()
	cmd := osexec.CommandContext(rctx, env.GHPPath, "auth", "git-credential",
		"--type", "agent", "--app", env.AgentAppRecordID, "--cache-backend", "file", op)
	cmd.Dir = home
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"USERPROFILE=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"XDG_CONFIG_DIRS=" + filepath.Join(home, "xdg"),
		"TMPDIR=" + os.TempDir(),
		"LC_ALL=C",
		"GHP_SERVER_URL=" + env.Mgmt,
		"GHP_USER_TOKEN=" + env.Session,
	}
	if ca := os.Getenv("SSL_CERT_FILE"); ca != "" {
		cmd.Env = append(cmd.Env, "SSL_CERT_FILE="+ca)
	} else if env.CAFile != "" {
		cmd.Env = append(cmd.Env, "SSL_CERT_FILE="+env.CAFile)
	}
	SetProcessGroup(cmd)
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdin = strings.NewReader(stdin)
	stdout, stderr := &capWriter{max: MaxBody}, &capWriter{max: MaxBody}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if rctx.Err() != nil {
		return 0, "", "", fmt.Errorf("ghp auth git-credential %s timed out: %w", op, rctx.Err())
	}
	code := 0
	var exitErr *osexec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	default:
		return 0, "", "", fmt.Errorf("run ghp: %s", redact.String(err.Error()))
	}
	// stdout of get holds the token: the caller parses it and never stores it.
	return code, stdout.buf.String(), strings.TrimSpace(redact.String(stderr.buf.String())), nil
}

// parseCredential reads git credential protocol key=value lines.
func parseCredential(out string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimRight(l, "\r"), "="); ok {
			m[k] = v
		}
	}
	return m
}

// tokenPrefix returns the token's type prefix ("gha_", "ghx_") or "other".
func tokenPrefix(tok string) string {
	if i := strings.IndexByte(tok, '_'); i > 0 && i <= 4 {
		return tok[:i+1]
	}
	return "other"
}

func listGitCredTokens(ctx context.Context, env *RunEnv) ([]listedGitCredToken, error) {
	o, err := verbatimRequest(ctx, env.Mgmt, "/api/tokens", &scenario.Request{Method: http.MethodGet}, sessionAuth(env.Session), env)
	if err != nil {
		return nil, fmt.Errorf("list tokens: %w", err)
	}
	if o.Status != http.StatusOK {
		return nil, fmt.Errorf("list tokens: status %d", o.Status)
	}
	var toks []listedGitCredToken
	if err := json.NewDecoder(bytes.NewReader(o.Body)).Decode(&toks); err != nil {
		return nil, fmt.Errorf("decode token list: %w", err)
	}
	return toks, nil
}

// newGitCredTokens returns the unrevoked helper tokens in after that are
// not in before.
func newGitCredTokens(before, after []listedGitCredToken) []listedGitCredToken {
	seen := map[string]bool{}
	for _, t := range before {
		seen[t.ID] = true
	}
	var out []listedGitCredToken
	for _, t := range after {
		if !seen[t.ID] && strings.HasPrefix(t.SessionID, gitCredSessionPrefix) {
			out = append(out, t)
		}
	}
	return out
}

func gitCredRevoked(ctx context.Context, env *RunEnv, id string) (bool, error) {
	o, err := verbatimRequest(ctx, env.Mgmt, "/api/tokens/"+url.PathEscape(id), &scenario.Request{Method: http.MethodGet}, sessionAuth(env.Session), env)
	if err != nil {
		return false, fmt.Errorf("get token: %w", err)
	}
	if o.Status != http.StatusOK {
		return false, fmt.Errorf("get token: status %d", o.Status)
	}
	var t listedGitCredToken
	if err := json.Unmarshal(o.Body, &t); err != nil {
		return false, fmt.Errorf("decode token: %w", err)
	}
	return t.RevokedAt != nil, nil
}

// sameToken reports whether two helper passwords are the same token; an
// empty password never matches.
func sameToken(a, b string) bool { return a != "" && a == b }

// matchesGitCred reports whether listed token t is the one whose value is
// pw, pinned to exactly [repo] and minted from app.
func matchesGitCred(t listedGitCredToken, pw, repo, app string) bool {
	if pw == "" || len(t.TokenPrefix) < 8 || !strings.HasPrefix(pw, t.TokenPrefix) {
		return false
	}
	if app == "" || !strings.EqualFold(t.AppID, app) {
		return false
	}
	var repos []string
	if json.Unmarshal(t.Repositories, &repos) != nil || len(repos) != 1 {
		return false
	}
	return asciiutil.EqualFold(repos[0], repo)
}
