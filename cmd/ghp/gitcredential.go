package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	dvclient "github.com/goodtune/dotvault/client"
	"github.com/spf13/cobra"

	"github.com/goodtune/ghp/internal/asciiutil"
	"github.com/goodtune/ghp/internal/gitcred"
	"github.com/goodtune/ghp/internal/securestore"
)

// Environment variables read by `ghp auth git-credential`. A flag given on
// the command line beats its variable, which beats the default.
const (
	envGitCMApp          = "GHP_GIT_CM_APP"
	envGitCMType         = "GHP_GIT_CM_TYPE"
	envGitCMScopes       = "GHP_GIT_CM_SCOPES"
	envGitCMTTL          = "GHP_GIT_CM_TTL"
	envGitCMCacheBackend = "GHP_GIT_CM_CACHE_BACKEND"
)

// msgDotvaultLoginRequired replaces dvclient.ErrLoginRequired: the helper
// runs under git with no terminal, so it never logs in itself.
const msgDotvaultLoginRequired = "dotvault login required: run `ghp auth status` in a terminal to log in"

// gitCredentialProtectors returns the key protectors the helper's cache may
// use. Tests swap in a file-only set.
var gitCredentialProtectors = securestore.Default

func newAuthGitCredentialCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "git-credential <operation>",
		Short: "Git credential helper that mints ghp tokens per repository",
		Long: `Git credential helper that mints a short-lived ghp token for the repository
git is talking to, and keeps it in an encrypted local cache until it expires.

git runs this command itself; configure it with 'ghp auth setup-git'.

Operations:
  get     answer a credential request from git on stdin
  store   accepted and ignored (the helper is the source of truth)
  erase   drop the cached token for the requested repository
  status  show the cache tier, path and entries (never the tokens)
  clear   remove every cached entry and revoke its token (best effort)

Unknown operations exit 0 with no output, as git requires.

Flags beat environment variables, which beat the defaults:
  --app            GHP_GIT_CM_APP            GitHub App name or record ID (server default app)
  --type           GHP_GIT_CM_TYPE           token type: agent or proxy (agent)
  --scopes         GHP_GIT_CM_SCOPES         requested scopes (contents:write)
  --ttl            GHP_GIT_CM_TTL            token lifetime (1h)
  --cache-backend  GHP_GIT_CM_CACHE_BACKEND  auto, none, tpm, dpapi, keychain or file (auto)
  --host                                     host to serve; repeatable (github.com)

A GHP_GIT_CM_APP value is ignored when --type proxy is given as a flag.
Every failure is one stderr line prefixed "ghp git-credential: ".`,
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := gitCredentialOptions(cmd)
			code := gitcred.Run(cmd.Context(), opts, args[0], cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
			if code != 0 {
				return &exitCodeError{code: code}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.String("app", "", "GitHub App name or record ID (env "+envGitCMApp+"; default: the server's default app)")
	f.String("type", gitcred.DefaultType, "token type: agent or proxy (env "+envGitCMType+")")
	f.String("scopes", gitcred.DefaultScopes, "requested token scopes (env "+envGitCMScopes+")")
	f.String("ttl", gitcred.DefaultTTL, "token lifetime (env "+envGitCMTTL+")")
	f.String("cache-backend", gitcred.BackendAuto, "cache tier: auto, none, tpm, dpapi, keychain or file (env "+envGitCMCacheBackend+")")
	f.StringArray("host", []string{gitcred.DefaultHost}, "host this helper serves; repeat for several")
	return cmd
}

// gitCredentialOptions builds the helper options from cmd's flags and the
// GHP_GIT_CM_* environment.
func gitCredentialOptions(cmd *cobra.Command) gitcred.Options {
	flags := cmd.Flags()
	// setting returns the flag value when the flag was given, else the
	// environment variable when non-empty, else the flag default.
	setting := func(name, env string) string {
		v, _ := flags.GetString(name)
		if flags.Changed(name) {
			return v
		}
		if e := os.Getenv(env); e != "" {
			return e
		}
		return v
	}
	hosts, _ := flags.GetStringArray("host")
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	return gitcred.Options{
		Settings: gitcred.Settings{
			Type:           setting("type", envGitCMType),
			App:            setting("app", envGitCMApp),
			Scopes:         setting("scopes", envGitCMScopes),
			TTL:            setting("ttl", envGitCMTTL),
			ScopesExplicit: flags.Changed("scopes") || os.Getenv(envGitCMScopes) != "",
			AppFromEnv:     !flags.Changed("app") && os.Getenv(envGitCMApp) != "",
			TypeFromFlag:   flags.Changed("type"),
		},
		Hosts:        hosts,
		CacheBackend: setting("cache-backend", envGitCMCacheBackend),
		CacheDir:     gitCredentialCacheDir(),
		Hostname:     hostname,
		LoadStatic:   gitCredentialLoadStatic,
		LoadAuthed:   gitCredentialLoadAuthed,
		Protectors:   gitCredentialProtectors(),
	}
}

// gitCredentialCacheDir is the helper's cache directory beside the per-user
// CLI config, or "" when the home directory cannot be resolved.
func gitCredentialCacheDir() string {
	p := userCLIConfigPath()
	if p == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(p), "git-credential")
}

// gitCredentialLoadStatic is phase A: config files and environment only.
// Its warnings are returned for the helper to print with its prefix.
func gitCredentialLoadStatic() (gitcred.Config, error) {
	var buf bytes.Buffer
	cfg, err := loadCLIConfigWith(&buf)
	var warnings []string
	for _, line := range strings.Split(buf.String(), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			warnings = append(warnings, line)
		}
	}
	if err != nil {
		return gitcred.Config{Warnings: warnings}, err
	}
	return gitcred.Config{ServerURL: cfg.ServerURL, UserToken: cfg.UserToken, Warnings: warnings}, nil
}

// gitCredentialLoadAuthed is phase B: phase A plus dotvault, using only a
// cached dotvault token. Phase A has already reported the file warnings.
func gitCredentialLoadAuthed(ctx context.Context) (gitcred.Config, error) {
	cfg, err := loadCLIConfigCached(ctx, io.Discard)
	if errors.Is(err, dvclient.ErrLoginRequired) {
		return gitcred.Config{}, errors.New(msgDotvaultLoginRequired)
	}
	if err != nil {
		return gitcred.Config{}, err
	}
	return gitcred.Config{ServerURL: cfg.ServerURL, UserToken: cfg.UserToken}, nil
}

// osExecutable reports the running binary's path. Tests swap it.
var osExecutable = os.Executable

// runGit runs git with args. git's stderr is captured into the error.
var runGit = func(ctx context.Context, args ...string) error {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

// shellSafeWord matches the words shellQuote leaves unquoted.
var shellSafeWord = regexp.MustCompile(`^[A-Za-z0-9@%+=:,./_-]+$`)

// setupGitHost matches a host name with an optional port.
var setupGitHost = regexp.MustCompile(`^[A-Za-z0-9.-]+(:[0-9]+)?$`)

// shellQuote returns s as one POSIX shell word: unchanged when it holds only
// characters that are never special to the shell, else single-quoted.
func shellQuote(s string) string {
	if shellSafeWord.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// gitCredentialHelperLine is the credential.helper value that runs
// `ghp auth git-credential` for host. git runs a value starting with "!"
// through the shell, so every word is quoted, and a value holding a line
// break or NUL (which could end the gitconfig line) is refused.
func gitCredentialHelperLine(ghp, host, app, tokenType string) (string, error) {
	for _, field := range []struct{ name, value string }{
		{"ghp executable path", ghp},
		{"host", host},
		{"app", app},
	} {
		if strings.ContainsAny(field.value, "\n\r\x00") {
			return "", fmt.Errorf("%s contains a newline, carriage return or NUL", field.name)
		}
	}
	words := []string{shellQuote(ghp), "auth", "git-credential"}
	if !asciiutil.EqualFold(host, gitcred.DefaultHost) {
		words = append(words, "--host", shellQuote(host))
	}
	if app != "" {
		words = append(words, "--app", shellQuote(app))
	}
	if tokenType == gitcred.TypeProxy {
		words = append(words, "--type", gitcred.TypeProxy)
	}
	return "!" + strings.Join(words, " "), nil
}

// ghpCommand is how the helper line names ghp: bare "ghp" when that
// resolves on PATH to the running binary, else the running binary's path.
func ghpCommand() (string, error) {
	exe, err := osExecutable()
	if err != nil {
		return "", fmt.Errorf("locating the ghp executable: %w", err)
	}
	onPath, err := exec.LookPath("ghp")
	if err != nil {
		return exe, nil
	}
	resolvedPath, err := filepath.EvalSymlinks(onPath)
	if err != nil {
		return exe, nil
	}
	resolvedExe, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return exe, nil
	}
	if resolvedPath == resolvedExe {
		return "ghp", nil
	}
	return exe, nil
}

func newAuthSetupGitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup-git",
		Short: "Configure git to use ghp as its credential helper",
		Long: `Configure git to use 'ghp auth git-credential' as the credential helper for
each host, in the global git config (~/.gitconfig).

For every host this runs:
  git config --global --replace-all credential.https://HOST.helper ""
  git config --global --add credential.https://HOST.helper "!ghp auth git-credential ..."
  git config --global credential.https://HOST.useHttpPath true

The empty helper value stops git from asking any helper configured before
it, so any previous helper for these hosts (for example gh) is replaced.
useHttpPath gives the helper the repository path, so it can mint a token
scoped to that repository.`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			hosts, _ := cmd.Flags().GetStringArray("host")
			app, _ := cmd.Flags().GetString("app")
			tokenType, _ := cmd.Flags().GetString("type")
			return setupGit(cmd, hosts, app, tokenType)
		},
	}
	f := cmd.Flags()
	f.StringArray("host", []string{gitcred.DefaultHost}, "host to configure; repeat for several")
	f.String("app", "", "GitHub App name or record ID for the helper (default: the server's default app)")
	f.String("type", gitcred.DefaultType, "token type for the helper: agent or proxy")
	return cmd
}

// setupGit validates every input and builds every helper line before it
// changes any git config, so a bad value leaves the config untouched.
func setupGit(cmd *cobra.Command, hosts []string, app, tokenType string) error {
	if tokenType != gitcred.TypeAgent && tokenType != gitcred.TypeProxy {
		return fmt.Errorf("invalid --type %q: must be agent or proxy", tokenType)
	}
	if app != "" && tokenType == gitcred.TypeProxy {
		return errors.New("--app is only valid with --type agent")
	}
	ghp, err := ghpCommand()
	if err != nil {
		return err
	}
	lines := make([]string, len(hosts))
	for i, host := range hosts {
		if !setupGitHost.MatchString(host) {
			return fmt.Errorf("invalid --host %q: want a host name with an optional :port", host)
		}
		if lines[i], err = gitCredentialHelperLine(ghp, host, app, tokenType); err != nil {
			return err
		}
	}

	ctx := cmd.Context()
	out := cmd.OutOrStdout()
	for i, host := range hosts {
		section := "credential.https://" + host
		steps := [][]string{
			{"config", "--global", "--replace-all", section + ".helper", ""},
			{"config", "--global", "--add", section + ".helper", lines[i]},
			{"config", "--global", section + ".useHttpPath", "true"},
		}
		for _, step := range steps {
			if err := runGit(ctx, step...); err != nil {
				return err
			}
		}
		fmt.Fprintf(out, "Configured https://%s:\n  %s.helper = %s\n  %s.useHttpPath = true\n", host, section, lines[i], section)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "warning: replaced any existing credential helper for %s (for example gh)\n", strings.Join(hosts, ", "))
	return nil
}
