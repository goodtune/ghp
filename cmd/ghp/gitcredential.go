package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	dvclient "github.com/goodtune/dotvault/client"
	"github.com/spf13/cobra"

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
