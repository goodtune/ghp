package main

import (
	"context"
	"fmt"
	"io"

	dvclient "github.com/goodtune/dotvault/client"
)

// dotvaultConfig is the optional `dotvault:` stanza of the CLI config. When
// present it lets the CLI source secrets (notably the session token) from
// HashiCorp Vault via the dotvault client, so they need not be written into
// ~/.config/ghp/config.yaml.
//
// dotvault itself owns connectivity (Vault address, CA, TLS), authentication,
// cached-token resolution, the KV mount, and the per-user path convention —
// all read from dotvault's own config file. This stanza only says *which*
// secret under the user root to read and which fields map onto the CLI config.
type dotvaultConfig struct {
	// Service is the path segment under the per-user root that holds the
	// secret: kv/users/<identity>/<service>. It may contain slashes for a
	// nested layout (e.g. "vendor/tool-name").
	Service string `yaml:"service"`

	// Config is an optional path to the dotvault client config file. When
	// empty, dotvault's platform default config path is used.
	Config string `yaml:"config"`

	// Fields maps CLI config keys to the dotvault secret field that supplies
	// them. Supported keys: "user_token" and "server_url". Example:
	//
	//	dotvault:
	//	  service: ghp
	//	  fields:
	//	    user_token: token
	Fields map[string]string `yaml:"fields"`
}

// dotvaultReader is the slice of the dotvault client the CLI depends on. It is
// an interface so resolution can be unit-tested with a fake — *dvclient.Client
// satisfies it.
type dotvaultReader interface {
	// Authenticate makes the client hold a usable Vault token, following
	// dotvault's precedence: DOTVAULT_TOKEN, the token file, a peer-socket
	// token borrow when enabled, and finally an interactive login. The
	// interactive fallback is appropriate for a CLI run by a human.
	Authenticate(ctx context.Context) error
	// AuthenticateCached is Authenticate without the interactive fallback:
	// it never prompts, and returns an error wrapping
	// dvclient.ErrLoginRequired when no cached token works. Background
	// callers such as the git credential helper use it.
	AuthenticateCached(ctx context.Context) error
	// ReadUserSecret reads kv/users/<identity>/<service> field <field>.
	ReadUserSecret(ctx context.Context, service, field string) (string, bool, error)
}

// newDotvaultReader builds a dotvault client from the config at configPath (or
// dotvault's platform default when empty). It is a package variable so tests
// can substitute a fake without a real dotvault config or a reachable Vault.
var newDotvaultReader = func(configPath string) (dotvaultReader, error) {
	if configPath == "" {
		configPath = dvclient.DefaultConfigPath()
	}
	cfg, err := dvclient.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("loading dotvault config %s: %w", configPath, err)
	}
	cli, err := dvclient.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating dotvault client: %w", err)
	}
	return cli, nil
}

// supportedDotvaultFields lists the CLI config keys that a dotvault field
// mapping may target.
var supportedDotvaultFields = map[string]bool{
	"user_token": true,
	"server_url": true,
}

// applyDotvault resolves CLI config fields from Vault via the dotvault client
// when a `dotvault:` stanza is configured. It is the highest-precedence
// source: every field it reads overrides the value from the config file and
// environment. A no-op when no stanza is configured.
//
// Resolution fails loudly: once an operator opts into dotvault, an
// authentication error or a missing field is surfaced rather than silently
// falling back to a (likely absent) file/env value.
func (cfg *cliConfig) applyDotvault(ctx context.Context) error {
	return cfg.resolveDotvault(ctx, dotvaultReader.Authenticate)
}

// applyDotvaultCached is applyDotvault for callers that must never prompt:
// the same validation and field mapping, authenticated with
// AuthenticateCached. When no cached token works the error wraps
// dvclient.ErrLoginRequired.
func (cfg *cliConfig) applyDotvaultCached(ctx context.Context) error {
	return cfg.resolveDotvault(ctx, dotvaultReader.AuthenticateCached)
}

// resolveDotvault is the shared body of applyDotvault and
// applyDotvaultCached; authenticate is the dotvaultReader method that makes
// the reader hold a Vault token.
func (cfg *cliConfig) resolveDotvault(ctx context.Context, authenticate func(dotvaultReader, context.Context) error) error {
	dv := cfg.Dotvault
	if dv == nil || (dv.Service == "" && len(dv.Fields) == 0) {
		return nil
	}
	if dv.Service == "" {
		return fmt.Errorf("dotvault: 'fields' is set but 'service' is empty")
	}
	if len(dv.Fields) == 0 {
		return fmt.Errorf("dotvault: 'service' is set but 'fields' is empty; nothing to read")
	}

	// Validate every mapping target before any network call so a typo fails
	// fast rather than after an interactive login.
	for key := range dv.Fields {
		if !supportedDotvaultFields[key] {
			return fmt.Errorf("dotvault: unknown field mapping %q (supported: server_url, user_token)", key)
		}
	}

	reader, err := newDotvaultReader(dv.Config)
	if err != nil {
		return err
	}
	if err := authenticate(reader, ctx); err != nil {
		return fmt.Errorf("dotvault authentication failed: %w", err)
	}

	for key, field := range dv.Fields {
		val, found, err := reader.ReadUserSecret(ctx, dv.Service, field)
		if err != nil {
			return fmt.Errorf("dotvault: reading %s/%s: %w", dv.Service, field, err)
		}
		if !found {
			return fmt.Errorf("dotvault: field %q not found at user secret %q", field, dv.Service)
		}
		switch key {
		case "user_token":
			cfg.UserToken = val
		case "server_url":
			cfg.ServerURL = val
		}
	}
	return nil
}

// loadCLIConfigAuthed loads the CLI config (file + env) and then resolves any
// dotvault-sourced fields. Commands that talk to the ghp server with the
// session token should use this rather than loadCLIConfig so the token can be
// supplied by dotvault. Commands that *set* the token (auth login, set-token)
// must not use it.
func loadCLIConfigAuthed(ctx context.Context) (*cliConfig, error) {
	cfg, err := loadCLIConfig()
	if err != nil {
		return nil, err
	}
	if err := cfg.applyDotvault(ctx); err != nil {
		return nil, err
	}
	return cfg, nil
}

// loadCLIConfigCached is loadCLIConfigAuthed for callers that must never
// prompt: warnings go to warn and dotvault uses only a cached token.
func loadCLIConfigCached(ctx context.Context, warn io.Writer) (*cliConfig, error) {
	cfg, err := loadCLIConfigWith(warn)
	if err != nil {
		return nil, err
	}
	if err := cfg.applyDotvaultCached(ctx); err != nil {
		return nil, err
	}
	return cfg, nil
}
