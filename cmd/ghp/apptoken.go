package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/github"
	"github.com/spf13/cobra"
)

func newAppTokenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "apptoken [installation-name]",
		Short: "Generate a GitHub App installation access token",
		Long: `Generate a GitHub App installation access token directly from the CLI.

Uses the configured App ID and private key to authenticate with GitHub
and issue an open-scoped installation token. Useful for local development,
CI scripts, or any context where you need a raw GitHub token.

If installation-name is omitted and only one installation exists, it is
used automatically. If multiple installations exist, they are listed and
the command exits with an error.

The token is printed to stdout for easy piping:

  export GH_TOKEN=$(ghp apptoken myorg)`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath, _ := cmd.Flags().GetString("config")
			if cfgPath == "" {
				cfgPath = os.Getenv("GHP_CONFIG")
			}

			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}

			if cfg.GitHub.AppID == 0 {
				return fmt.Errorf("github.app_id is not configured")
			}

			// Resolve private key: inline value or file fallback.
			privateKey := cfg.GitHub.PrivateKey
			if privateKey == "" && cfg.GitHub.PrivateKeyFile != "" {
				keyData, err := os.ReadFile(cfg.GitHub.PrivateKeyFile)
				if err != nil {
					return fmt.Errorf("reading GitHub App private key file: %w", err)
				}
				privateKey = string(keyData)
			}
			if privateKey == "" {
				return fmt.Errorf("github.private_key or github.private_key_file must be configured")
			}

			provider, err := github.NewAppTokenProvider(github.AppConfig{
				AppID:      cfg.GitHub.AppID,
				PrivateKey: privateKey,
				BaseURL:    cfg.GitHub.BaseURL,
			})
			if err != nil {
				return fmt.Errorf("initializing GitHub App token provider: %w", err)
			}

			ctx := context.Background()

			installations, err := provider.ListInstallations(ctx)
			if err != nil {
				return fmt.Errorf("listing installations: %w", err)
			}
			if len(installations) == 0 {
				return fmt.Errorf("no installations found for this GitHub App")
			}

			var installation github.Installation

			if len(args) == 1 {
				name := args[0]
				for _, inst := range installations {
					if strings.EqualFold(inst.Account.Login, name) {
						installation = inst
						break
					}
				}
				if installation.ID == 0 {
					fmt.Fprintf(cmd.ErrOrStderr(), "Installation %q not found. Available installations:\n", name)
					for _, inst := range installations {
						fmt.Fprintf(cmd.ErrOrStderr(), "  - %s\n", inst.Account.Login)
					}
					return fmt.Errorf("installation %q not found", name)
				}
			} else {
				if len(installations) > 1 {
					fmt.Fprintln(cmd.ErrOrStderr(), "Multiple installations found. Please specify one:")
					for _, inst := range installations {
						fmt.Fprintf(cmd.ErrOrStderr(), "  - %s\n", inst.Account.Login)
					}
					return fmt.Errorf("multiple installations found; specify an installation name")
				}
				installation = installations[0]
			}

			token, err := provider.GetInstallationToken(ctx, installation.ID, nil, nil)
			if err != nil {
				return fmt.Errorf("generating installation token: %w", err)
			}

			fmt.Fprint(cmd.OutOrStdout(), token)
			return nil
		},
	}
}
