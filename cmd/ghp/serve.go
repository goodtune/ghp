package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/observability"
	"github.com/goodtune/ghp/internal/server"
	"github.com/spf13/cobra"
)

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the HTTP server (proxy + web UI + API)",
		Long: `Start the GHP server which runs the GitHub API reverse proxy,
management web UI, and REST API.

Use --migrate to automatically apply any pending database schema
migrations before the server begins accepting connections. This is
the recommended mode for packaged deployments where the binary may
be upgraded between restarts.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath, _ := cmd.Flags().GetString("config")
			if cfgPath == "" {
				cfgPath = os.Getenv("GHP_CONFIG")
			}

			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}

			logging, cleanupLogger, err := observability.Setup(context.Background(), cfg, version)
			if err != nil {
				return err
			}
			defer cleanupLogger()

			// Make the configured logger the global slog default so background
			// goroutines in internal packages (e.g. token.StartCleanup,
			// gitcache.StartCleanup) that use bare slog.Info/Error calls route
			// through the same OTel LoggerProvider as the rest of the server.
			logger := logging.Logger
			slog.SetDefault(logger)

			migrate, _ := cmd.Flags().GetBool("migrate")

			logger.Info("server_start", "msg", "starting ghp server", "version", version)

			srv := server.New(cfg, cfgPath, version, logger, logging.Provider, migrate)
			return srv.Run(context.Background())
		},
	}

	cmd.Flags().Bool("migrate", false, "Run pending database migrations before starting the server")

	return cmd
}
