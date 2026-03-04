package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/goodtune/ghp/internal/config"
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

			logger, logWriter, cleanupLogger := newLogger(cfg)
			defer cleanupLogger()

			migrate, _ := cmd.Flags().GetBool("migrate")

			logger.Info("server_start", "msg", "starting ghp server", "version", version)

			srv := server.New(cfg, cfgPath, version, logger, logWriter, migrate)
			return srv.Run(context.Background())
		},
	}

	cmd.Flags().Bool("migrate", false, "Run pending database migrations before starting the server")

	return cmd
}

func newLogger(cfg *config.Config) (*slog.Logger, io.Writer, func()) {
	var level slog.Level
	switch cfg.Logging.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}

	var w io.Writer = os.Stdout
	cleanup := func() {}
	if cfg.Logging.Output == "file" && cfg.Logging.File.Path != "" {
		f, err := os.OpenFile(cfg.Logging.File.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			w = f
			cleanup = func() { f.Close() }
		} else {
			fmt.Fprintf(os.Stderr, "warning: failed to open log file %q: %v; falling back to stdout\n", cfg.Logging.File.Path, err)
		}
	}

	return slog.New(slog.NewJSONHandler(w, opts)), w, cleanup
}
