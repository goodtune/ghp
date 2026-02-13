package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/server"
	"github.com/spf13/cobra"
)

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the server (proxy + web UI + API)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath, _ := cmd.Flags().GetString("config")
			if cfgPath == "" {
				cfgPath = os.Getenv("GHP_CONFIG")
			}

			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}

			logger := newLogger(cfg)
			logger.Info("server_start", "msg", "starting ghp server")

			srv := server.New(cfg, logger)
			return srv.Run(context.Background())
		},
	}
}

func newLogger(cfg *config.Config) *slog.Logger {
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

	switch cfg.Logging.Output {
	case "file":
		if cfg.Logging.File.Path != "" {
			f, err := os.OpenFile(cfg.Logging.File.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				// Fall back to stdout.
				return slog.New(slog.NewJSONHandler(os.Stdout, opts))
			}
			return slog.New(slog.NewJSONHandler(f, opts))
		}
	}

	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}
