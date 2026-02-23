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

			logger, logWriter := newLogger(cfg)

			migrate, _ := cmd.Flags().GetBool("migrate")
			if migrate {
				logger.Info("running database migrations before startup")
				if err := runMigrations(cfg); err != nil {
					return fmt.Errorf("pre-startup migration: %w", err)
				}
				logger.Info("database migrations complete")
			}

			logger.Info("server_start", "msg", "starting ghp server")

			srv := server.New(cfg, logger, logWriter)
			return srv.Run(context.Background())
		},
	}

	cmd.Flags().Bool("migrate", false, "Run database migrations before starting the server")

	return cmd
}

func newLogger(cfg *config.Config) (*slog.Logger, io.Writer) {
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
	if cfg.Logging.Output == "file" && cfg.Logging.File.Path != "" {
		f, err := os.OpenFile(cfg.Logging.File.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			w = f
		}
	}

	return slog.New(slog.NewJSONHandler(w, opts)), w
}
