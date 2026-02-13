package main

import (
	"context"
	"fmt"
	"os"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/database"
	"github.com/spf13/cobra"
)

func newMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Run database migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath, _ := cmd.Flags().GetString("config")
			if cfgPath == "" {
				cfgPath = os.Getenv("GHP_CONFIG")
			}

			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}

			store, err := database.Open(cfg.Database.Driver, cfg.Database.DSN)
			if err != nil {
				return fmt.Errorf("opening database: %w", err)
			}
			defer store.Close()

			migrator := database.NewMigrator(store, cfg.Database.Driver)

			ctx := context.Background()

			// Ensure migration tracking table exists.
			executor, ok := store.(database.MigrationExecutor)
			if !ok {
				return fmt.Errorf("store does not support migrations")
			}
			if err := executor.EnsureMigrationsTable(ctx); err != nil {
				return fmt.Errorf("ensuring migrations table: %w", err)
			}

			if err := migrator.Migrate(ctx); err != nil {
				return fmt.Errorf("running migrations: %w", err)
			}

			fmt.Println("Migrations complete.")
			return nil
		},
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Check migration status",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath, _ := cmd.Flags().GetString("config")
			if cfgPath == "" {
				cfgPath = os.Getenv("GHP_CONFIG")
			}

			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}

			store, err := database.Open(cfg.Database.Driver, cfg.Database.DSN)
			if err != nil {
				return fmt.Errorf("opening database: %w", err)
			}
			defer store.Close()

			migrator := database.NewMigrator(store, cfg.Database.Driver)

			ctx := context.Background()
			statuses, err := migrator.Status(ctx)
			if err != nil {
				return fmt.Errorf("checking migration status: %w", err)
			}

			for _, s := range statuses {
				status := "pending"
				if s.Applied {
					status = "applied"
				}
				fmt.Printf("%-40s %s\n", s.Name, status)
			}

			if len(statuses) == 0 {
				fmt.Println("No migrations found.")
			}

			return nil
		},
	})

	return cmd
}
