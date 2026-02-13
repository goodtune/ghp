package database

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed migrations/postgres/*.sql
var postgresMigrations embed.FS

//go:embed migrations/sqlite/*.sql
var sqliteMigrations embed.FS

// MigrationStatus describes a migration's state.
type MigrationStatus struct {
	Name    string
	Applied bool
}

// Migrator runs database migrations.
type Migrator struct {
	db     Store
	driver string
}

// NewMigrator creates a new Migrator.
func NewMigrator(db Store, driver string) *Migrator {
	return &Migrator{db: db, driver: driver}
}

func (m *Migrator) migrations() (embed.FS, string) {
	if m.driver == "postgres" {
		return postgresMigrations, "migrations/postgres"
	}
	return sqliteMigrations, "migrations/sqlite"
}

// PendingMigrations returns the list of migrations not yet applied.
func (m *Migrator) PendingMigrations(ctx context.Context) ([]string, error) {
	migFS, dir := m.migrations()

	entries, err := fs.ReadDir(migFS, dir)
	if err != nil {
		return nil, fmt.Errorf("reading migrations dir: %w", err)
	}

	var upFiles []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			upFiles = append(upFiles, e.Name())
		}
	}
	sort.Strings(upFiles)

	executor, ok := m.db.(MigrationExecutor)
	if !ok {
		return nil, fmt.Errorf("store does not support migrations")
	}

	applied, err := executor.AppliedMigrations(ctx)
	if err != nil {
		return nil, err
	}

	appliedSet := make(map[string]bool, len(applied))
	for _, name := range applied {
		appliedSet[name] = true
	}

	var pending []string
	for _, f := range upFiles {
		name := strings.TrimSuffix(f, ".up.sql")
		if !appliedSet[name] {
			pending = append(pending, name)
		}
	}
	return pending, nil
}

// Migrate runs all pending up migrations.
func (m *Migrator) Migrate(ctx context.Context) error {
	executor, ok := m.db.(MigrationExecutor)
	if !ok {
		return fmt.Errorf("store does not support migrations")
	}

	if err := executor.EnsureMigrationsTable(ctx); err != nil {
		return fmt.Errorf("ensuring migrations table: %w", err)
	}

	pending, err := m.PendingMigrations(ctx)
	if err != nil {
		return err
	}

	migFS, dir := m.migrations()

	for _, name := range pending {
		filename := name + ".up.sql"
		data, err := fs.ReadFile(migFS, dir+"/"+filename)
		if err != nil {
			return fmt.Errorf("reading migration %s: %w", filename, err)
		}

		if err := executor.RunMigration(ctx, name, string(data)); err != nil {
			return fmt.Errorf("running migration %s: %w", name, err)
		}
	}

	return nil
}

// Status returns the status of all known migrations.
func (m *Migrator) Status(ctx context.Context) ([]MigrationStatus, error) {
	executor, ok := m.db.(MigrationExecutor)
	if !ok {
		return nil, fmt.Errorf("store does not support migrations")
	}

	if err := executor.EnsureMigrationsTable(ctx); err != nil {
		return nil, fmt.Errorf("ensuring migrations table: %w", err)
	}

	migFS, dir := m.migrations()
	entries, err := fs.ReadDir(migFS, dir)
	if err != nil {
		return nil, fmt.Errorf("reading migrations dir: %w", err)
	}

	var upFiles []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			upFiles = append(upFiles, e.Name())
		}
	}
	sort.Strings(upFiles)

	applied, err := executor.AppliedMigrations(ctx)
	if err != nil {
		return nil, err
	}

	appliedSet := make(map[string]bool, len(applied))
	for _, name := range applied {
		appliedSet[name] = true
	}

	var statuses []MigrationStatus
	for _, f := range upFiles {
		name := strings.TrimSuffix(f, ".up.sql")
		statuses = append(statuses, MigrationStatus{
			Name:    name,
			Applied: appliedSet[name],
		})
	}
	return statuses, nil
}

// MigrationExecutor is implemented by stores that can run migrations.
type MigrationExecutor interface {
	EnsureMigrationsTable(ctx context.Context) error
	AppliedMigrations(ctx context.Context) ([]string, error)
	RunMigration(ctx context.Context, name, sql string) error
}
