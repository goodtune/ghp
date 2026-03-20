package database

import (
	"context"
	"fmt"
)

// Open creates a Store for the given driver and DSN.
// For SQL backends, the DSN is the connection string.
// For Vault, use OpenVault instead.
func Open(driver, dsn string) (Store, error) {
	switch driver {
	case "sqlite":
		return NewSQLiteStore(dsn)
	case "postgres":
		return NewPostgresStore(dsn)
	case "vault":
		return nil, fmt.Errorf("vault backend does not use DSN-based connections or SQL migrations; configure it via the vault section in your config file (see docs)")
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", driver)
	}
}

// OpenVault creates a VaultStore with the given configuration.
func OpenVault(ctx context.Context, cfg VaultConfig) (Store, error) {
	return NewVaultStore(ctx, cfg)
}
