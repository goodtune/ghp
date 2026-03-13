package database

import "fmt"

// Open creates a Store for the given driver and DSN.
// For SQL backends, the DSN is the connection string.
// For Vault, use OpenVault instead.
func Open(driver, dsn string) (Store, error) {
	switch driver {
	case "sqlite":
		return NewSQLiteStore(dsn)
	case "postgres":
		return NewPostgresStore(dsn)
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", driver)
	}
}

// OpenVault creates a VaultStore with the given configuration.
func OpenVault(cfg VaultConfig) (Store, error) {
	return NewVaultStore(cfg)
}
