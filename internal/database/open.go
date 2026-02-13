package database

import "fmt"

// Open creates a Store for the given driver and DSN.
func Open(driver, dsn string) (Store, error) {
	switch driver {
	case "sqlite":
		return NewSQLiteStore(dsn)
	case "postgres":
		return nil, fmt.Errorf("postgres driver not yet implemented — use sqlite for development")
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", driver)
	}
}
