// Package sqlitedb opens the agent's embedded SQLite databases using the
// pure-Go modernc.org/sqlite driver, so agent builds stay CGO-free.
package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// Open opens or creates a WAL-mode database at path. cacheKiB bounds the page
// cache to respect the agent memory ceiling. A single connection is used so
// writers never contend for the database lock.
func Open(ctx context.Context, path string, cacheKiB int) (*sql.DB, error) {
	pragmas := []string{
		"auto_vacuum(INCREMENTAL)", // only effective on a new database; must precede WAL
		"journal_mode(WAL)",
		"synchronous(NORMAL)",
		"busy_timeout(5000)",
		fmt.Sprintf("cache_size(-%d)", cacheKiB),
		"journal_size_limit(8388608)",
		"temp_store(MEMORY)",
	}
	dsn := path + "?_pragma=" + strings.Join(pragmas, "&_pragma=")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return db, nil
}
