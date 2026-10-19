// Package migrations embeds the ordered SQL schema migrations and applies them
// on server boot.
//
// Embedding rather than reading a directory is what makes the release binary
// (and therefore the container image) self-contained: `docker run` against an
// empty Postgres needs no volume mount, no init container and no `make migrate`
// step. The files are also still plain .sql on disk, so the Makefile and
// scripts/dev.ps1 can apply them by hand for development.
package migrations

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed *.sql
var files embed.FS

// LockKey is the advisory lock held for the duration of the migration run so
// two replicas starting at once cannot race on the same DDL.
const LockKey int64 = 0x5354_4D49_4752 // "STMIGR"

// File is one migration, identified by its filename without the .sql suffix.
type File struct {
	Version string
	Name    string
	SQL     string
}

// Files returns the embedded migrations in apply order. Filenames are the
// ordering key, which is why they are zero-padded (`001_`, `002_`, ...).
func Files() ([]File, error) {
	entries, err := fs.Glob(files, "*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(entries)
	out := make([]File, 0, len(entries))
	for _, name := range entries {
		body, err := files.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", name, err)
		}
		out = append(out, File{
			Version: strings.TrimSuffix(name, ".sql"),
			Name:    name,
			SQL:     trimBOM(string(body)),
		})
	}
	return out, nil
}

// trimBOM removes a leading UTF-8 byte-order mark.
//
// Postgres rejects a BOM at the start of a statement ("syntax error at or near
// \ufeff"), so one migration saved by an editor that adds a BOM — Notepad and
// Visual Studio both do — makes the server exit on first boot against an empty
// database. That failure is total and the message does not name the file, so the
// loader normalizes instead of trusting every editor in the chain.
func trimBOM(sql string) string {
	return strings.TrimPrefix(sql, "\ufeff")
}

// Apply runs every migration not yet recorded in schema_migrations.
//
// Each file and its bookkeeping row are committed in one transaction, so a
// failed migration leaves neither a half-applied schema nor a row claiming it
// was applied. Re-running is a no-op: the version table is the source of truth,
// not the presence of a table.
func Apply(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	migrations, err := Files()
	if err != nil {
		return err
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()

	// Session-level lock: held until the connection is released, which covers
	// the whole run including the transactions below.
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, LockKey); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		if _, err := conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, LockKey); err != nil {
			logger.Warn("release migration lock", "err", err)
		}
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied := map[string]bool{}
	rows, err := conn.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("read applied migrations: %w", err)
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return fmt.Errorf("scan applied migration: %w", err)
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read applied migrations: %w", err)
	}

	for _, m := range migrations {
		if applied[m.Version] {
			continue
		}
		if err := applyOne(ctx, conn, m); err != nil {
			return fmt.Errorf("migration %s: %w", m.Name, err)
		}
		logger.Info("migration applied", "version", m.Version)
	}
	return nil
}

func applyOne(ctx context.Context, conn *pgxpool.Conn, m File) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// The migration body and its bookkeeping row travel together. Simple
	// protocol (no parameters) is required: these files contain multiple
	// statements.
	if _, err := tx.Exec(ctx, m.SQL); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, m.Version); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Pending reports the migrations that would be applied, for a dry-run log line.
func Pending(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	migrations, err := Files()
	if err != nil {
		return nil, err
	}
	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT to_regclass('public.schema_migrations') IS NOT NULL`).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		// The first-boot state: nothing has ever been applied.
		return versions(migrations), nil
	}
	rows, err := pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	applied := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []string
	for _, m := range migrations {
		if !applied[m.Version] {
			out = append(out, m.Version)
		}
	}
	return out, nil
}

func versions(ms []File) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Version)
	}
	return out
}
