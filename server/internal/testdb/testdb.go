// Package testdb prepares the Postgres database the database-backed suites run
// against.
//
// # Why this exists
//
// Every DB test used to assume the schema was already there: it opened a pool,
// called DefaultOrg and inserted rows. That works on a developer machine where
// `make up migrate` has been run once, and it passed locally for exactly that
// reason. In CI the Postgres service container starts empty, so the first
// INSERT failed with `relation "organizations" does not exist` and the whole
// release job went red — the tests were green against a database that only
// existed on one laptop.
//
// Preparing here instead makes the suite self-sufficient: a bare, empty
// Postgres is the supported input, which is also the state a production first
// boot sees.
package testdb

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/statetrack/statetrack/server/migrations"
)

// EnvVar names the DSN every DB-backed suite reads. When unset those suites
// skip: a unit-test run on a laptop without Postgres must still pass.
const EnvVar = "STATETRACK_TEST_DATABASE_URL"

// DSN returns the test DSN, or "" when the suite should skip.
func DSN() string { return os.Getenv(EnvVar) }

var once struct {
	sync.Mutex
	done map[string]error
}

// Pool opens a pool against the test database and ensures the schema is
// applied. It calls t.Skip when no DSN is configured.
//
// Migrations run once per distinct DSN per test binary: `go test` builds one
// process per package, so four packages would otherwise race through nine
// migrations four times. The advisory lock inside migrations.Apply already
// makes concurrent runs safe, but the in-process guard keeps the log readable
// and the tests fast.
func Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := DSN()
	if dsn == "" {
		t.Skip(EnvVar + " not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := ensureSchema(ctx, dsn, pool); err != nil {
		t.Fatalf("prepare test schema: %v", err)
	}
	return pool
}

// ensureSchema applies the embedded migrations at most once per DSN.
func ensureSchema(ctx context.Context, dsn string, pool *pgxpool.Pool) error {
	once.Lock()
	defer once.Unlock()
	if once.done == nil {
		once.done = map[string]error{}
	}
	if err, ok := once.done[dsn]; ok {
		return err
	}

	// Apply is idempotent (schema_migrations is the source of truth), so a
	// developer database that is already current costs one SELECT and no DDL.
	// The logger is discarded: a migration line per test package is noise in an
	// otherwise assertion-only test log.
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := migrations.Apply(ctx, pool, quiet)
	if err != nil {
		err = fmt.Errorf("apply migrations: %w", err)
	}
	once.done[dsn] = err
	return err
}
