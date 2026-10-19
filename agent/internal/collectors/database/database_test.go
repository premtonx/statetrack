package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/statetrack/statetrack/agent/internal/engine"
)

// ---------------------------------------------------------------------------
// Canonical serialization
// ---------------------------------------------------------------------------

func TestRenderTableScrubsSecretsAndIsStable(t *testing.T) {
	snap := TableSnapshot{
		Engine:   EnginePostgres,
		Database: "settings_db",
		Schema:   "public",
		Table:    "app_settings",
		Columns:  []string{"key", "value", "updated_by"},
		KeyColumns: []string{
			"key",
		},
		Rows: []TableRow{
			{Values: []string{"payment_gateway.verify_tls", "true", "dba_sarah"}},
			{Values: []string{"stripe_webhook_secret", "whsec_live_9f3a1c8e", "dba_sarah"}},
		},
	}
	scrub := &Scrubber{
		Stub: func(string) string { return "[REDACTED:sha256:9f3a1c8e]" },
		Line: func(v string) string { return v },
	}
	first := RenderTable(snap, scrub)
	second := RenderTable(snap, scrub)

	if len(first) == 0 {
		t.Fatal("RenderTable returned nothing")
	}
	if string(first) != string(second) {
		t.Fatal("render is not deterministic; an unchanged table would emit events every poll")
	}
	if strings.Contains(string(first), "whsec_live_9f3a1c8e") {
		t.Fatalf("cleartext secret reached the document:\n%s", first)
	}
	if !strings.Contains(string(first), "[REDACTED:sha256:9f3a1c8e]") {
		t.Errorf("scrubbed marker missing:\n%s", first)
	}
	if !strings.Contains(string(first), "payment_gateway.verify_tls") {
		t.Errorf("non-secret row lost:\n%s", first)
	}

	var doc struct {
		Kind       string           `yaml:"kind"`
		Table      string           `yaml:"table"`
		KeyColumns []string         `yaml:"key_columns"`
		Rows       []map[string]any `yaml:"rows"`
	}
	if err := yaml.Unmarshal(first, &doc); err != nil {
		t.Fatalf("rendered table is not valid YAML: %v\n%s", err, first)
	}
	if doc.Kind != "database_table" || doc.Table != "app_settings" {
		t.Errorf("header = %+v", doc)
	}
	if len(doc.Rows) != 2 || len(doc.KeyColumns) != 1 {
		t.Errorf("rows/key columns = %d/%d", len(doc.Rows), len(doc.KeyColumns))
	}
	// Column order is preserved: a map-shaped row would not be, and the diff
	// would churn.
	if !strings.Contains(string(first), "key: payment_gateway.verify_tls") {
		t.Errorf("row not rendered as a labelled mapping:\n%s", first)
	}
}

func TestRenderTableFallsBackToFixedStubWithoutScrubber(t *testing.T) {
	snap := TableSnapshot{
		Engine: EnginePostgres, Database: "settings_db", Schema: "public", Table: "app_settings",
		Columns: []string{"key", "api_key"},
		Rows:    []TableRow{{Values: []string{"stripe", "sk_live_abc123"}}},
	}
	doc := RenderTable(snap, nil)
	if strings.Contains(string(doc), "sk_live_abc123") {
		t.Fatalf("secret rendered without a scrubber:\n%s", doc)
	}
	if !strings.Contains(string(doc), stubValue) {
		t.Errorf("fixed stub missing:\n%s", doc)
	}
}

func TestRenderTableScrubsSecretsNamedByRowKey(t *testing.T) {
	// The most common shape of a config table: the credential is the row whose
	// key says so, not the column. This is the case a column-only check misses.
	snap := TableSnapshot{
		Engine: EnginePostgres, Database: "settings_db", Schema: "public", Table: "app_settings",
		Columns: []string{"key", "value"},
		Rows: []TableRow{
			{Values: []string{"payment_gateway.verify_tls", "true"}},
			{Values: []string{"stripe_webhook_secret", "whsec_live_9f3a1c8e"}},
			{Values: []string{"support_email", "ops@example.com"}},
		},
	}
	doc := RenderTable(snap, nil)
	if strings.Contains(string(doc), "whsec_live_9f3a1c8e") {
		t.Fatalf("secret named by its row key reached the document:\n%s", doc)
	}
	// The key itself stays readable, so a reviewer sees *which* credential
	// rotated; only the value is stubbed.
	if !strings.Contains(string(doc), "stripe_webhook_secret") {
		t.Errorf("row key was redacted too:\n%s", doc)
	}
	if !strings.Contains(string(doc), `"true"`) || !strings.Contains(string(doc), "ops@example.com") {
		t.Errorf("non-secret rows lost:\n%s", doc)
	}
}

func TestRenderTableScrubsEmbeddedCredentialsInFreeText(t *testing.T) {
	// A non-secret column can still hold a credential: a JSON blob or a DSN.
	snap := TableSnapshot{
		Engine: EnginePostgres, Database: "settings_db", Schema: "public", Table: "app_settings",
		Columns: []string{"key", "value"},
		Rows:    []TableRow{{Values: []string{"billing_dsn", "postgres://svc:hunter2@db:5432/billing"}}},
	}
	scrub := &Scrubber{Line: func(v string) string {
		return strings.ReplaceAll(v, "hunter2", "[REDACTED:sha256:aaaa1111]")
	}}
	doc := RenderTable(snap, scrub)
	if strings.Contains(string(doc), "hunter2") {
		t.Fatalf("embedded credential reached the document:\n%s", doc)
	}
}

func TestIsSecretColumn(t *testing.T) {
	secret := []string{"password", "db_password", "api_key", "stripe_webhook_secret", "access_token",
		"connection_string", "private_key", "DSN"}
	plain := []string{"key", "value", "updated_by", "created_at", "enabled"}
	for _, c := range secret {
		if !isSecretColumn(c) {
			t.Errorf("isSecretColumn(%q) = false, want true", c)
		}
	}
	for _, c := range plain {
		if isSecretColumn(c) {
			t.Errorf("isSecretColumn(%q) = true, want false", c)
		}
	}
}

func TestRenderSchemaAndParamsAreSorted(t *testing.T) {
	schema := SchemaSnapshot{
		Engine: EnginePostgres, Database: "settings_db",
		Tables: []SchemaTable{
			{Schema: "public", Name: "z_table", Columns: []SchemaColumn{{Name: "b"}, {Name: "a"}}},
			{Schema: "public", Name: "a_table"},
		},
		Grants: []Grant{
			{Role: "bob", Privilege: "SELECT", ObjectType: "TABLE", Object: "public.app_settings"},
			{Role: "alice", Privilege: "SELECT", ObjectType: "TABLE", Object: "public.app_settings"},
		},
	}
	doc := RenderSchema(schema)
	aIdx, zIdx := strings.Index(string(doc), "name: a_table"), strings.Index(string(doc), "name: z_table")
	if aIdx < 0 || zIdx < 0 || aIdx > zIdx {
		t.Errorf("tables not sorted:\n%s", doc)
	}
	if strings.Index(string(doc), "role: alice") > strings.Index(string(doc), "role: bob") {
		t.Errorf("grants not sorted:\n%s", doc)
	}
	if again := RenderSchema(schema); string(again) != string(doc) {
		t.Error("schema render is not deterministic")
	}

	params := ParamsSnapshot{
		Engine: EnginePostgres, Database: "settings_db",
		Params: []Param{{Name: "work_mem", Value: "8MB"}, {Name: "log_min_duration_statement", Value: "500"}},
	}
	pdoc := RenderParams(params)
	if strings.Index(string(pdoc), "log_min_duration_statement") > strings.Index(string(pdoc), "work_mem") {
		t.Errorf("parameters not sorted:\n%s", pdoc)
	}
}

func TestTruncateCellKeepsTheOriginalLengthVisible(t *testing.T) {
	got := truncateCell(strings.Repeat("a", 5000), 16)
	if !strings.HasPrefix(got, "aaaaaaaaaaaaaaaa") || !strings.Contains(got, "truncated") {
		t.Errorf("truncateCell = %q", got)
	}
}

// ---------------------------------------------------------------------------
// Read-only guarantee and path parsing
// ---------------------------------------------------------------------------

func TestOnlySelectRejectsWrites(t *testing.T) {
	ok := []string{
		"SELECT 1",
		"  select * from t",
		"WITH x AS (SELECT 1) SELECT * FROM x",
		"SELECT 1;",
	}
	for _, q := range ok {
		if err := onlySelect(q); err != nil {
			t.Errorf("onlySelect(%q) = %v, want nil", q, err)
		}
	}
	bad := []string{
		"UPDATE app_settings SET value = 'false'",
		"DELETE FROM app_settings",
		"INSERT INTO t VALUES (1)",
		"ALTER SYSTEM SET work_mem = '1GB'",
		"SELECT 1; DROP TABLE app_settings",
		"",
	}
	for _, q := range bad {
		if err := onlySelect(q); err == nil {
			t.Errorf("onlySelect(%q) = nil, want a refusal", q)
		}
	}
}

func TestParseTargetForms(t *testing.T) {
	cases := []struct {
		in        string
		ok        bool
		kind      string
		path      string
		targetTyp string
	}{
		{"db://postgres/settings_db/tables/public.app_settings", true, KindTables,
			"db://postgres/settings_db/tables/public.app_settings", TargetTable},
		{"db://postgresql/settings_db/public.app_settings", true, KindTables,
			"db://postgres/settings_db/tables/public.app_settings", TargetTable},
		{"db://sqlserver/Inventory/dbo.SystemSettings", true, KindTables,
			"db://sqlserver/Inventory/tables/dbo.SystemSettings", TargetTable},
		{"db://postgres/settings_db/schema", true, KindSchema,
			"db://postgres/settings_db/schema", TargetSchema},
		{"db://postgres/settings_db/server_params", true, KindParams,
			"db://postgres/settings_db/server_params", TargetParams},
		{"db://postgres/settings_db", false, "", "", ""},
		{"db://oracle/x/tables/a.b", false, "", "", ""},
		{"/etc/passwd", false, "", "", ""},
	}
	for _, c := range cases {
		got, ok := ParseTarget(c.in)
		if ok != c.ok {
			t.Errorf("ParseTarget(%q) ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if got.Kind != c.kind || got.Path != c.path || got.TargetType() != c.targetTyp {
			t.Errorf("ParseTarget(%q) = %+v", c.in, got)
		}
	}
}

func TestDatabaseFromDSN(t *testing.T) {
	cases := map[string]string{
		"postgres://svc:pw@db.internal:5432/settings_db?sslmode=require": "settings_db",
		"server=db;database=settings_db;user id=svc;password=pw":         "settings_db",
		"server=db;Initial Catalog=Inventory;user id=svc":                "Inventory",
		"postgres://db.internal:5432":                                    "",
	}
	for dsn, want := range cases {
		if got := databaseFromDSN(dsn); got != want {
			t.Errorf("databaseFromDSN(%q) = %q, want %q", dsn, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Collector against an in-memory driver
//
// The collector's job is not to be a database client; it is to seed a baseline,
// detect a changed row and hand the rendered document to the engine. A fixture
// driver is enough to prove that, and it keeps the test hermetic: a CI runner
// has no PostgreSQL, and a test that needed one would be skipped exactly where
// it matters.
// ---------------------------------------------------------------------------

type fixtureDriver struct{ db *fixtureDB }

func (d *fixtureDriver) Open(string) (driver.Conn, error) { return &fixtureConn{db: d.db}, nil }

type fixtureConn struct{ db *fixtureDB }

func (c *fixtureConn) Prepare(query string) (driver.Stmt, error) {
	return &fixtureStmt{db: c.db, query: query}, nil
}
func (c *fixtureConn) Close() error              { return nil }
func (c *fixtureConn) Begin() (driver.Tx, error) { return nil, fmt.Errorf("read-only fixture") }

// QueryContext is what makes the driver usable without a Prepare round trip.
func (c *fixtureConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.db.mu.Lock()
	c.db.queries = append(c.db.queries, query)
	c.db.mu.Unlock()
	return c.db.rowsFor(query)
}

type fixtureStmt struct {
	db    *fixtureDB
	query string
}

func (s *fixtureStmt) Close() error  { return nil }
func (s *fixtureStmt) NumInput() int { return -1 }
func (s *fixtureStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, fmt.Errorf("read-only fixture")
}
func (s *fixtureStmt) Query([]driver.Value) (driver.Rows, error) { return s.db.rowsFor(s.query) }

type fixtureRows struct {
	cols []string
	data [][]driver.Value
	pos  int
}

func (r *fixtureRows) Columns() []string { return r.cols }
func (r *fixtureRows) Close() error      { return nil }
func (r *fixtureRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.data) {
		return io.EOF
	}
	copy(dest, r.data[r.pos])
	r.pos++
	return nil
}

type fixtureDB struct {
	mu      sync.Mutex
	queries []string
	// settingsRows is the app_settings table's current content.
	settingsRows [][]driver.Value
}

func (f *fixtureDB) rowsFor(query string) (driver.Rows, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case strings.Contains(query, "information_schema.columns"):
		return &fixtureRows{
			cols: []string{"column_name"},
			data: [][]driver.Value{{"key"}, {"value"}, {"updated_by"}},
		}, nil
	case strings.Contains(query, "pg_index"):
		return &fixtureRows{cols: []string{"attname"}, data: [][]driver.Value{{"key"}}}, nil
	case strings.Contains(query, "FROM \"public\".\"app_settings\""):
		if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(query)), "SELECT") {
			return nil, fmt.Errorf("non-read query issued: %s", query)
		}
		return &fixtureRows{cols: []string{"key", "value", "updated_by"}, data: f.settingsRows}, nil
	case strings.Contains(query, "pg_stat_activity"):
		return &fixtureRows{cols: []string{"usename", "application_name", "client_addr"},
			data: [][]driver.Value{{"dba_sarah", "psql", "10.0.14.22"}}}, nil
	}
	return nil, fmt.Errorf("unexpected query: %s", query)
}

// snapshot reports every statement the collector issued, for the read-only
// assertion.
func (f *fixtureDB) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

func (f *fixtureDB) setRows(rows [][]driver.Value) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.settingsRows = rows
}

func TestCollectorWatchesSettingsDBTable(t *testing.T) {
	fixture := &fixtureDB{settingsRows: [][]driver.Value{
		{"payment_gateway.verify_tls", "true", "dba_sarah"},
		{"stripe_webhook_secret", "whsec_live_9f3a1c8e", "dba_sarah"},
	}}
	sql.Register("statetrack-fixture", &fixtureDriver{db: fixture})
	handle, err := sql.Open("statetrack-fixture", "fixture")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer handle.Close()

	var (
		mu      sync.Mutex
		seeded  = map[string]string{}
		handled []engine.DocEvent
	)
	col := New(Options{
		Connections: []Connection{{
			Name:     "settings",
			Engine:   EnginePostgres,
			DSN:      "postgres://svc@db:5432/settings_db",
			Database: "settings_db",
			Tables:   []string{"public.app_settings"},
		}},
		Interval: time.Hour,
		Scrub: &Scrubber{
			Stub: func(string) string { return "[REDACTED:sha256:9f3a1c8e]" },
			Line: func(v string) string { return v },
		},
		Handle: func(_ context.Context, de engine.DocEvent) error {
			mu.Lock()
			defer mu.Unlock()
			handled = append(handled, de)
			return nil
		},
		Seed: func(_ context.Context, path, _ string, content []byte, _ time.Time) error {
			mu.Lock()
			defer mu.Unlock()
			seeded[path] = string(content)
			return nil
		},
		Known: func(_ context.Context, path string) bool {
			mu.Lock()
			defer mu.Unlock()
			_, ok := seeded[path]
			return ok
		},
		Attribute: func(context.Context, DB, string) (string, string, string) {
			return "dba_sarah", "psql", "10.0.14.22"
		},
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})

	conn := col.o.Connections[0]
	col.poll(context.Background(), handle, conn, "settings_db", col.log)

	path := "db://postgres/settings_db/tables/public.app_settings"
	base, ok := seeded[path]
	if !ok {
		t.Fatalf("table baseline not seeded; seeded=%v", seeded)
	}
	if !strings.Contains(base, "payment_gateway.verify_tls") {
		t.Errorf("baseline missing the row:\n%s", base)
	}
	if strings.Contains(base, "whsec_live_9f3a1c8e") {
		t.Fatalf("cleartext secret in the baseline:\n%s", base)
	}
	if len(handled) != 0 {
		t.Fatalf("baseline emitted %d events", len(handled))
	}

	// The operator flips verify_tls and rotates the secret.
	fixture.setRows([][]driver.Value{
		{"payment_gateway.verify_tls", "false", "dba_sarah"},
		{"stripe_webhook_secret", "whsec_live_4b7d2e10", "dba_sarah"},
	})
	col.poll(context.Background(), handle, conn, "settings_db", col.log)

	if len(handled) != 1 {
		t.Fatalf("events = %d, want one table change", len(handled))
	}
	de := handled[0]
	if de.Path != path || de.TargetType != TargetTable {
		t.Fatalf("event = %s/%s", de.TargetType, de.Path)
	}
	if !strings.Contains(string(de.Content), `verify_tls`) {
		t.Errorf("event content missing the changed row:\n%s", de.Content)
	}
	if strings.Contains(string(de.Content), "whsec_live_4b7d2e10") {
		t.Fatalf("cleartext secret in the emitted document:\n%s", de.Content)
	}
	if de.Actor.GetUsername() != "dba_sarah" || de.Actor.GetProcessName() != "psql" ||
		de.Actor.GetRemoteIp() != "10.0.14.22" {
		t.Errorf("actor attribution lost: %+v", de.Actor)
	}

	for _, q := range fixture.snapshot() {
		if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(q)), "SELECT") &&
			!strings.HasPrefix(strings.ToUpper(strings.TrimSpace(q)), "WITH") {
			t.Errorf("collector issued a non-read statement: %s", q)
		}
	}
}

func TestSurfacesMergesConsoleTargets(t *testing.T) {
	var mu sync.Mutex
	dynamic := []string(nil)
	col := New(Options{
		Targets: []string{
			"db://postgres/settings_db/tables/public.feature_flags",
			"db://postgres/other_db/tables/public.app_settings", // no DSN: skipped
			"db://postgres/settings_db/server_params",
		},
		DynamicTargets: func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), dynamic...)
		},
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	conn := Connection{Engine: EnginePostgres, Database: "settings_db", Tables: []string{"public.app_settings"}}
	tables, schema, params := col.surfaces(conn, "settings_db")

	if len(tables) != 2 {
		t.Fatalf("tables = %+v, want the configured and the console-added one", tables)
	}
	if tables[0].Table != "app_settings" || tables[1].Table != "feature_flags" {
		t.Errorf("tables not sorted: %+v", tables)
	}
	if schema || !params {
		t.Errorf("schema/params = %v/%v", schema, params)
	}

	// A rule created after the collector started must be picked up on the next
	// poll, and a glob must be ignored because a table cannot be enumerated.
	mu.Lock()
	dynamic = []string{
		"db://postgres/settings_db/tables/public.tenant_config",
		"db://postgres/settings_db/tables/public.audit_*",
	}
	mu.Unlock()

	tables, _, _ = col.surfaces(conn, "settings_db")
	if len(tables) != 3 {
		t.Fatalf("tables = %+v, want the newly watched one and no glob expansion", tables)
	}
	found := false
	for _, tbl := range tables {
		if tbl.Table == "tenant_config" {
			found = true
		}
		if strings.Contains(tbl.Table, "*") {
			t.Errorf("glob pattern became a table name: %+v", tbl)
		}
	}
	if !found {
		t.Error("console-pushed table was not picked up")
	}
}
