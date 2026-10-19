// Package database watches a handful of database surfaces that behave like
// configuration: chosen tables, schema/privilege DDL and live server
// parameters. Each surface is rendered as a canonical YAML document and handed
// to the same shadow store, diff engine and classifier as a file on disk.
//
// Three properties define the collector:
//
//   - It is read-only. Every statement is a constant that starts with SELECT,
//     checked by onlySelect before it is issued, and the PostgreSQL session is
//     pinned to a read-only transaction. The documented least-privilege
//     deployment grants a read-only login; the code does not need write access
//     and never asks for it.
//
//   - Credentials never leave the host. A cell in a secret-bearing column is
//     replaced with the salted stub from pkg/redact, and the whole rendered
//     document is passed through the line scrubber before it is hashed, so a
//     connection string hidden in an ordinary column is caught too.
//
//   - Scope is explicit. A connection in agent.yaml names a database; the
//     console's watched-target rules name the exact table paths
//     (db://postgres/settings_db/tables/public.app_settings). Nothing is
//     discovered by scanning a database, so an agent pointed at production only
//     ever queries what an operator named.
package database

import (
	"fmt"
	"strings"
)

// Document path prefixes and target types.
//
// The path shape is URI-like rather than filesystem-like so a rule authored in
// the console reads as the thing the operator named, and so the classifier's
// `db://**` critical pattern covers every surface of a database.
const (
	Scheme = "db://"

	// TargetTable is one configured table's rows.
	TargetTable = "database_table"
	// TargetSchema is the database's table/column/privilege snapshot.
	TargetSchema = "database_schema"
	// TargetParams is the server's non-default runtime parameters.
	TargetParams = "database_params"

	// TargetFamily is the prefix a single console rule can use to cover all
	// three surfaces (limiter.ruleTypeMatches treats "database" as covering
	// "database_table", "database_schema" and "database_params").
	TargetFamily = "database"
)

// Engines accepted in a connection and in a document path.
const (
	EnginePostgres  = "postgres"
	EngineSQLServer = "sqlserver"
)

// Surface kinds that can appear in a tracked path.
const (
	KindTables = "tables"
	KindSchema = "schema"
	KindParams = "server_params"
)

// ParseTarget decodes a tracked path into its parts.
//
// Accepted forms:
//
//	db://postgres/settings_db/tables/public.app_settings
//	db://postgres/settings_db/tables/app_settings        (default schema)
//	db://sqlserver/Inventory/dbo.SystemSettings
//	db://postgres/settings_db/schema
//	db://postgres/settings_db/server_params
func ParseTarget(path string) (Target, bool) {
	raw := strings.TrimSpace(path)
	if len(raw) < len(Scheme) || !strings.EqualFold(raw[:len(Scheme)], Scheme) {
		return Target{}, false
	}
	parts := splitPath(raw[len(Scheme):])
	if len(parts) < 2 {
		return Target{}, false
	}
	engine, ok := NormalizeEngine(parts[0])
	if !ok {
		return Target{}, false
	}
	db := parts[1]
	if db == "" {
		return Target{}, false
	}
	t := Target{Engine: engine, Database: db}

	rest := parts[2:]
	if len(rest) == 0 {
		// A bare db://<engine>/<db> addresses the whole database, which this
		// collector does not watch: a whole-database dump is neither bounded
		// nor reviewable. It is rejected rather than silently expanded.
		return Target{}, false
	}

	switch strings.ToLower(rest[0]) {
	case KindSchema:
		if len(rest) != 1 {
			return Target{}, false
		}
		t.Kind = KindSchema
		t.Path = SchemaPath(engine, db)
		return t, true
	case KindParams:
		if len(rest) != 1 {
			return Target{}, false
		}
		t.Kind = KindParams
		t.Path = ParamsPath(engine, db)
		return t, true
	case KindTables:
		if len(rest) != 2 {
			return Target{}, false
		}
		schema, table := splitTable(rest[1], DefaultSchema(engine))
		if table == "" {
			return Target{}, false
		}
		t.Kind = KindTables
		t.Schema, t.Table = schema, table
		t.Path = TablePath(engine, db, schema, table)
		return t, true
	}

	// A two-part table name is accepted without the "tables/" segment because
	// that is how an operator writes it ("dbo.SystemSettings"); the console
	// always emits the full form.
	if len(rest) == 1 {
		schema, table := splitTable(rest[0], DefaultSchema(engine))
		if table == "" {
			return Target{}, false
		}
		t.Kind = KindTables
		t.Schema, t.Table = schema, table
		t.Path = TablePath(engine, db, schema, table)
		return t, true
	}
	return Target{}, false
}

// Target is one decoded tracked path.
type Target struct {
	Engine   string
	Database string
	// Kind is one of "tables", "schema", "server_params".
	Kind string
	// Schema/Table are set for a table target only.
	Schema string
	Table  string
	// Path is the canonical tracked path (the decoded form, not the input).
	Path string
}

// TargetType maps the surface kind to the value reported on events and matched
// by a granular policy rule.
func (t Target) TargetType() string {
	switch t.Kind {
	case KindSchema:
		return TargetSchema
	case KindParams:
		return TargetParams
	}
	return TargetTable
}

// String renders the target for a log line.
func (t Target) String() string {
	if t.Kind == KindTables {
		return t.Schema + "." + t.Table
	}
	return t.Kind
}

// NormalizeEngine canonicalises an engine name.
func NormalizeEngine(v string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "postgres", "postgresql", "pg", "pgsql":
		return EnginePostgres, true
	case "sqlserver", "mssql", "sql-server", "sql_server", "microsoft-sql-server":
		return EngineSQLServer, true
	}
	return "", false
}

// DefaultSchema is the schema an unqualified table name resolves to.
func DefaultSchema(engine string) string {
	if engine == EngineSQLServer {
		return "dbo"
	}
	return "public"
}

// TablePath renders the tracked path for one table.
func TablePath(engine, db, schema, table string) string {
	if eng, ok := NormalizeEngine(engine); ok {
		engine = eng
	}
	return Scheme + engine + "/" + db + "/" + KindTables + "/" + schema + "." + table
}

// SchemaPath renders the tracked path for a database's schema/privilege DDL.
func SchemaPath(engine, db string) string {
	if eng, ok := NormalizeEngine(engine); ok {
		engine = eng
	}
	return Scheme + engine + "/" + db + "/" + KindSchema
}

// ParamsPath renders the tracked path for a database's server parameters.
func ParamsPath(engine, db string) string {
	if eng, ok := NormalizeEngine(engine); ok {
		engine = eng
	}
	return Scheme + engine + "/" + db + "/" + KindParams
}

// IsTablePath reports whether p addresses one table.
func IsTablePath(p string) bool {
	t, ok := ParseTarget(p)
	return ok && t.Kind == KindTables
}

// splitTable splits "schema.table" / "[schema].[table]" / "table".
func splitTable(v, defSchema string) (schema, table string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", ""
	}
	// Bracket-quoted SQL Server identifiers: [dbo].[SystemSettings].
	if strings.HasPrefix(v, "[") {
		var parts []string
		var cur strings.Builder
		in := false
		for _, r := range v {
			switch r {
			case '[':
				in = true
			case ']':
				in = false
			case '.':
				if in {
					cur.WriteRune(r)
				} else {
					parts = append(parts, cur.String())
					cur.Reset()
				}
			default:
				cur.WriteRune(r)
			}
		}
		parts = append(parts, cur.String())
		if len(parts) >= 2 {
			return strings.TrimSpace(parts[len(parts)-2]), strings.TrimSpace(parts[len(parts)-1])
		}
		return defSchema, strings.TrimSpace(parts[0])
	}
	if i := strings.LastIndexByte(v, '.'); i >= 0 {
		return strings.TrimSpace(v[:i]), strings.TrimSpace(v[i+1:])
	}
	return defSchema, v
}

// splitPath splits on '/' and drops empty segments.
func splitPath(v string) []string {
	var out []string
	for _, p := range strings.Split(v, "/") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// QuoteIdent quotes a SQL identifier for the engine.
//
// Identifiers come from configuration and from the database catalog, never from
// an event, but quoting is still what makes a table named "audit.events" or a
// schema named "my schema" work rather than silently query the wrong object.
func QuoteIdent(engine, ident string) string {
	switch engine {
	case EngineSQLServer:
		return "[" + strings.ReplaceAll(ident, "]", "]]") + "]"
	default:
		return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`
	}
}

// onlySelect rejects a statement that is not a read.
//
// Every query in this package is a constant SELECT, so this is a guard against
// a future edit rather than against untrusted input. It is deliberately
// conservative: a CTE (WITH) is allowed, and a trailing semicolon is stripped
// before the check so a statement cannot smuggle a second one.
func onlySelect(q string) error {
	trimmed := strings.TrimSpace(q)
	if i := strings.IndexByte(trimmed, ';'); i >= 0 {
		// One statement only: a semicolon anywhere but the very end is refused.
		if strings.TrimSpace(trimmed[i+1:]) != "" {
			return fmt.Errorf("database: refusing multi-statement query")
		}
		trimmed = strings.TrimSpace(trimmed[:i])
	}
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return fmt.Errorf("database: empty query")
	}
	switch strings.ToUpper(fields[0]) {
	case "SELECT", "WITH", "SHOW":
		return nil
	}
	return fmt.Errorf("database: refusing non-read statement %q", fields[0])
}

// maxDocumentBytes bounds one rendered document. A table row limit already
// bounds it, but a single cell can be arbitrarily large (a blob stored in a
// config table), and a document the shadow store has to diff should stay small.
const maxDocumentBytes = 1 << 20

// truncateCell shortens an oversized cell so one blob cannot make a document
// undiffable. The marker names the original length, so a reviewer sees what was
// elided rather than a silently shortened value.
func truncateCell(v string, limit int) string {
	if limit <= 0 {
		limit = 4096
	}
	if len(v) <= limit {
		return v
	}
	return v[:limit] + fmt.Sprintf("…[truncated %d bytes]", len(v)-limit)
}
