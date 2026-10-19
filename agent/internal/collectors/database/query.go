package database

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	// Pure-Go drivers: the agent must stay a single static binary with no
	// libpq or ODBC dependency, so a hardened host with no client library can
	// still run the watcher.
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/microsoft/go-mssqldb"
)

// DefaultRowLimit bounds a table snapshot. A configuration table has tens of
// rows; a limit of 500 is generous for that and still small enough that a
// watcher accidentally pointed at an audit log cannot pull a production
// database across the network every 30 seconds.
const DefaultRowLimit = 500

// DefaultQueryTimeout bounds one statement, so a lock or a slow catalog query
// cannot stall the whole poll cycle.
const DefaultQueryTimeout = 20 * time.Second

// DB is the subset of *sql.DB this package needs. It exists so the renderers
// and the collector can be tested against a fixture without a live server.
type DB interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// Open builds a database handle for a connection.
func Open(engine, dsn string) (*sql.DB, error) {
	switch engine {
	case EnginePostgres:
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			return nil, fmt.Errorf("database: open postgres: %w", err)
		}
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		db.SetConnMaxLifetime(time.Hour)
		return db, nil
	case EngineSQLServer:
		db, err := sql.Open("sqlserver", dsn)
		if err != nil {
			return nil, fmt.Errorf("database: open sqlserver: %w", err)
		}
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		db.SetConnMaxLifetime(time.Hour)
		return db, nil
	}
	return nil, fmt.Errorf("database: unsupported engine %q", engine)
}

// ReadTable reads one table's rows in primary-key order.
//
// The column set and the ordering key come from the catalog rather than from
// configuration, because a config table's key is a property of the schema: an
// operator naming `public.app_settings` should not also have to name `key` as
// the sort column, and getting that wrong would make the document churn on
// every poll.
func ReadTable(ctx context.Context, db DB, engine, database, schema, table string, limit int) (TableSnapshot, error) {
	if limit <= 0 {
		limit = DefaultRowLimit
	}
	snap := TableSnapshot{Engine: engine, Database: database, Schema: schema, Table: table}

	cols, keys, err := tableColumns(ctx, db, engine, schema, table)
	if err != nil {
		return snap, err
	}
	if len(cols) == 0 {
		return snap, fmt.Errorf("database: table %s.%s has no readable columns", schema, table)
	}
	snap.Columns = cols
	snap.KeyColumns = keys

	selectList := make([]string, 0, len(cols))
	for _, c := range cols {
		selectList = append(selectList, QuoteIdent(engine, c))
	}
	order := make([]string, 0, len(keys))
	for _, k := range keys {
		order = append(order, QuoteIdent(engine, k))
	}
	if len(order) == 0 {
		// No primary key: order by the whole column set so the document is
		// still deterministic, which is what keeps an unchanged table quiet.
		order = selectList
	}

	q := fmt.Sprintf("SELECT %s FROM %s.%s ORDER BY %s",
		strings.Join(selectList, ", "),
		QuoteIdent(engine, schema), QuoteIdent(engine, table),
		strings.Join(order, ", "))
	if engine == EngineSQLServer {
		q = fmt.Sprintf("SELECT TOP (%d) %s FROM %s.%s ORDER BY %s",
			limit+1,
			strings.Join(selectList, ", "),
			QuoteIdent(engine, schema), QuoteIdent(engine, table),
			strings.Join(order, ", "))
	} else {
		q += fmt.Sprintf(" LIMIT %d", limit+1)
	}
	if err := onlySelect(q); err != nil {
		return snap, err
	}

	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return snap, fmt.Errorf("database: read %s.%s: %w", schema, table, err)
	}
	defer rows.Close()

	for rows.Next() {
		raw := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return snap, fmt.Errorf("database: scan %s.%s: %w", schema, table, err)
		}
		if len(snap.Rows) >= limit {
			// The extra row exists, so the result is a window, not the table.
			snap.Truncated = true
			break
		}
		vals := make([]string, len(cols))
		for i, v := range raw {
			vals[i] = formatValue(v)
		}
		snap.Rows = append(snap.Rows, TableRow{Values: vals})
	}
	if err := rows.Err(); err != nil {
		return snap, fmt.Errorf("database: iterate %s.%s: %w", schema, table, err)
	}
	return snap, nil
}

// tableColumns reads a table's columns in ordinal order and its primary key.
func tableColumns(ctx context.Context, db DB, engine, schema, table string) ([]string, []string, error) {
	var q string
	var args []any
	switch engine {
	case EnginePostgres:
		q = `SELECT column_name FROM information_schema.columns
		     WHERE table_schema = $1 AND table_name = $2
		     ORDER BY ordinal_position`
		args = []any{schema, table}
	case EngineSQLServer:
		q = `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
		     WHERE TABLE_SCHEMA = @p1 AND TABLE_NAME = @p2
		     ORDER BY ORDINAL_POSITION`
		args = []any{schema, table}
	default:
		return nil, nil, fmt.Errorf("database: unsupported engine %q", engine)
	}
	if err := onlySelect(q); err != nil {
		return nil, nil, err
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("database: read columns of %s.%s: %w", schema, table, err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, nil, err
		}
		cols = append(cols, c)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	keys, err := primaryKey(ctx, db, engine, schema, table)
	if err != nil {
		// A missing key is not fatal: the caller falls back to ordering by the
		// whole row. Returning the columns is more useful than failing the poll.
		return cols, nil, nil
	}
	return cols, keys, nil
}

// primaryKey reads the primary-key columns in key order.
func primaryKey(ctx context.Context, db DB, engine, schema, table string) ([]string, error) {
	var q string
	var args []any
	switch engine {
	case EnginePostgres:
		q = `SELECT a.attname
		     FROM pg_index i
		     JOIN pg_class c ON c.oid = i.indrelid
		     JOIN pg_namespace n ON n.oid = c.relnamespace
		     JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord) ON TRUE
		     JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
		     WHERE i.indisprimary AND n.nspname = $1 AND c.relname = $2
		     ORDER BY k.ord`
		args = []any{schema, table}
	case EngineSQLServer:
		q = `SELECT c.name
		     FROM sys.indexes i
		     JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
		     JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
		     JOIN sys.tables t ON t.object_id = i.object_id
		     JOIN sys.schemas s ON s.schema_id = t.schema_id
		     WHERE i.is_primary_key = 1 AND s.name = @p1 AND t.name = @p2
		     ORDER BY ic.key_ordinal`
		args = []any{schema, table}
	default:
		return nil, fmt.Errorf("database: unsupported engine %q", engine)
	}
	if err := onlySelect(q); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// ReadSchema reads the table/column inventory and the privilege grants.
func ReadSchema(ctx context.Context, db DB, engine, database string) (SchemaSnapshot, error) {
	snap := SchemaSnapshot{Engine: engine, Database: database}

	cols, err := readColumns(ctx, db, engine)
	if err != nil {
		return snap, err
	}
	byTable := map[string]*SchemaTable{}
	var order []string
	for _, c := range cols {
		key := c.Schema + "." + c.Name
		t, ok := byTable[key]
		if !ok {
			t = &SchemaTable{Schema: c.Schema, Name: c.Name}
			byTable[key] = t
			order = append(order, key)
		}
		t.Columns = append(t.Columns, SchemaColumn{
			Name: c.Column, Type: c.Type, Nullable: c.Nullable, Default: c.Default,
		})
	}
	sort.Strings(order)
	for _, k := range order {
		snap.Tables = append(snap.Tables, *byTable[k])
	}

	grants, err := readGrants(ctx, db, engine)
	if err != nil {
		// A login with no visibility into the privilege catalog is a normal
		// least-privilege deployment. Losing grants must not lose the column
		// inventory, which is the half that catches ALTER TABLE.
		grants = nil
	}
	snap.Grants = grants
	return snap, nil
}

type columnRow struct {
	Schema, Name, Column, Type, Default string
	Nullable                            bool
}

func readColumns(ctx context.Context, db DB, engine string) ([]columnRow, error) {
	var q string
	switch engine {
	case EnginePostgres:
		q = `SELECT table_schema, table_name, column_name, data_type,
		            is_nullable = 'YES', COALESCE(column_default, '')
		     FROM information_schema.columns
		     WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
		     ORDER BY table_schema, table_name, ordinal_position`
	case EngineSQLServer:
		q = `SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE,
		            CASE WHEN IS_NULLABLE = 'YES' THEN 1 ELSE 0 END,
		            COALESCE(COLUMN_DEFAULT, '')
		     FROM INFORMATION_SCHEMA.COLUMNS
		     ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION`
	default:
		return nil, fmt.Errorf("database: unsupported engine %q", engine)
	}
	if err := onlySelect(q); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("database: read columns: %w", err)
	}
	defer rows.Close()
	var out []columnRow
	for rows.Next() {
		var c columnRow
		var nullable any
		if err := rows.Scan(&c.Schema, &c.Name, &c.Column, &c.Type, &nullable, &c.Default); err != nil {
			return nil, err
		}
		c.Nullable = truthy(nullable)
		out = append(out, c)
	}
	return out, rows.Err()
}

func readGrants(ctx context.Context, db DB, engine string) ([]Grant, error) {
	var q string
	switch engine {
	case EnginePostgres:
		q = `SELECT grantee, privilege_type, table_schema, table_name, is_grantable = 'YES'
		     FROM information_schema.role_table_grants
		     WHERE grantee NOT IN ('PUBLIC') 
		     ORDER BY grantee, table_schema, table_name, privilege_type`
	case EngineSQLServer:
		q = `SELECT grantee_principal.name, permission_name, 'OBJECT',
		            COALESCE(OBJECT_SCHEMA_NAME(major_id), '') + '.' + COALESCE(OBJECT_NAME(major_id), ''),
		            state
		     FROM sys.database_permissions p
		     JOIN sys.database_principals grantee_principal
		       ON grantee_principal.principal_id = p.grantee_principal_id
		     WHERE p.class = 1
		     ORDER BY grantee_principal.name, permission_name`
	default:
		return nil, fmt.Errorf("database: unsupported engine %q", engine)
	}
	if err := onlySelect(q); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("database: read grants: %w", err)
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		var object, flag any
		if err := rows.Scan(&g.Role, &g.Privilege, &object, &g.Object, &flag); err != nil {
			return nil, err
		}
		g.ObjectType = formatValue(object)
		g.Grantable = truthy(flag) || formatValue(flag) == "W"
		out = append(out, g)
	}
	return out, rows.Err()
}

// ReadParams reads the server's non-default runtime parameters.
func ReadParams(ctx context.Context, db DB, engine, database string) (ParamsSnapshot, error) {
	snap := ParamsSnapshot{Engine: engine, Database: database}
	var q string
	switch engine {
	case EnginePostgres:
		// source <> 'default' is what makes this "what an operator changed":
		// every default setting would otherwise appear and the document would
		// carry hundreds of rows nobody touched.
		q = `SELECT name, setting, COALESCE(unit, ''), source
		     FROM pg_settings
		     WHERE source <> 'default'
		     ORDER BY name`
	case EngineSQLServer:
		q = `SELECT name, CAST(value AS NVARCHAR(256)),
		            CAST(value_in_use AS NVARCHAR(256)), CAST(description AS NVARCHAR(400))
		     FROM sys.configurations
		     ORDER BY name`
	default:
		return snap, fmt.Errorf("database: unsupported engine %q", engine)
	}
	if err := onlySelect(q); err != nil {
		return snap, err
	}
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return snap, fmt.Errorf("database: read server parameters: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var p Param
		if engine == EngineSQLServer {
			var inUse string
			if err := rows.Scan(&p.Name, &p.Value, &inUse, &p.Unit); err != nil {
				return snap, err
			}
			// value is the configured value; value_in_use is what a restart
			// has applied. Reporting both is what distinguishes "someone ran
			// sp_configure" from "the change is live".
			p.Source = "configured"
			if inUse != p.Value {
				p.Source = "pending_restart"
			}
			p.Unit = "description"
			p.Value = p.Value + " (in use: " + inUse + ")"
		} else {
			if err := rows.Scan(&p.Name, &p.Value, &p.Unit, &p.Source); err != nil {
				return snap, err
			}
		}
		snap.Params = append(snap.Params, p)
	}
	return snap, rows.Err()
}

// Attribute resolves who last touched the database.
//
// PostgreSQL exposes its sessions in pg_stat_activity: the application name is
// the tool (psql, pgAdmin), the client address is where it came from and the
// user is the database role. SQL Server has no equivalent "recent write"
// view that a read-only login can use, so it falls back to sys.dm_exec_sessions
// with the same three fields. An empty result means "unknown", which the
// collector reports as no actor rather than guessing.
func Attribute(ctx context.Context, db DB, engine string) (user, client, ip string) {
	var q string
	switch engine {
	case EnginePostgres:
		q = `SELECT usename, COALESCE(application_name, ''), COALESCE(host(client_addr), '')
		     FROM pg_stat_activity
		     WHERE pid <> pg_backend_pid() AND state <> 'idle' AND usename IS NOT NULL
		     ORDER BY query_start DESC NULLS LAST
		     LIMIT 1`
	case EngineSQLServer:
		q = `SELECT TOP (1) login_name, COALESCE(program_name, ''), COALESCE(client_net_address, '')
		     FROM sys.dm_exec_sessions
		     WHERE is_user_process = 1 AND session_id <> @@SPID
		     ORDER BY last_request_end_time DESC`
	default:
		return "", "", ""
	}
	if err := onlySelect(q); err != nil {
		return "", "", ""
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return "", "", ""
	}
	defer rows.Close()
	if rows.Next() {
		var u, c, h sql.NullString
		if err := rows.Scan(&u, &c, &h); err == nil {
			return u.String, c.String, h.String
		}
	}
	return "", "", ""
}

// formatValue renders a scanned value deterministically.
//
// database/sql returns []byte for most string types on both drivers, and
// time.Time for timestamps. Rendering them explicitly is what keeps the
// document byte-identical across polls: fmt.Sprint on a []byte would print a
// slice of byte values.
func formatValue(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []byte:
		return string(t)
	case time.Time:
		return t.UTC().Format(time.RFC3339Nano)
	case bool:
		return strconv.FormatBool(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case int32:
		return strconv.FormatInt(int64(t), 10)
	case int:
		return strconv.Itoa(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(t), 'f', -1, 32)
	default:
		return fmt.Sprint(v)
	}
}

// truthy normalises the several shapes a boolean arrives in (bool from
// SQL Server's BIT, int64 from a CASE expression, the strings 'YES'/'1').
func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case int64:
		return t != 0
	case int32:
		return t != 0
	case []byte:
		return truthy(string(t))
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		return s == "1" || s == "t" || s == "true" || s == "yes" || s == "y"
	}
	return false
}
