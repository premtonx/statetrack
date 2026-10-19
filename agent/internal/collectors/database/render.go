package database

import (
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// stubValue is the marker written in place of a secret when no scrubber is
// configured. A test or a dry run that has no salt still must not write a
// credential, so the fallback is a fixed stub rather than the raw value.
const stubValue = "[REDACTED]"

// maxCellBytes is how much of one oversized cell is rendered.
const maxCellBytes = 4096

// Scrubber is the edge redaction contract for a rendered document.
//
// Two functions are needed because the two cases are genuinely different. A
// cell in a secret-bearing column is *known* to be a credential, so it is
// hash-stubbed whole: Stub derives the salted marker directly from the value,
// which keeps a rotation visible as a changed line. A cell in an ordinary
// column is free text that may happen to contain a credential (a JSON blob, a
// DSN), so it is scrubbed as a line, which is the only form that can recognise
// `password=…` inside a larger string.
//
// A single callback cannot serve both: hash-stubbing every value would redact
// the whole document, and line-scrubbing a bare secret would leave it in place
// because there is no key to key off. That is why this is a struct rather than
// one function.
type Scrubber struct {
	// Stub returns the deterministic marker for one credential value.
	Stub func(string) string
	// Line scrubs credentials embedded in free text.
	Line func(string) string
}

// secret renders one known-credential value.
func (s *Scrubber) secret(v string) string {
	if v == "" {
		return ""
	}
	if s == nil || s.Stub == nil {
		return stubValue
	}
	return s.Stub(v)
}

// text renders one free-text value, catching an embedded credential.
func (s *Scrubber) text(v string) string {
	if v == "" {
		return ""
	}
	v = truncateCell(v, maxCellBytes)
	if s == nil || s.Line == nil {
		return v
	}
	return s.Line(v)
}

// TableSnapshot is one configured table's rows, already reduced to strings.
type TableSnapshot struct {
	Engine     string
	Database   string
	Schema     string
	Table      string
	Columns    []string
	KeyColumns []string
	// Rows holds one value per column, in Columns order.
	Rows []TableRow
	// Truncated records that the row limit cut the result, so a reviewer knows
	// the document is a window rather than the whole table.
	Truncated bool
}

// TableRow is one row's values, aligned with the snapshot's Columns.
type TableRow struct {
	Values []string
}

// SchemaSnapshot is a database's table/column and privilege DDL.
type SchemaSnapshot struct {
	Engine   string
	Database string
	Tables   []SchemaTable
	Grants   []Grant
}

// SchemaTable is one table's column inventory.
type SchemaTable struct {
	Schema  string
	Name    string
	Columns []SchemaColumn
}

// SchemaColumn is one column definition.
type SchemaColumn struct {
	Name     string
	Type     string
	Nullable bool
	Default  string
}

// Grant is one privilege assignment (a GRANT statement's essence).
type Grant struct {
	Role       string
	Privilege  string
	ObjectType string
	Object     string
	Grantable  bool
}

// ParamsSnapshot is a server's non-default runtime parameters.
type ParamsSnapshot struct {
	Engine   string
	Database string
	Params   []Param
}

// Param is one server setting.
type Param struct {
	Name   string
	Value  string
	Unit   string
	Source string
}

// RenderTable builds the canonical YAML document for one table.
//
// Every row is written in primary-key order and every column in ordinal order,
// so two polls of an unchanged table produce byte-identical documents and the
// shadow store emits nothing. The row's columns are mapping keys (rather than a
// positional list) because the diff an operator reads is a YAML diff: a changed
// setting has to appear as `verify_tls: "true" -> "false"`, not as an unlabelled
// change in the fourth line of a row.
func RenderTable(s TableSnapshot, scrub *Scrubber) []byte {
	cols := append([]string(nil), s.Columns...)
	if len(cols) == 0 {
		return nil
	}
	// A key/value settings table names its secret in the row, not in the
	// column: `app_settings` has (key, value) and the credential is the row
	// whose key is `stripe_webhook_secret`. The column-name check alone would
	// therefore let every secret through in the most common shape of the very
	// table this watcher exists to guard.
	secretCols := secretColumns(cols)
	rows := make([]yaml.Node, 0, len(s.Rows))
	for _, r := range s.Rows {
		var mapping yaml.Node
		mapping.Kind = yaml.MappingNode
		mapping.Tag = "!!map"
		rowIsSecret := rowNamesSecret(cols, r.Values)
		for i, col := range cols {
			var key, val yaml.Node
			key.SetString(col)
			cell := ""
			if i < len(r.Values) {
				cell = r.Values[i]
			}
			secret := secretCols[col] || (rowIsSecret && isValueColumn(col))
			val.SetString(scrubCell(col, cell, scrub, secret))
			mapping.Content = append(mapping.Content, &key, &val)
		}
		rows = append(rows, mapping)
	}

	root := mappingNode()
	appendString(root, "kind", "database_table")
	appendString(root, "engine", s.Engine)
	appendString(root, "database", s.Database)
	appendString(root, "schema", s.Schema)
	appendString(root, "table", s.Table)
	appendStringList(root, "key_columns", s.KeyColumns)
	appendStringList(root, "columns", cols)
	appendString(root, "row_count", strconv.Itoa(len(s.Rows)))
	appendBool(root, "truncated", s.Truncated)
	appendNode(root, "rows", sequenceNode(rows))
	return marshalBounded(root)
}

// RenderSchema builds the canonical YAML document for a schema/privilege
// snapshot. Tables, columns and grants are sorted, so the document only changes
// when the DDL does — not when the catalog happened to return rows in a
// different order.
func RenderSchema(s SchemaSnapshot) []byte {
	tables := append([]SchemaTable(nil), s.Tables...)
	sort.Slice(tables, func(i, j int) bool {
		if tables[i].Schema != tables[j].Schema {
			return tables[i].Schema < tables[j].Schema
		}
		return tables[i].Name < tables[j].Name
	})

	tblNodes := make([]yaml.Node, 0, len(tables))
	for _, t := range tables {
		cols := append([]SchemaColumn(nil), t.Columns...)
		sort.Slice(cols, func(i, j int) bool { return cols[i].Name < cols[j].Name })
		colNodes := make([]yaml.Node, 0, len(cols))
		for _, c := range cols {
			n := mappingNode()
			appendString(n, "name", c.Name)
			appendString(n, "type", c.Type)
			appendBool(n, "nullable", c.Nullable)
			appendString(n, "default", c.Default)
			colNodes = append(colNodes, deref(n))
		}
		n := mappingNode()
		appendString(n, "schema", t.Schema)
		appendString(n, "name", t.Name)
		appendNode(n, "columns", sequenceNode(colNodes))
		tblNodes = append(tblNodes, deref(n))
	}

	grants := append([]Grant(nil), s.Grants...)
	sort.Slice(grants, func(i, j int) bool {
		a, b := grants[i], grants[j]
		if a.Role != b.Role {
			return a.Role < b.Role
		}
		if a.Object != b.Object {
			return a.Object < b.Object
		}
		return a.Privilege < b.Privilege
	})
	grantNodes := make([]yaml.Node, 0, len(grants))
	for _, g := range grants {
		n := mappingNode()
		appendString(n, "role", g.Role)
		appendString(n, "privilege", g.Privilege)
		appendString(n, "object_type", g.ObjectType)
		appendString(n, "object", g.Object)
		appendBool(n, "grantable", g.Grantable)
		grantNodes = append(grantNodes, deref(n))
	}

	root := mappingNode()
	appendString(root, "kind", "database_schema")
	appendString(root, "engine", s.Engine)
	appendString(root, "database", s.Database)
	appendNode(root, "tables", sequenceNode(tblNodes))
	appendNode(root, "grants", sequenceNode(grantNodes))
	return marshalBounded(root)
}

// RenderParams builds the canonical YAML document for the server parameters.
func RenderParams(s ParamsSnapshot) []byte {
	params := append([]Param(nil), s.Params...)
	sort.Slice(params, func(i, j int) bool { return params[i].Name < params[j].Name })
	nodes := make([]yaml.Node, 0, len(params))
	for _, p := range params {
		n := mappingNode()
		appendString(n, "name", p.Name)
		appendString(n, "value", p.Value)
		appendString(n, "unit", p.Unit)
		appendString(n, "source", p.Source)
		nodes = append(nodes, deref(n))
	}
	root := mappingNode()
	appendString(root, "kind", "database_server_params")
	appendString(root, "engine", s.Engine)
	appendString(root, "database", s.Database)
	appendString(root, "parameter_count", strconv.Itoa(len(params)))
	appendNode(root, "parameters", sequenceNode(nodes))
	return marshalBounded(root)
}

// scrubCell renders one cell, stubbing a secret-bearing column exactly and
// scrubbing any other value for an embedded credential.
//
// The column-name check comes first because a config table's secret column is
// known: stubbing it whole is both safer and more informative than letting the
// entropy scrubber decide, and it keeps the diff a single changed line even for
// a connection string.
func scrubCell(column, value string, scrub *Scrubber, secret bool) string {
	if secret || isSecretColumn(column) {
		return scrub.secret(value)
	}
	return scrub.text(value)
}

// secretColumns reports which columns are secret-bearing by name.
func secretColumns(cols []string) map[string]bool {
	out := make(map[string]bool, len(cols))
	for _, c := range cols {
		if isSecretColumn(c) {
			out[c] = true
		}
	}
	return out
}

// keyColumns are the column names that name a setting in a key/value table,
// tried in order of specificity.
var keyColumns = []string{"key", "setting", "setting_key", "name", "param", "parameter"}

// valueColumns are the column names that hold the value a key names.
var valueColumns = []string{"value", "setting_value", "val", "data", "current_value"}

// rowNamesSecret reports whether a row's key column names a credential.
//
// This is what makes `stripe_webhook_secret -> whsec_…` redact in a table whose
// column is merely called "value". It is a heuristic and it is deliberately
// generous: over-redacting one cell loses a little review context, while
// under-redacting writes a live secret into the shadow store, the diff and the
// transport.
func rowNamesSecret(cols []string, values []string) bool {
	for i, col := range cols {
		if !isKeyColumn(col) || i >= len(values) {
			continue
		}
		if isSecretColumn(values[i]) {
			return true
		}
	}
	return false
}

func isKeyColumn(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, k := range keyColumns {
		if n == k {
			return true
		}
	}
	return false
}

func isValueColumn(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, v := range valueColumns {
		if n == v {
			return true
		}
	}
	return false
}

// isSecretColumn reports whether a column name denotes a credential.
func isSecretColumn(name string) bool {
	n := strings.ToLower(name)
	for _, marker := range []string{
		"password", "passwd", "secret", "api_key", "apikey", "api-key",
		"token", "credential", "private_key", "connection_string", "conn_str",
		"dsn", "access_key",
	} {
		if strings.Contains(n, marker) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// yaml.Node helpers
//
// The document is built as a node tree rather than from a struct because the
// row shape is dynamic: the column set is whatever the table has, in ordinal
// order. A struct could not preserve that order, and an unordered map would
// make two polls of an unchanged table render differently.
// ---------------------------------------------------------------------------

func mappingNode() *yaml.Node {
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	return n
}

func sequenceNode(items []yaml.Node) *yaml.Node {
	n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	n.Content = make([]*yaml.Node, 0, len(items))
	for i := range items {
		n.Content = append(n.Content, &items[i])
	}
	return n
}

func appendString(parent *yaml.Node, key, value string) {
	var k, v yaml.Node
	k.SetString(key)
	v.SetString(value)
	parent.Content = append(parent.Content, &k, &v)
}

func appendBool(parent *yaml.Node, key string, value bool) {
	var k, v yaml.Node
	k.SetString(key)
	v.SetString(strconv.FormatBool(value))
	parent.Content = append(parent.Content, &k, &v)
}

func appendStringList(parent *yaml.Node, key string, values []string) {
	var k yaml.Node
	k.SetString(key)
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, s := range values {
		var v yaml.Node
		v.SetString(s)
		seq.Content = append(seq.Content, &v)
	}
	parent.Content = append(parent.Content, &k, seq)
}

func appendNode(parent *yaml.Node, key string, value *yaml.Node) {
	var k yaml.Node
	k.SetString(key)
	parent.Content = append(parent.Content, &k, value)
}

func deref(n *yaml.Node) yaml.Node { return *n }

// marshalBounded serialises a node tree and enforces the document ceiling.
//
// An oversized document is refused rather than truncated: a truncated YAML
// document is not valid YAML, and a silently shortened one would read as a real
// change on the next poll. The caller logs and skips the target instead.
func marshalBounded(root *yaml.Node) []byte {
	out, err := yaml.Marshal(root)
	if err != nil {
		return nil
	}
	if len(out) > maxDocumentBytes {
		return nil
	}
	return out
}
