package database

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/statetrack/statetrack/agent/internal/engine"
	"github.com/statetrack/statetrack/agent/internal/limiter"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// DefaultInterval is how often the watched surfaces are re-read.
//
// Sixty seconds, not one. A database watcher polls with real queries against a
// production server, and a configuration table that changes twice an hour does
// not need sub-minute resolution. An operator who wants a table checked sooner
// can set poll_interval on the connection.
const DefaultInterval = 60 * time.Second

// Connection is one watched database.
type Connection struct {
	// Name is a stable label for logs and for keying the connection. It is not
	// part of a document path, which is derived from the engine and database
	// name so a rule authored in the console does not depend on it.
	Name string
	// Engine is "postgres" or "sqlserver".
	Engine string
	// DSN is the connection string. It is a credential: it is never logged.
	DSN string
	// Database is the database name used in tracked paths. Empty derives it
	// from the DSN.
	Database string
	// Tables are the tables to snapshot, as "schema.table" or "table".
	Tables []string
	// WatchSchema snapshots the table/column/privilege DDL.
	WatchSchema bool
	// WatchServerParams snapshots the non-default runtime parameters.
	WatchServerParams bool
	// RowLimit bounds one table snapshot.
	RowLimit int
	// Interval overrides DefaultInterval for this connection.
	Interval time.Duration
}

// Options configures the collector.
type Options struct {
	Connections []Connection

	// Targets are the extra table/schema/param paths an operator added in the
	// console. They are merged with each connection's configured surfaces, so a
	// rule created in the UI starts being tracked on the next poll with no
	// agent restart. A target whose database matches no connection is skipped:
	// the agent cannot reach a database it was never given a DSN for.
	Targets []string
	// DynamicTargets returns the console's paths at poll time. It is what makes
	// a rule created after the agent started take effect: the classifier is
	// reconfigured on every heartbeat, so re-reading it each poll is enough.
	// Patterns with glob metacharacters are ignored — this watcher addresses
	// concrete tables, and it has no way to enumerate a database by pattern.
	DynamicTargets func() []string

	Interval   time.Duration
	Classifier *limiter.Classifier
	// Scrub is the edge redaction pair: a hash stub for a known credential
	// column and a line scrubber for free text. Nil is safe and falls back to a
	// fixed marker, so a misconfigured collector never writes a cleartext
	// secret — it just loses the ability to show that a credential rotated.
	Scrub *Scrubber
	// Open builds a handle for a connection. Empty uses the real driver.
	Open   func(engine, dsn string) (*sql.DB, error)
	Handle func(context.Context, engine.DocEvent) error
	Seed   func(ctx context.Context, path, targetType string, content []byte, modTime time.Time) error
	Known  func(ctx context.Context, path string) bool
	// Attribute resolves the actor behind a change. Empty uses the platform
	// query (pg_stat_activity / sys.dm_exec_sessions).
	Attribute func(ctx context.Context, db DB, engine string) (user, client, ip string)
	Logger    *slog.Logger
}

// Collector polls the configured database surfaces, rendering one canonical
// YAML document per surface.
type Collector struct {
	o   Options
	log *slog.Logger

	mu   sync.Mutex
	last map[string]bool // rendered paths, so a removed target is reported once
	seen map[string]bool
}

// New builds a collector, applying defaults.
func New(o Options) *Collector {
	if o.Interval <= 0 {
		o.Interval = DefaultInterval
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Open == nil {
		o.Open = Open
	}
	if o.Attribute == nil {
		o.Attribute = Attribute
	}
	return &Collector{o: o, log: o.Logger.With("collector", "database"), last: map[string]bool{}}
}

// Run polls every connection until ctx is done.
func (c *Collector) Run(ctx context.Context) error {
	if c.o.Handle == nil {
		return errors.New("database: Handle is required")
	}
	if len(c.o.Connections) == 0 {
		c.log.Info("database watcher has no connections; add one in agent.yaml to enable it")
		return nil
	}
	var wg sync.WaitGroup
	for _, conn := range c.o.Connections {
		conn := conn
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runConnection(ctx, conn)
		}()
	}
	wg.Wait()
	return nil
}

// runConnection owns one connection's poll loop and its database handle.
func (c *Collector) runConnection(ctx context.Context, conn Connection) {
	interval := conn.Interval
	if interval <= 0 {
		interval = c.o.Interval
	}
	db := conn.Database
	if db == "" {
		db = databaseFromDSN(conn.DSN)
	}
	log := c.log.With("connection", conn.Name, "engine", conn.Engine, "database", db)
	if db == "" {
		// A path with no database name cannot be addressed by a console rule,
		// so the connection is refused rather than producing unreachable
		// documents nobody can see.
		log.Error("database connection has no database name; set database in agent.yaml or include it in the DSN")
		return
	}
	log.Info("database connection started", "tables", len(conn.Tables),
		"schema", conn.WatchSchema, "params", conn.WatchServerParams, "interval", interval)

	// The handle is opened once and reused: opening per poll would add a
	// connection handshake (and a TLS exchange) to every cycle for no benefit.
	handle, err := c.o.Open(conn.Engine, conn.DSN)
	if err != nil {
		log.Error("database connection failed", "err", err)
		return
	}
	defer handle.Close()

	c.poll(ctx, handle, conn, db, log)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.poll(ctx, handle, conn, db, log)
		}
	}
}

// poll reads every watched surface once.
func (c *Collector) poll(ctx context.Context, db *sql.DB, conn Connection, database string, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(ctx, DefaultQueryTimeout)
	defer cancel()

	now := time.Now()
	tables, wantSchema, wantParams := c.surfaces(conn, database)
	seen := make(map[string]bool, len(tables)+2)

	for _, t := range tables {
		path := TablePath(conn.Engine, database, t.Schema, t.Table)
		seen[path] = true
		c.observeTable(ctx, db, conn, database, t, path, now, log)
	}
	if wantSchema {
		path := SchemaPath(conn.Engine, database)
		seen[path] = true
		c.observeSchema(ctx, db, conn, database, path, now, log)
	}
	if wantParams {
		path := ParamsPath(conn.Engine, database)
		seen[path] = true
		c.observeParams(ctx, db, conn, database, path, now, log)
	}
	c.prune(ctx, conn.Engine, database, seen)
}

// surface is one table to snapshot.
type surface struct {
	Schema, Table string
}

// surfaces merges the connection's configured tables with the console's targets
// for this database.
func (c *Collector) surfaces(conn Connection, database string) (tables []surface, schema, params bool) {
	schema, params = conn.WatchSchema, conn.WatchServerParams
	seen := map[string]bool{}

	add := func(target Target) {
		if target.Engine != conn.Engine || target.Database != database {
			return
		}
		switch target.Kind {
		case KindSchema:
			schema = true
		case KindParams:
			params = true
		case KindTables:
			key := target.Schema + "." + target.Table
			if seen[key] {
				return
			}
			seen[key] = true
			tables = append(tables, surface{Schema: target.Schema, Table: target.Table})
		}
	}

	for _, raw := range conn.Tables {
		s, t := splitTable(raw, DefaultSchema(conn.Engine))
		if t == "" {
			continue
		}
		key := s + "." + t
		if seen[key] {
			continue
		}
		seen[key] = true
		tables = append(tables, surface{Schema: s, Table: t})
	}
	for _, raw := range c.o.Targets {
		target, ok := ParseTarget(raw)
		if !ok {
			continue
		}
		add(target)
	}
	if c.o.DynamicTargets != nil {
		for _, raw := range c.o.DynamicTargets() {
			if strings.ContainsAny(raw, "*?[") {
				// A glob cannot be turned into a table name, and expanding it
				// would mean enumerating the catalog, which this watcher
				// deliberately never does.
				continue
			}
			if target, ok := ParseTarget(raw); ok {
				add(target)
			}
		}
	}
	sort.Slice(tables, func(i, j int) bool {
		if tables[i].Schema != tables[j].Schema {
			return tables[i].Schema < tables[j].Schema
		}
		return tables[i].Table < tables[j].Table
	})
	return tables, schema, params
}

func (c *Collector) observeTable(ctx context.Context, db *sql.DB, conn Connection, database string, t surface, path string, now time.Time, log *slog.Logger) {
	if c.o.Classifier != nil && c.o.Classifier.Blacklisted(path) {
		return
	}
	limit := conn.RowLimit
	if limit <= 0 {
		limit = DefaultRowLimit
	}
	snap, err := ReadTable(ctx, db, conn.Engine, database, t.Schema, t.Table, limit)
	if err != nil {
		// A table that was dropped, renamed or is locked is logged and skipped.
		// Reporting the document as deleted on a transient query error would
		// raise a Level 1 "table removed" alert for a timeout.
		log.Warn("read table", "table", t.Schema+"."+t.Table, "err", err)
		return
	}
	content := RenderTable(snap, c.o.Scrub)
	if content == nil {
		log.Warn("table document empty or oversized; skipped", "table", t.Schema+"."+t.Table)
		return
	}
	summary := "Modified " + path
	if snap.Truncated {
		summary = "Modified " + path + " (first " + strconv.Itoa(len(snap.Rows)) + " rows)"
	}
	c.observe(ctx, db, conn, path, TargetTable, content, now, summary, t.Schema+"."+t.Table, log)
}

func (c *Collector) observeSchema(ctx context.Context, db *sql.DB, conn Connection, database, path string, now time.Time, log *slog.Logger) {
	if c.o.Classifier != nil && c.o.Classifier.Blacklisted(path) {
		return
	}
	snap, err := ReadSchema(ctx, db, conn.Engine, database)
	if err != nil {
		log.Warn("read schema", "err", err)
		return
	}
	content := RenderSchema(snap)
	if content == nil {
		log.Warn("schema document empty or oversized; skipped")
		return
	}
	c.observe(ctx, db, conn, path, TargetSchema, content, now, "Modified "+path, "schema", log)
}

func (c *Collector) observeParams(ctx context.Context, db *sql.DB, conn Connection, database, path string, now time.Time, log *slog.Logger) {
	if c.o.Classifier != nil && c.o.Classifier.Blacklisted(path) {
		return
	}
	snap, err := ReadParams(ctx, db, conn.Engine, database)
	if err != nil {
		log.Warn("read server parameters", "err", err)
		return
	}
	content := RenderParams(snap)
	if content == nil {
		log.Warn("server parameter document empty or oversized; skipped")
		return
	}
	c.observe(ctx, db, conn, path, TargetParams, content, now, "Modified "+path, "server parameters", log)
}

// observe hands one rendered document to the engine.
func (c *Collector) observe(ctx context.Context, db *sql.DB, conn Connection, path, targetType string, content []byte, now time.Time, summary, label string, log *slog.Logger) {
	c.mu.Lock()
	had := c.last[path]
	c.last[path] = true
	c.mu.Unlock()

	if !c.known(ctx, path) {
		if c.o.Seed != nil {
			if err := c.o.Seed(ctx, path, targetType, content, now); err != nil {
				log.Error("database seed", "target", label, "err", err)
			}
		}
		return
	}

	de := engine.DocEvent{
		Path:       path,
		TargetType: targetType,
		Content:    content,
		ModTime:    now,
	}
	if actor, method := c.attribute(ctx, db, conn.Engine); actor != nil {
		de.Actor = actor
		de.Attribution = method
	}
	if err := c.o.Handle(ctx, de); err != nil {
		log.Error("database change", "target", label, "err", err)
		return
	}
	if had {
		log.Info("database change observed", "target", label, "summary", summary)
	}
}

// attribute names the acting identity from the server's session table.
func (c *Collector) attribute(ctx context.Context, db *sql.DB, engine string) (*pb.ActorContext, string) {
	if c.o.Attribute == nil {
		return nil, ""
	}
	user, client, ip := c.o.Attribute(ctx, db, engine)
	if user == "" && client == "" && ip == "" {
		return nil, ""
	}
	return &pb.ActorContext{
		Username:    user,
		ProcessName: client,
		RemoteIp:    ip,
	}, "database_session"
}

// known reports whether the path already has a baseline.
func (c *Collector) known(ctx context.Context, path string) bool {
	return c.o.Known != nil && c.o.Known(ctx, path)
}

// prune reports watched documents that no longer exist as deletions, so a table
// removed from configuration (or from the database) is itself a change rather
// than a row that silently stops updating.
func (c *Collector) prune(ctx context.Context, engineName, database string, seen map[string]bool) {
	prefix := Scheme + engineName + "/" + database + "/"
	c.mu.Lock()
	var gone []string
	for path := range c.last {
		if strings.HasPrefix(path, prefix) && !seen[path] {
			gone = append(gone, path)
		}
	}
	for _, path := range gone {
		delete(c.last, path)
	}
	c.mu.Unlock()
	sort.Strings(gone)
	for _, path := range gone {
		target, ok := ParseTarget(path)
		if !ok {
			continue
		}
		if err := c.o.Handle(ctx, engine.DocEvent{
			Path:       path,
			TargetType: target.TargetType(),
			Content:    nil,
			ModTime:    time.Now(),
		}); err != nil {
			c.log.Error("database delete", "path", path, "err", err)
		}
	}
}

// databaseFromDSN extracts the database name from a connection string when the
// connection did not name one explicitly.
func databaseFromDSN(dsn string) string {
	// URL form: postgres://user@host:5432/settings_db?sslmode=require
	if i := strings.Index(dsn, "://"); i >= 0 {
		rest := dsn[i+3:]
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			rest = rest[at+1:]
		}
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			db := rest[slash+1:]
			if q := strings.IndexByte(db, '?'); q >= 0 {
				db = db[:q]
			}
			return strings.TrimSpace(db)
		}
		return ""
	}
	// ADO form: server=...;database=settings_db;user id=...
	for _, part := range strings.Split(dsn, ";") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(kv[0])) {
		case "database", "initial catalog":
			return strings.TrimSpace(kv[1])
		}
	}
	return ""
}
