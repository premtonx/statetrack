// Package spool is the agent's durable outbound queue: a SQLite (WAL) ring
// buffer of serialized MutationEvents awaiting delivery to the server.
//
// The spool enforces a byte ceiling (200 MB by default). When an append
// would exceed it, the oldest events are evicted by priority — Level 3
// drift first, then Level 4, Level 2 and finally Level 1 — so critical
// changes survive long server outages. Delivery is at-least-once: events
// stay spooled until acknowledged.
package spool

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/statetrack/statetrack/agent/internal/sqlitedb"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

const (
	DefaultMaxBytes = 200 << 20
	// RowOverhead approximates per-row index and page overhead so the
	// accounted size tracks the on-disk size.
	RowOverhead = 96
)

// DefaultEvictionOrder lists levels from first to last evicted.
var DefaultEvictionOrder = []pb.ImpactLevel{
	pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT,
	pb.ImpactLevel_IMPACT_LEVEL_4_FORENSIC,
	pb.ImpactLevel_IMPACT_LEVEL_UNSPECIFIED,
	pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED,
	pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL,
}

// ErrTooLarge is returned for a single event larger than the ceiling.
var ErrTooLarge = errors.New("spool: event larger than spool capacity")

// Options configures a Spool.
type Options struct {
	MaxBytes      int64
	EvictionOrder []pb.ImpactLevel
}

// Stats describes the spool state.
type Stats struct {
	Events   int64
	Bytes    int64 // accounted bytes (payload + RowOverhead per event)
	MaxBytes int64
	// Evicted counts events dropped for capacity since creation, per level.
	Evicted map[pb.ImpactLevel]int64
}

// Spool is safe for concurrent use.
type Spool struct {
	db    *sql.DB
	max   int64
	order []pb.ImpactLevel
	// schemaBytes is the fixed size of an empty database (root page of
	// every table and index, schema page, pointer map), excluded from the
	// ceiling.
	schemaBytes int64

	mu   sync.Mutex
	used int64
}

const schema = `
CREATE TABLE IF NOT EXISTS events (
	seq      INTEGER PRIMARY KEY AUTOINCREMENT,
	event_id TEXT    NOT NULL UNIQUE,
	level    INTEGER NOT NULL,
	size     INTEGER NOT NULL,
	payload  BLOB    NOT NULL
);
CREATE INDEX IF NOT EXISTS events_level_seq ON events(level, seq);
CREATE TABLE IF NOT EXISTS evictions (
	level INTEGER PRIMARY KEY,
	count INTEGER NOT NULL
);`

// Open opens or creates the spool database at path (e.g. spool.db).
func Open(ctx context.Context, path string, opts Options) (*Spool, error) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	if len(opts.EvictionOrder) == 0 {
		opts.EvictionOrder = DefaultEvictionOrder
	}
	db, err := sqlitedb.Open(ctx, path, 1024)
	if err != nil {
		return nil, fmt.Errorf("spool: %w", err)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("spool: schema: %w", err)
	}
	s := &Spool{db: db, max: opts.MaxBytes, order: opts.EvictionOrder}
	if err := db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(size), 0) + COUNT(*) * ? FROM events`, RowOverhead).Scan(&s.used); err != nil {
		db.Close()
		return nil, fmt.Errorf("spool: %w", err)
	}
	if err := db.QueryRowContext(ctx,
		`SELECT (COUNT(*) + 2) * (SELECT page_size FROM pragma_page_size()) FROM sqlite_schema WHERE rootpage > 0`).
		Scan(&s.schemaBytes); err != nil {
		db.Close()
		return nil, fmt.Errorf("spool: %w", err)
	}
	return s, nil
}

// Close closes the database.
func (s *Spool) Close() error { return s.db.Close() }

// Append durably enqueues events, evicting older low-priority events if the
// ceiling would be exceeded. Events whose ID is already spooled are ignored.
func (s *Spool) Append(ctx context.Context, events ...*pb.MutationEvent) error {
	if len(events) == 0 {
		return nil
	}
	type row struct {
		id      string
		level   pb.ImpactLevel
		payload []byte
	}
	rows := make([]row, 0, len(events))
	for _, ev := range events {
		if ev.GetEventId() == "" {
			return errors.New("spool: event without event_id")
		}
		b, err := proto.Marshal(ev)
		if err != nil {
			return fmt.Errorf("spool: marshal %s: %w", ev.GetEventId(), err)
		}
		if int64(len(b))+RowOverhead > s.max {
			return fmt.Errorf("%w: %s is %d bytes", ErrTooLarge, ev.GetEventId(), len(b))
		}
		rows = append(rows, row{ev.GetEventId(), ev.GetLevel(), b})
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("spool: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit

	used := s.used
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO events (event_id, level, size, payload) VALUES (?, ?, ?, ?) ON CONFLICT(event_id) DO NOTHING`)
	if err != nil {
		return fmt.Errorf("spool: %w", err)
	}
	defer stmt.Close()
	for _, r := range rows {
		if used+int64(len(r.payload))+RowOverhead > s.max {
			freed, err := s.evict(ctx, tx, used+int64(len(r.payload))+RowOverhead-s.max)
			if err != nil {
				return err
			}
			used -= freed
		}
		res, err := stmt.ExecContext(ctx, r.id, int32(r.level), len(r.payload), r.payload)
		if err != nil {
			return fmt.Errorf("spool: insert %s: %w", r.id, err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			used += int64(len(r.payload)) + RowOverhead
		}
	}
	// The accounting above ignores B-tree and index overhead; bound the
	// data pages actually in use so the database file honours the ceiling
	// too (plus the fixed schema overhead).
	for i := 0; i < 16; i++ {
		disk, err := pagesInUse(ctx, tx)
		if err != nil {
			return err
		}
		if disk-s.schemaBytes <= s.max {
			break
		}
		freed, err := s.evict(ctx, tx, disk-s.schemaBytes-s.max)
		if err != nil {
			return err
		}
		used -= freed
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("spool: commit: %w", err)
	}
	s.used = used
	return nil
}

// evict frees at least want bytes, oldest first within each level of the
// eviction order, and returns the bytes freed.
func (s *Spool) evict(ctx context.Context, tx *sql.Tx, want int64) (int64, error) {
	var freed int64
	for _, level := range s.order {
		for freed < want {
			rows, err := tx.QueryContext(ctx,
				`SELECT seq, size FROM events WHERE level = ? ORDER BY seq LIMIT 512`, int32(level))
			if err != nil {
				return freed, fmt.Errorf("spool: evict: %w", err)
			}
			var lastSeq, count, bytes int64
			for rows.Next() && freed+bytes < want {
				var seq, size int64
				if err := rows.Scan(&seq, &size); err != nil {
					rows.Close()
					return freed, err
				}
				lastSeq, count, bytes = seq, count+1, bytes+size+RowOverhead
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return freed, err
			}
			if count == 0 {
				break // level exhausted
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM events WHERE level = ? AND seq <= ?`, int32(level), lastSeq); err != nil {
				return freed, fmt.Errorf("spool: evict: %w", err)
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO evictions (level, count) VALUES (?, ?) ON CONFLICT(level) DO UPDATE SET count = count + excluded.count`,
				int32(level), count); err != nil {
				return freed, fmt.Errorf("spool: evict: %w", err)
			}
			freed += bytes
		}
		if freed >= want {
			return freed, nil
		}
	}
	return freed, fmt.Errorf("spool: cannot free %d bytes", want)
}

// pagesInUse returns the bytes of database pages holding data. Freed pages
// are reused before the file grows, so this bounds the file size.
func pagesInUse(ctx context.Context, tx *sql.Tx) (int64, error) {
	var pages, free, size int64
	err := tx.QueryRowContext(ctx,
		`SELECT p.page_count, f.freelist_count, s.page_size FROM pragma_page_count() p, pragma_freelist_count() f, pragma_page_size() s`).
		Scan(&pages, &free, &size)
	if err != nil {
		return 0, fmt.Errorf("spool: page stats: %w", err)
	}
	return (pages - free) * size, nil
}

// ReadBatch returns up to maxEvents of the oldest unacknowledged events,
// stopping before maxBytes of payload (but always returning at least one
// event if any are spooled). MonotonicSeq is set to the spool sequence.
// Events remain spooled until Ack.
func (s *Spool) ReadBatch(ctx context.Context, maxEvents, maxBytes int) ([]*pb.MutationEvent, error) {
	if maxEvents <= 0 {
		maxEvents = 500
	}
	rows, err := s.db.QueryContext(ctx, `SELECT seq, payload FROM events ORDER BY seq LIMIT ?`, maxEvents)
	if err != nil {
		return nil, fmt.Errorf("spool: read: %w", err)
	}
	defer rows.Close()
	var out []*pb.MutationEvent
	total := 0
	for rows.Next() {
		var seq int64
		var payload []byte
		if err := rows.Scan(&seq, &payload); err != nil {
			return nil, err
		}
		if maxBytes > 0 && len(out) > 0 && total+len(payload) > maxBytes {
			break
		}
		ev := &pb.MutationEvent{}
		if err := proto.Unmarshal(payload, ev); err != nil {
			return nil, fmt.Errorf("spool: corrupt event at seq %d: %w", seq, err)
		}
		ev.MonotonicSeq = uint64(seq)
		out = append(out, ev)
		total += len(payload)
	}
	return out, rows.Err()
}

// Ack removes delivered events and returns how many were removed. Unknown
// IDs (e.g. already evicted) are ignored.
func (s *Spool) Ack(ctx context.Context, eventIDs []string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	const chunk = 500
	for start := 0; start < len(eventIDs); start += chunk {
		ids := eventIDs[start:min(start+chunk, len(eventIDs))]
		args := make([]any, len(ids))
		for i, id := range ids {
			args[i] = id
		}
		q := `DELETE FROM events WHERE event_id IN (?` + strings.Repeat(",?", len(ids)-1) + `) RETURNING size`
		rows, err := s.db.QueryContext(ctx, q, args...)
		if err != nil {
			return removed, fmt.Errorf("spool: ack: %w", err)
		}
		for rows.Next() {
			var size int64
			if err := rows.Scan(&size); err != nil {
				rows.Close()
				return removed, err
			}
			s.used -= size + RowOverhead
			removed++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return removed, err
		}
	}
	return removed, nil
}

// Stats returns current counters.
func (s *Spool) Stats(ctx context.Context) (Stats, error) {
	s.mu.Lock()
	used := s.used
	s.mu.Unlock()
	st := Stats{Bytes: used, MaxBytes: s.max, Evicted: map[pb.ImpactLevel]int64{}}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&st.Events); err != nil {
		return st, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT level, count FROM evictions`)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var level int32
		var n int64
		if err := rows.Scan(&level, &n); err != nil {
			return st, err
		}
		st.Evicted[pb.ImpactLevel(level)] = n
	}
	return st, rows.Err()
}

// Compact returns free pages to the filesystem (incremental vacuum) and
// truncates the WAL. Call it occasionally, e.g. after a large backlog drains.
func (s *Spool) Compact(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.ExecContext(ctx, `PRAGMA incremental_vacuum`); err != nil {
		return fmt.Errorf("spool: compact: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("spool: compact: %w", err)
	}
	return nil
}

// String is for logs.
func (st Stats) String() string {
	return strconv.FormatInt(st.Events, 10) + " events, " + strconv.FormatInt(st.Bytes, 10) + "/" +
		strconv.FormatInt(st.MaxBytes, 10) + " bytes"
}
