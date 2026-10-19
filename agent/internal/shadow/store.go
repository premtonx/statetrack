// Package shadow keeps the agent's last-known state of every watched file:
// a content-addressable store of Zstd-compressed snapshots plus a path index,
// used to diff new file contents against what was there before.
//
// Snapshot objects are addressed by the SHA-256 of the original file
// content but hold the secret-scrubbed text, so no credential is ever
// persisted by the agent.
package shadow

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/statetrack/statetrack/agent/internal/sqlitedb"
	"github.com/statetrack/statetrack/pkg/diff"
)

// ErrNoContent is returned when no snapshot is stored for a hash.
var ErrNoContent = errors.New("shadow: no snapshot for hash")

// Entry is the last-known state of one path.
type Entry struct {
	Path    string
	Hash    string // hex SHA-256 of the original file content
	Size    int64
	ModTime time.Time
	Mode    fs.FileMode
	// HasContent is true when a scrubbed snapshot is stored for Hash.
	HasContent bool
	UpdatedAt  time.Time
}

// Store is the shadow cache rooted at a directory:
//
//	<dir>/index.db                 path index and metadata (SQLite, WAL)
//	<dir>/objects/ab/abcdef….zst   compressed snapshots
type Store struct {
	dir     string
	objects string
	db      *sql.DB
	// gcMu serialises GC against writers so an object is never removed
	// between being written and being referenced.
	gcMu sync.RWMutex
}

const schema = `
CREATE TABLE IF NOT EXISTS entries (
	path        TEXT PRIMARY KEY,
	hash        TEXT NOT NULL,
	size        INTEGER NOT NULL,
	mod_time_ns INTEGER NOT NULL,
	mode        INTEGER NOT NULL,
	has_content INTEGER NOT NULL,
	updated_ns  INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS entries_hash ON entries(hash);
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
) WITHOUT ROWID;`

// Open opens or creates the shadow cache in dir (created with mode 0700).
func Open(ctx context.Context, dir string) (*Store, error) {
	objects := filepath.Join(dir, "objects")
	if err := os.MkdirAll(objects, 0o700); err != nil {
		return nil, fmt.Errorf("shadow: %w", err)
	}
	db, err := sqlitedb.Open(ctx, filepath.Join(dir, "index.db"), 512)
	if err != nil {
		return nil, fmt.Errorf("shadow: %w", err)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("shadow: schema: %w", err)
	}
	return &Store{dir: dir, objects: objects, db: db}, nil
}

// Close closes the index.
func (s *Store) Close() error { return s.db.Close() }

// Get returns the entry for path.
func (s *Store) Get(ctx context.Context, path string) (Entry, bool, error) {
	var e Entry
	var modNS, updNS int64
	var mode uint32
	var has int
	err := s.db.QueryRowContext(ctx,
		`SELECT path, hash, size, mod_time_ns, mode, has_content, updated_ns FROM entries WHERE path = ?`, path).
		Scan(&e.Path, &e.Hash, &e.Size, &modNS, &mode, &has, &updNS)
	if errors.Is(err, sql.ErrNoRows) {
		return Entry{}, false, nil
	}
	if err != nil {
		return Entry{}, false, fmt.Errorf("shadow: get %s: %w", path, err)
	}
	e.ModTime, e.UpdatedAt = time.Unix(0, modNS), time.Unix(0, updNS)
	e.Mode, e.HasContent = fs.FileMode(mode), has != 0
	return e, true, nil
}

// Put records e. If content is non-nil it is stored as the snapshot for
// e.Hash (deduplicated) and e.HasContent is set.
func (s *Store) Put(ctx context.Context, e Entry, content []byte) error {
	s.gcMu.RLock()
	defer s.gcMu.RUnlock()
	e.HasContent = content != nil
	if e.HasContent {
		if err := s.writeObject(e.Hash, content); err != nil {
			return err
		}
	}
	if e.UpdatedAt.IsZero() {
		e.UpdatedAt = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO entries (path, hash, size, mod_time_ns, mode, has_content, updated_ns)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(path) DO UPDATE SET hash = excluded.hash, size = excluded.size,
			mod_time_ns = excluded.mod_time_ns, mode = excluded.mode,
			has_content = excluded.has_content, updated_ns = excluded.updated_ns`,
		e.Path, e.Hash, e.Size, e.ModTime.UnixNano(), uint32(e.Mode), boolInt(e.HasContent), e.UpdatedAt.UnixNano())
	if err != nil {
		return fmt.Errorf("shadow: put %s: %w", e.Path, err)
	}
	return nil
}

// Delete removes the entry for path. Its snapshot is reclaimed by GC.
func (s *Store) Delete(ctx context.Context, path string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM entries WHERE path = ?`, path); err != nil {
		return fmt.Errorf("shadow: delete %s: %w", path, err)
	}
	return nil
}

// PathsUnder returns the indexed paths equal to or below root (using sep as
// the path separator), sorted.
func (s *Store) PathsUnder(ctx context.Context, root string, sep byte) ([]string, error) {
	prefix := strings.TrimSuffix(root, string(sep)) + string(sep)
	// Range scan on the primary key: [prefix, prefix with sep+1).
	upper := prefix[:len(prefix)-1] + string(sep+1)
	rows, err := s.db.QueryContext(ctx,
		`SELECT path FROM entries WHERE path = ? OR (path >= ? AND path < ?) ORDER BY path`, root, prefix, upper)
	if err != nil {
		return nil, fmt.Errorf("shadow: list %s: %w", root, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Count returns the number of indexed paths.
func (s *Store) Count(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM entries`).Scan(&n)
	return n, err
}

// Content returns the decompressed snapshot stored for hash.
func (s *Store) Content(hash string) ([]byte, error) {
	p, err := s.objectPath(hash)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoContent
	}
	if err != nil {
		return nil, fmt.Errorf("shadow: read object: %w", err)
	}
	out, err := diff.Decompress(raw)
	if err != nil {
		return nil, fmt.Errorf("shadow: object %s: %w", hash, err)
	}
	return out, nil
}

// Meta returns a metadata value.
func (s *Store) Meta(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

// SetMeta stores a metadata value.
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// GC removes snapshot objects no longer referenced by any entry, and stray
// temporary files. It returns the number of files removed.
func (s *Store) GC(ctx context.Context) (int, error) {
	s.gcMu.Lock()
	defer s.gcMu.Unlock()

	live := make(map[string]struct{})
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT hash FROM entries WHERE has_content = 1`)
	if err != nil {
		return 0, fmt.Errorf("shadow: gc: %w", err)
	}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return 0, err
		}
		live[h] = struct{}{}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	removed := 0
	err = filepath.WalkDir(s.objects, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		name := d.Name()
		hash, isObj := strings.CutSuffix(name, ".zst")
		if _, ok := live[hash]; isObj && ok {
			return nil
		}
		if err := os.Remove(p); err == nil {
			removed++
		}
		return nil
	})
	return removed, err
}

func (s *Store) objectPath(hash string) (string, error) {
	if len(hash) != 64 {
		return "", fmt.Errorf("shadow: invalid hash %q", hash)
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return "", fmt.Errorf("shadow: invalid hash %q", hash)
	}
	return filepath.Join(s.objects, hash[:2], hash+".zst"), nil
}

func (s *Store) writeObject(hash string, content []byte) error {
	p, err := s.objectPath(hash)
	if err != nil {
		return err
	}
	if _, err := os.Stat(p); err == nil {
		return nil // content-addressed: already stored
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("shadow: %w", err)
	}
	z, err := diff.Compress(content)
	if err != nil {
		return fmt.Errorf("shadow: compress: %w", err)
	}
	var suffix [6]byte
	_, _ = rand.Read(suffix[:])
	tmp := p + ".tmp-" + hex.EncodeToString(suffix[:])
	if err := os.WriteFile(tmp, z, 0o600); err != nil {
		return fmt.Errorf("shadow: write object: %w", err)
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("shadow: write object: %w", err)
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
