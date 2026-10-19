package shadow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/statetrack/statetrack/agent/internal/limiter"
	"github.com/statetrack/statetrack/pkg/diff"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/pkg/redact"
)

// DefaultDeleteGrace is how long a vanished file may stay missing before it
// is reported as deleted. Editors that save by renaming the original away
// and writing a new file (vim with backupcopy=no) recreate it well within
// this window, which then surfaces as a single modification.
const DefaultDeleteGrace = time.Second

// Mode selects how much work is done for a path.
type Mode int

const (
	// ModeFull stores a scrubbed snapshot and produces text diffs.
	ModeFull Mode = iota
	// ModeMetadata records hash and size only (Level 3 drift).
	ModeMetadata
)

// Change is a detected difference between a path and its shadow state.
type Change struct {
	Path   string
	Action pb.Action // ACTION_CREATED, ACTION_MODIFIED or ACTION_DELETED
	Before *Entry    // nil for creations
	After  *Entry    // nil for deletions
	// Content classifies the new content (or the old one for deletions).
	Content limiter.ContentKind
	// Diff is the secret-scrubbed unified diff, if one was produced.
	Diff string
	// DiffSkipped explains a missing diff: "binary", "too_large",
	// "metadata_only" or "no_previous_snapshot".
	DiffSkipped string
	// ModeChanged is set when only permissions changed.
	ModeChanged bool
}

// Tracker turns "something happened to path" notifications into Changes by
// comparing the current file with its shadow entry. Because it is
// state-based rather than event-based, atomic-save sequences (write temp +
// rename over target, as done by sed -i and most editors) produce exactly
// one modification of the target diffed against its previous content.
type Tracker struct {
	store    *Store
	scrubber *redact.Scrubber
	context  int
	grace    time.Duration
	now      func() time.Time

	mu      sync.Mutex
	pending map[string]time.Time // vanished paths awaiting delete confirmation
}

// TrackerOptions configures a Tracker.
type TrackerOptions struct {
	// DiffContext is the unified diff context; negative means default (3).
	DiffContext int
	DeleteGrace time.Duration
	Now         func() time.Time
}

// NewTracker creates a tracker over store using scrubber for snapshots and diffs.
func NewTracker(store *Store, scrubber *redact.Scrubber, opts TrackerOptions) *Tracker {
	t := &Tracker{store: store, scrubber: scrubber, context: opts.DiffContext, grace: opts.DeleteGrace,
		now: opts.Now, pending: make(map[string]time.Time)}
	if t.grace <= 0 {
		t.grace = DefaultDeleteGrace
	}
	if t.now == nil {
		t.now = time.Now
	}
	if t.context < 0 {
		t.context = diff.DefaultContext
	}
	return t
}

// Store returns the underlying shadow store.
func (t *Tracker) Store() *Store { return t.store }

type snapshot struct {
	entry   Entry
	kind    limiter.ContentKind
	content []byte // full content for text files, nil otherwise
}

// read hashes the whole file while keeping at most MaxDiffFileSize+1 bytes.
func read(path string, fi fs.FileInfo) (snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return snapshot{}, err
	}
	defer f.Close()

	h := sha256.New()
	keep := &cappedBuffer{max: limiter.MaxDiffFileSize + 1}
	n, err := io.Copy(io.MultiWriter(h, keep), f)
	if err != nil {
		return snapshot{}, err
	}
	s := snapshot{
		entry: Entry{Path: path, Hash: hex.EncodeToString(h.Sum(nil)), Size: n, ModTime: fi.ModTime(), Mode: fi.Mode().Perm()},
		kind:  limiter.DetectContent(n, keep.Bytes()),
	}
	if s.kind == limiter.ContentText {
		s.content = keep.Bytes()
	}
	return s, nil
}

// Seed records the current state of path without reporting a change. It is
// used by the Day-0 baseline. It returns false for non-regular files.
func (t *Tracker) Seed(ctx context.Context, path string, mode Mode) (bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() {
		return false, nil
	}
	prev, ok, err := t.store.Get(ctx, path)
	if err != nil {
		return false, err
	}
	if ok && prev.Size == fi.Size() && prev.ModTime.Equal(fi.ModTime()) && prev.Mode == fi.Mode().Perm() &&
		(prev.HasContent || mode == ModeMetadata) {
		return true, nil // unchanged since last seed
	}
	snap, err := read(path, fi)
	if err != nil {
		return false, err
	}
	return true, t.store.Put(ctx, snap.entry, t.storedContent(snap, mode))
}

// Observe compares path with its shadow state, updates the shadow and
// returns the change, or nil if nothing relevant changed. A path that has
// vanished is only reported by ConfirmDeletes after the grace period.
func (t *Tracker) Observe(ctx context.Context, path string, mode Mode) (*Change, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	prev, hadPrev, err := t.store.Get(ctx, path)
	if err != nil {
		return nil, err
	}

	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		if hadPrev {
			if _, waiting := t.pending[path]; !waiting {
				t.pending[path] = t.now()
			}
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	delete(t.pending, path)
	if !fi.Mode().IsRegular() {
		return nil, nil
	}

	snap, err := read(path, fi)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) { // raced with a rename/delete
			return nil, nil
		}
		return nil, err
	}
	return t.compare(ctx, path, prev, hadPrev, snap, mode)
}

// contentSnapshot describes a virtual document (e.g. a rendered registry
// key) the same way read describes a file.
func contentSnapshot(path string, content []byte, modTime time.Time) snapshot {
	sum := sha256.Sum256(content)
	s := snapshot{
		entry: Entry{Path: path, Hash: hex.EncodeToString(sum[:]), Size: int64(len(content)), ModTime: modTime},
		kind:  limiter.DetectContent(int64(len(content)), content),
	}
	if s.kind == limiter.ContentText {
		s.content = content
	}
	return s
}

// SeedContent is Seed for a virtual document such as a registry key.
func (t *Tracker) SeedContent(ctx context.Context, path string, content []byte, modTime time.Time, mode Mode) error {
	snap := contentSnapshot(path, content, modTime)
	return t.store.Put(ctx, snap.entry, t.storedContent(snap, mode))
}

// ObserveContent is Observe for a virtual document. A nil content means the
// document no longer exists; unlike files, that is reported immediately
// (registry deletions are not part of save-by-rename sequences).
func (t *Tracker) ObserveContent(ctx context.Context, path string, content []byte, modTime time.Time, mode Mode) (*Change, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	prev, hadPrev, err := t.store.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if content == nil {
		if !hadPrev {
			return nil, nil
		}
		return t.deleted(ctx, path, prev, mode)
	}
	return t.compare(ctx, path, prev, hadPrev, contentSnapshot(path, content, modTime), mode)
}

func (t *Tracker) compare(ctx context.Context, path string, prev Entry, hadPrev bool, snap snapshot, mode Mode) (*Change, error) {
	after := snap.entry
	stored := t.storedContent(snap, mode)
	after.HasContent = stored != nil

	if hadPrev && prev.Hash == after.Hash {
		modeChanged := prev.Mode != after.Mode
		if modeChanged || (stored != nil && !prev.HasContent) || !prev.ModTime.Equal(after.ModTime) {
			if err := t.store.Put(ctx, after, stored); err != nil {
				return nil, err
			}
		}
		if !modeChanged {
			return nil, nil
		}
		return &Change{Path: path, Action: pb.Action_ACTION_MODIFIED, Before: &prev, After: &after,
			Content: snap.kind, ModeChanged: true, DiffSkipped: "metadata_only"}, nil
	}

	ch := &Change{Path: path, After: &after, Content: snap.kind, Action: pb.Action_ACTION_CREATED}
	if hadPrev {
		ch.Action, ch.Before = pb.Action_ACTION_MODIFIED, &prev
		ch.ModeChanged = prev.Mode != after.Mode
	}

	switch {
	case snap.kind == limiter.ContentBinary:
		ch.DiffSkipped = "binary"
	case snap.kind == limiter.ContentTooLarge:
		ch.DiffSkipped = "too_large"
	case mode == ModeMetadata:
		ch.DiffSkipped = "metadata_only"
	case !hadPrev:
		ch.Diff = diff.Unified("/dev/null", label("b", path), "", string(stored), t.context)
	case !prev.HasContent:
		ch.DiffSkipped = "no_previous_snapshot"
	default:
		old, err := t.store.Content(prev.Hash)
		if err != nil {
			ch.DiffSkipped = "no_previous_snapshot"
			break
		}
		ch.Diff = diff.Unified(label("a", path), label("b", path), string(old), string(stored), t.context)
	}

	if err := t.store.Put(ctx, after, stored); err != nil {
		return nil, err
	}
	return ch, nil
}

// PendingDelete reports whether path has vanished and awaits confirmation.
func (t *Tracker) PendingDelete(path string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.pending[path]
	return ok
}

// ConfirmDeletes reports paths that have stayed missing for the grace
// period as deletions, removing them from the shadow index. Deletions of
// text files with a snapshot carry a diff of the removed content.
func (t *Tracker) ConfirmDeletes(ctx context.Context, mode func(path string) Mode) ([]*Change, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var out []*Change
	for path, since := range t.pending {
		if now.Sub(since) < t.grace {
			continue
		}
		delete(t.pending, path)
		if _, err := os.Lstat(path); err == nil {
			continue // came back; the next Observe will diff it
		}
		prev, ok, err := t.store.Get(ctx, path)
		if err != nil {
			return out, err
		}
		if !ok {
			continue
		}
		m := ModeFull
		if mode != nil {
			m = mode(path)
		}
		ch, err := t.deleted(ctx, path, prev, m)
		if err != nil {
			return out, err
		}
		out = append(out, ch)
	}
	return out, nil
}

func (t *Tracker) deleted(ctx context.Context, path string, prev Entry, mode Mode) (*Change, error) {
	ch := &Change{Path: path, Action: pb.Action_ACTION_DELETED, Before: &prev, Content: limiter.ContentText}
	switch {
	case !prev.HasContent, mode == ModeMetadata:
		ch.DiffSkipped = "metadata_only"
	default:
		if old, err := t.store.Content(prev.Hash); err == nil {
			ch.Diff = diff.Unified(label("a", path), "/dev/null", string(old), "", t.context)
		} else {
			ch.DiffSkipped = "no_previous_snapshot"
		}
	}
	if err := t.store.Delete(ctx, path); err != nil {
		return nil, err
	}
	return ch, nil
}

func (t *Tracker) storedContent(s snapshot, mode Mode) []byte {
	if mode != ModeFull || s.kind != limiter.ContentText {
		return nil
	}
	if t.scrubber == nil {
		return append([]byte{}, s.content...)
	}
	return []byte(t.scrubber.Text(string(s.content)))
}

// label renders a git-style diff label: a/etc/nginx/nginx.conf, b/C:/x/web.config.
func label(prefix, path string) string {
	return prefix + "/" + strings.TrimPrefix(filepath.ToSlash(path), "/")
}

// cappedBuffer keeps the first max bytes written to it.
type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

func (c *cappedBuffer) Bytes() []byte { return c.buf.Bytes() }
