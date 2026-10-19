// Package baseline implements the Day-0 walker: on first start it silently
// seeds the shadow cache with every watched file so that pre-existing files
// never surface as fake creation events, and later edits diff against the
// real previous content.
package baseline

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/statetrack/statetrack/agent/internal/shadow"
)

const metaPrefix = "baseline:"

// Policy decides what to do with a path during the walk.
type Policy interface {
	// Skip reports whether a path (file or directory) must not be visited.
	Skip(path string) bool
	// Mode returns how a file is recorded.
	Mode(path string) shadow.Mode
}

// Walker seeds the shadow cache for configured roots.
type Walker struct {
	Tracker *shadow.Tracker
	Policy  Policy
	// Pace is slept after each seeded file to keep the walk under the
	// agent's CPU budget. Zero disables pacing.
	Pace   time.Duration
	Logger *slog.Logger
}

// Stats summarises a walk.
type Stats struct {
	RootsWalked  int // roots baselined during this run
	RootsSkipped int // roots already baselined earlier
	Files        int // files seeded
	Skipped      int // paths skipped by policy or non-regular
	Errors       int // unreadable paths (logged, not fatal)
	Duration     time.Duration
}

// Run baselines every root not yet completed. A root is marked complete
// only after a full walk, so an interrupted baseline resumes (Seed is
// idempotent) on the next start.
func (w *Walker) Run(ctx context.Context, roots []string) (Stats, error) {
	start := time.Now()
	var st Stats
	store := w.Tracker.Store()
	for _, root := range roots {
		root = filepath.Clean(root)
		done, err := w.Done(ctx, root)
		if err != nil {
			return st, err
		}
		if done {
			st.RootsSkipped++
			continue
		}
		if err := w.walk(ctx, root, &st); err != nil {
			return st, err
		}
		if err := store.SetMeta(ctx, metaPrefix+root, time.Now().UTC().Format(time.RFC3339)); err != nil {
			return st, fmt.Errorf("baseline: mark %s: %w", root, err)
		}
		st.RootsWalked++
		w.logger().Info("baseline complete", "root", root, "files", st.Files)
	}
	st.Duration = time.Since(start)
	return st, nil
}

// Done reports whether root has been fully baselined.
func (w *Walker) Done(ctx context.Context, root string) (bool, error) {
	_, ok, err := w.Tracker.Store().Meta(ctx, metaPrefix+filepath.Clean(root))
	return ok, err
}

func (w *Walker) walk(ctx context.Context, root string, st *Stats) error {
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			if p == root && errors.Is(err, fs.ErrNotExist) {
				return filepath.SkipDir // absent root counts as baselined
			}
			st.Errors++
			w.logger().Warn("baseline: unreadable path", "path", p, "err", err)
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if w.Policy != nil && w.Policy.Skip(p) {
			st.Skipped++
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			st.Skipped++
			return nil
		}
		mode := shadow.ModeFull
		if w.Policy != nil {
			mode = w.Policy.Mode(p)
		}
		ok, err := w.Tracker.Seed(ctx, p, mode)
		switch {
		case err != nil:
			st.Errors++
			w.logger().Warn("baseline: seed failed", "path", p, "err", err)
		case ok:
			st.Files++
		default:
			st.Skipped++
		}
		if w.Pace > 0 {
			t := time.NewTimer(w.Pace)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
		}
		return nil
	})
	if errors.Is(err, filepath.SkipDir) {
		return nil
	}
	return err
}

func (w *Walker) logger() *slog.Logger {
	if w.Logger != nil {
		return w.Logger
	}
	return slog.Default()
}
