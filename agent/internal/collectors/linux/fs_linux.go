//go:build linux

package linux

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/statetrack/statetrack/agent/internal/engine"
	"github.com/statetrack/statetrack/agent/internal/limiter"
)

// DefaultSettle is how long a path must be quiet before it is observed, so
// a burst of writes (or an editor's save sequence) becomes one observation.
const DefaultSettle = 150 * time.Millisecond

// FSOptions configures the filesystem collector.
type FSOptions struct {
	Roots []string
	// SelfFiles are watched individually even outside Roots (the agent
	// binary); events for other files in their directories are ignored.
	SelfFiles  []string
	Classifier *limiter.Classifier
	Resolver   *Resolver
	// Handle receives settled file events (engine.HandleFile).
	Handle func(context.Context, engine.FileEvent) error
	// Known lists the shadow-indexed paths under a directory, so files in a
	// directory moved out of the watch tree are reported as deleted.
	Known  func(ctx context.Context, dir string) []string
	Settle time.Duration
	// DisableFanotify forces inotify + /proc attribution.
	DisableFanotify bool
	Logger          *slog.Logger
}

// FSStatus describes the collector's state.
type FSStatus struct {
	Dirs     int
	Fanotify bool
}

// FS is the Linux filesystem collector: recursive inotify watches for
// paths, plus fanotify (when permitted) for writer PIDs.
type FS struct {
	o   FSOptions
	log *slog.Logger
	w   *fsnotify.Watcher
	fan *fanotifyWatcher

	rootsCh chan []string

	mu       sync.Mutex
	roots    []string
	started  bool
	watched  map[string]bool
	fileOnly map[string]map[string]bool // dir -> self files watched in it
	pending  map[string]time.Time       // path -> last event
}

// NewFS creates the collector; Run starts it.
func NewFS(o FSOptions) (*FS, error) {
	if o.Settle <= 0 {
		o.Settle = DefaultSettle
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	w, err := fsnotify.NewBufferedWatcher(4096)
	if err != nil {
		return nil, err
	}
	f := &FS{o: o, log: o.Logger.With("collector", "fs"), w: w, rootsCh: make(chan []string, 1),
		watched: make(map[string]bool), fileOnly: make(map[string]map[string]bool), pending: make(map[string]time.Time)}
	if !o.DisableFanotify {
		if fan, err := newFanotify(); err != nil {
			f.log.Info("fanotify unavailable; using inotify with /proc attribution", "err", err)
		} else {
			f.fan = fan
		}
	}
	return f, nil
}

// Status returns watch statistics.
func (f *FS) Status() FSStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return FSStatus{Dirs: len(f.watched), Fanotify: f.fan != nil}
}

// SetRoots replaces the watch roots (hot reload); it is applied by Run.
func (f *FS) SetRoots(roots []string) {
	select {
	case <-f.rootsCh:
	default:
	}
	f.rootsCh <- append([]string(nil), roots...)
}

// Run watches until ctx is done.
func (f *FS) Run(ctx context.Context) error {
	defer f.w.Close()
	var wg sync.WaitGroup
	if f.fan != nil {
		fanCtx, cancel := context.WithCancel(ctx)
		defer func() { cancel(); wg.Wait() }()
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.fan.Run(fanCtx, f.o.Resolver.NoteWriter)
		}()
	}
	f.applyRoots(f.o.Roots)
	for _, p := range f.o.SelfFiles {
		f.addSelfFile(p)
	}
	f.log.Info("filesystem collector started", "roots", f.roots, "dirs", f.Status().Dirs, "fanotify", f.fan != nil)

	tick := time.NewTicker(f.o.Settle / 3)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			f.settle(context.WithoutCancel(ctx), true)
			return nil
		case roots := <-f.rootsCh:
			f.applyRoots(roots)
		case ev, ok := <-f.w.Events:
			if !ok {
				return nil
			}
			f.event(ctx, ev)
		case err, ok := <-f.w.Errors:
			if !ok {
				return nil
			}
			if errors.Is(err, fsnotify.ErrEventOverflow) {
				f.log.Warn("inotify queue overflow; rescanning watch roots")
				f.rescan(ctx)
				continue
			}
			f.log.Error("inotify error", "err", err)
		case <-tick.C:
			f.settle(ctx, false)
		}
	}
}

func (f *FS) event(ctx context.Context, ev fsnotify.Event) {
	p := filepath.Clean(ev.Name)
	dir := filepath.Dir(p)
	f.mu.Lock()
	if files, ok := f.fileOnly[dir]; ok && !files[p] && !f.coveredLocked(dir) {
		f.mu.Unlock()
		return
	}
	f.mu.Unlock()

	if f.fan == nil {
		// Snapshot likely writers while they are still alive (sed exits
		// right after renaming its temp file over the target).
		f.o.Resolver.Activity(dir)
	}
	if f.o.Classifier.Blacklisted(p) {
		return
	}
	switch {
	case ev.Has(fsnotify.Create):
		if fi, err := os.Lstat(p); err == nil && fi.IsDir() {
			// Files may land in a new directory before its watch exists.
			for _, file := range f.addTree(p) {
				f.enqueue(file)
			}
			return
		}
	case ev.Has(fsnotify.Remove) || ev.Has(fsnotify.Rename):
		if f.isWatched(p) {
			f.removeTree(p)
			if f.o.Known != nil {
				for _, k := range f.o.Known(ctx, p) {
					f.enqueue(k)
				}
			}
			return
		}
	}
	f.enqueue(p)
}

func (f *FS) enqueue(p string) {
	f.mu.Lock()
	f.pending[p] = f.now()
	f.mu.Unlock()
}

func (f *FS) now() time.Time { return time.Now() }

func (f *FS) settle(ctx context.Context, all bool) {
	now := f.now()
	f.mu.Lock()
	var ready []string
	for p, last := range f.pending {
		if all || now.Sub(last) >= f.o.Settle {
			ready = append(ready, p)
			delete(f.pending, p)
		}
	}
	f.mu.Unlock()
	sort.Strings(ready)
	for _, p := range ready {
		if fi, err := os.Lstat(p); err == nil && fi.IsDir() {
			continue
		}
		pid, method := f.o.Resolver.Attribute(p)
		actor, ancestry := f.o.Resolver.Actor(pid)
		if actor == nil {
			method = AttrUnknown
		}
		if isPasswdFile(p) {
			f.o.Resolver.Users().Invalidate()
		}
		if err := f.o.Handle(ctx, engine.FileEvent{Path: p, Actor: actor, Ancestry: ancestry, Attribution: method}); err != nil {
			f.log.Error("handle file event", "path", p, "err", err)
		}
	}
}

func isPasswdFile(p string) bool { return p == "/etc/passwd" }

// applyRoots reconciles watches with roots. Files under roots that appear
// after startup (a new /home/*/.ssh match, a recreated directory) are
// observed, so their content is reported; callers baseline roots added by
// configuration before passing them here.
func (f *FS) applyRoots(roots []string) {
	roots = normalizeRoots(roots)
	f.mu.Lock()
	old, started := f.roots, f.started
	f.roots, f.started = roots, true
	f.mu.Unlock()
	for _, r := range roots {
		if slices.Contains(old, r) && f.isWatched(r) {
			continue
		}
		files := f.addTree(r)
		if started {
			for _, file := range files {
				f.enqueue(file)
			}
		}
	}
	for _, r := range old {
		if !slices.Contains(roots, r) {
			f.removeTree(r)
		}
	}
}

func normalizeRoots(roots []string) []string {
	out := make([]string, 0, len(roots))
	for _, r := range roots {
		out = append(out, filepath.Clean(r))
	}
	sort.Strings(out)
	return out
}

// addTree watches dir and its non-blacklisted subdirectories, returning the
// regular files found.
func (f *FS) addTree(dir string) []string {
	var files []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == dir {
				return err
			}
			return nil
		}
		if f.o.Classifier.Blacklisted(p) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			if d.Type().IsRegular() {
				files = append(files, p)
			}
			return nil
		}
		f.addWatch(p)
		return nil
	})
	return files
}

func (f *FS) addWatch(dir string) {
	f.mu.Lock()
	already := f.watched[dir]
	f.mu.Unlock()
	if already {
		return
	}
	if err := f.w.Add(dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return
		}
		f.log.Warn("cannot watch directory", "dir", dir, "err", err)
		return
	}
	if f.fan != nil {
		if err := f.fan.Add(dir); err != nil {
			f.log.Debug("fanotify mark failed", "dir", dir, "err", err)
		}
	}
	f.mu.Lock()
	f.watched[dir] = true
	f.mu.Unlock()
}

func (f *FS) addSelfFile(p string) {
	p = filepath.Clean(p)
	dir := filepath.Dir(p)
	f.mu.Lock()
	if f.fileOnly[dir] == nil {
		f.fileOnly[dir] = make(map[string]bool)
	}
	f.fileOnly[dir][p] = true
	f.mu.Unlock()
	f.addWatch(dir)
}

// removeTree drops watches on dir and below (unless still covered by
// another root or a self file).
func (f *FS) removeTree(dir string) {
	f.mu.Lock()
	var drop []string
	for d := range f.watched {
		if (d == dir || strings.HasPrefix(d, dir+"/")) && !f.coveredLocked(d) && f.fileOnly[d] == nil {
			drop = append(drop, d)
		}
	}
	for _, d := range drop {
		delete(f.watched, d)
	}
	f.mu.Unlock()
	for _, d := range drop {
		_ = f.w.Remove(d)
		if f.fan != nil {
			f.fan.Remove(d)
		}
	}
}

// coveredLocked reports whether d is within a current root that still
// exists, or hosts a self file.
func (f *FS) coveredLocked(d string) bool {
	for _, r := range f.roots {
		if d == r || strings.HasPrefix(d, r+"/") {
			if _, err := os.Lstat(d); err == nil {
				return true
			}
		}
	}
	return false
}

func (f *FS) isWatched(dir string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.watched[dir]
}

// rescan re-observes every file under the roots after an overflow, plus
// indexed files that disappeared.
func (f *FS) rescan(ctx context.Context) {
	f.mu.Lock()
	roots := append([]string(nil), f.roots...)
	f.mu.Unlock()
	for _, r := range roots {
		for _, file := range f.addTree(r) {
			f.enqueue(file)
		}
		if f.o.Known != nil {
			for _, k := range f.o.Known(ctx, r) {
				if _, err := os.Lstat(k); errors.Is(err, fs.ErrNotExist) {
					f.enqueue(k)
				}
			}
		}
	}
}
