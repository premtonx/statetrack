package shadow

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/statetrack/statetrack/agent/internal/limiter"
	"github.com/statetrack/statetrack/pkg/diff"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/pkg/redact"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func openStore(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newTracker(t *testing.T) (*Tracker, *clock, string) {
	t.Helper()
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	store := openStore(t, filepath.Join(t.TempDir(), "shadow"))
	tr := NewTracker(store, redact.New([]byte("salt")), TrackerOptions{DiffContext: -1, Now: clk.Now})
	return tr, clk, t.TempDir()
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func observe(t *testing.T, tr *Tracker, path string, mode Mode) *Change {
	t.Helper()
	ch, err := tr.Observe(context.Background(), path, mode)
	if err != nil {
		t.Fatalf("Observe(%s): %v", path, err)
	}
	return ch
}

func TestStorePutGetDedupAndReopen(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "shadow")
	s := openStore(t, dir)

	content := []byte("listen 80;\n")
	hash := strings.Repeat("ab", 32)
	mod := time.Unix(1_700_000_000, 123)
	for _, p := range []string{"/etc/a.conf", "/etc/b.conf"} {
		if err := s.Put(ctx, Entry{Path: p, Hash: hash, Size: 11, ModTime: mod, Mode: 0o644}, content); err != nil {
			t.Fatal(err)
		}
	}
	objs, _ := filepath.Glob(filepath.Join(dir, "objects", "ab", "*.zst"))
	if len(objs) != 1 {
		t.Fatalf("expected one deduplicated object, got %v", objs)
	}
	got, err := s.Content(hash)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("Content = %q, %v", got, err)
	}
	s.Close()

	s2 := openStore(t, dir)
	e, ok, err := s2.Get(ctx, "/etc/b.conf")
	if err != nil || !ok {
		t.Fatalf("entry lost after reopen: %v %v", ok, err)
	}
	if e.Hash != hash || e.Size != 11 || !e.ModTime.Equal(mod) || e.Mode != 0o644 || !e.HasContent {
		t.Fatalf("entry mismatch: %+v", e)
	}
	if n, _ := s2.Count(ctx); n != 2 {
		t.Fatalf("Count = %d", n)
	}
}

func TestStorePathsUnder(t *testing.T) {
	ctx := context.Background()
	s := openStore(t, t.TempDir())
	h := strings.Repeat("ab", 32)
	for _, p := range []string{"/etc", "/etc/a", "/etc/sub/b", "/etc-other/x", "/etcd", "/usr/x"} {
		if err := s.Put(ctx, Entry{Path: p, Hash: h}, nil); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.PathsUnder(ctx, "/etc/", '/')
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "/etc/a,/etc/sub/b" {
		t.Fatalf("got %v", got)
	}
	if got, _ := s.PathsUnder(ctx, "/etc", '/'); strings.Join(got, ",") != "/etc,/etc/a,/etc/sub/b" {
		t.Fatalf("got %v", got)
	}
}

func TestStoreRejectsInvalidHash(t *testing.T) {
	s := openStore(t, t.TempDir())
	for _, h := range []string{"", "../../etc/passwd", strings.Repeat("zz", 32)} {
		if _, err := s.Content(h); err == nil || err == ErrNoContent {
			t.Errorf("Content(%q) should fail validation, got %v", h, err)
		}
	}
	if _, err := s.Content(strings.Repeat("0", 64)); err != ErrNoContent {
		t.Errorf("missing object: got %v, want ErrNoContent", err)
	}
}

func TestStoreGC(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s := openStore(t, dir)
	h1, h2 := strings.Repeat("11", 32), strings.Repeat("22", 32)
	s.Put(ctx, Entry{Path: "/a", Hash: h1}, []byte("one"))
	s.Put(ctx, Entry{Path: "/b", Hash: h2}, []byte("two"))
	write(t, filepath.Join(dir, "objects", "11", "junk.tmp-123"), "partial")

	s.Delete(ctx, "/b")
	n, err := s.GC(ctx)
	if err != nil || n != 2 {
		t.Fatalf("GC removed %d (err %v), want 2 (orphan + temp)", n, err)
	}
	if _, err := s.Content(h1); err != nil {
		t.Fatalf("live object removed: %v", err)
	}
	if _, err := s.Content(h2); err != ErrNoContent {
		t.Fatalf("orphan not removed: %v", err)
	}
}

func TestTrackerCreateModifyUnchanged(t *testing.T) {
	tr, _, root := newTracker(t)
	p := filepath.Join(root, "etc", "app.conf")
	write(t, p, "port = 80\nworkers = 2\n")

	ch := observe(t, tr, p, ModeFull)
	if ch == nil || ch.Action != pb.Action_ACTION_CREATED || ch.Before != nil || ch.After == nil {
		t.Fatalf("create: %+v", ch)
	}
	if !strings.Contains(ch.Diff, "--- /dev/null\n") || !strings.Contains(ch.Diff, "+port = 80\n") {
		t.Fatalf("create diff:\n%s", ch.Diff)
	}

	if ch := observe(t, tr, p, ModeFull); ch != nil {
		t.Fatalf("unchanged file reported: %+v", ch)
	}

	write(t, p, "port = 8080\nworkers = 2\n")
	ch = observe(t, tr, p, ModeFull)
	if ch == nil || ch.Action != pb.Action_ACTION_MODIFIED || ch.Before.Hash == ch.After.Hash {
		t.Fatalf("modify: %+v", ch)
	}
	if !strings.Contains(ch.Diff, "-port = 80\n+port = 8080\n") {
		t.Fatalf("modify diff:\n%s", ch.Diff)
	}
	if ch.Before.Size != 22 || ch.After.Size != 24 {
		t.Fatalf("sizes %d -> %d", ch.Before.Size, ch.After.Size)
	}
}

func TestTrackerSedInPlaceAtomicRename(t *testing.T) {
	tr, _, root := newTracker(t)
	p := filepath.Join(root, "nginx.conf")
	write(t, p, "user www-data;\nworker_processes 2;\n")
	observe(t, tr, p, ModeFull)

	// sed -i: write a temp file in the same directory, then rename it over the target.
	tmp := filepath.Join(root, "sedAb12Cd")
	write(t, tmp, "user www-data;\nworker_processes auto;\n")
	if err := os.Rename(tmp, p); err != nil {
		t.Fatal(err)
	}
	// The collector reports both names; only the target produces a change.
	if ch := observe(t, tr, tmp, ModeFull); ch != nil {
		t.Fatalf("temp file produced a change: %+v", ch)
	}
	ch := observe(t, tr, p, ModeFull)
	if ch == nil || ch.Action != pb.Action_ACTION_MODIFIED {
		t.Fatalf("rename-over: %+v", ch)
	}
	if !strings.Contains(ch.Diff, "-worker_processes 2;\n+worker_processes auto;\n") {
		t.Fatalf("diff against shadow state wrong:\n%s", ch.Diff)
	}
}

func TestTrackerVimRenameAwayAndRecreate(t *testing.T) {
	tr, clk, root := newTracker(t)
	ctx := context.Background()
	p := filepath.Join(root, "hosts")
	write(t, p, "127.0.0.1 localhost\n")
	observe(t, tr, p, ModeFull)

	// vim (backupcopy=no): rename original to backup, write a new file.
	if err := os.Rename(p, p+"~"); err != nil {
		t.Fatal(err)
	}
	if ch := observe(t, tr, p, ModeFull); ch != nil {
		t.Fatalf("vanished file reported immediately: %+v", ch)
	}
	if !tr.PendingDelete(p) {
		t.Fatal("vanished file not pending")
	}
	clk.Advance(200 * time.Millisecond)
	write(t, p, "127.0.0.1 localhost\n10.0.0.5 db\n")
	os.Remove(p + "~")

	ch := observe(t, tr, p, ModeFull)
	if ch == nil || ch.Action != pb.Action_ACTION_MODIFIED || !strings.Contains(ch.Diff, "+10.0.0.5 db\n") {
		t.Fatalf("vim save should be one modification, got %+v", ch)
	}
	clk.Advance(5 * time.Second)
	if dels, err := tr.ConfirmDeletes(ctx, nil); err != nil || len(dels) != 0 {
		t.Fatalf("spurious delete: %+v %v", dels, err)
	}
}

func TestTrackerDeleteAfterGrace(t *testing.T) {
	tr, clk, root := newTracker(t)
	ctx := context.Background()
	p := filepath.Join(root, "app.ini")
	write(t, p, "a=1\n")
	observe(t, tr, p, ModeFull)
	os.Remove(p)
	observe(t, tr, p, ModeFull)

	clk.Advance(500 * time.Millisecond)
	if dels, _ := tr.ConfirmDeletes(ctx, nil); len(dels) != 0 {
		t.Fatalf("deleted before grace: %+v", dels)
	}
	clk.Advance(time.Second)
	dels, err := tr.ConfirmDeletes(ctx, nil)
	if err != nil || len(dels) != 1 {
		t.Fatalf("ConfirmDeletes = %+v, %v", dels, err)
	}
	d := dels[0]
	if d.Action != pb.Action_ACTION_DELETED || d.After != nil || !strings.Contains(d.Diff, "+++ /dev/null\n") ||
		!strings.Contains(d.Diff, "-a=1\n") {
		t.Fatalf("delete change: %+v\n%s", d, d.Diff)
	}
	if _, ok, _ := tr.Store().Get(ctx, p); ok {
		t.Fatal("entry not removed")
	}
	// A file that never existed in the shadow is ignored.
	if ch := observe(t, tr, filepath.Join(root, "never"), ModeFull); ch != nil || tr.PendingDelete(filepath.Join(root, "never")) {
		t.Fatal("unknown missing file tracked")
	}
}

func TestTrackerBinaryAndLargeFiles(t *testing.T) {
	tr, _, root := newTracker(t)
	bin := filepath.Join(root, "app.bin")
	write(t, bin, "\x7fELF\x00\x01")
	observe(t, tr, bin, ModeFull)
	write(t, bin, "\x7fELF\x00\x02")
	ch := observe(t, tr, bin, ModeFull)
	if ch == nil || ch.Content != limiter.ContentBinary || ch.Diff != "" || ch.DiffSkipped != "binary" ||
		ch.Before.Hash == ch.After.Hash || ch.Before.HasContent {
		t.Fatalf("binary: %+v", ch)
	}

	big := filepath.Join(root, "big.conf")
	write(t, big, strings.Repeat("x = 1\n", limiter.MaxDiffFileSize/6+10))
	ch = observe(t, tr, big, ModeFull)
	if ch == nil || ch.Content != limiter.ContentTooLarge || ch.Diff != "" || ch.After.Size <= limiter.MaxDiffFileSize {
		t.Fatalf("large: %+v", ch)
	}
	// Hash must cover the whole file, not just the retained prefix.
	write(t, big, strings.Repeat("x = 1\n", limiter.MaxDiffFileSize/6+10)+"tail\n")
	if ch2 := observe(t, tr, big, ModeFull); ch2 == nil || ch2.Before.Hash == ch2.After.Hash {
		t.Fatalf("change past 1 MiB not detected: %+v", ch2)
	}
}

func TestTrackerMetadataMode(t *testing.T) {
	tr, _, root := newTracker(t)
	p := filepath.Join(root, "index.html")
	write(t, p, "<h1>v1</h1>\n")
	observe(t, tr, p, ModeMetadata)
	write(t, p, "<h1>v2</h1>\n")
	ch := observe(t, tr, p, ModeMetadata)
	if ch == nil || ch.Diff != "" || ch.DiffSkipped != "metadata_only" || ch.After.HasContent {
		t.Fatalf("metadata mode: %+v", ch)
	}
	// Promoted to full mode later: no old snapshot to diff against.
	write(t, p, "<h1>v3</h1>\n")
	ch = observe(t, tr, p, ModeFull)
	if ch.DiffSkipped != "no_previous_snapshot" || !ch.After.HasContent {
		t.Fatalf("promotion: %+v", ch)
	}
}

func TestTrackerPermissionOnlyChange(t *testing.T) {
	tr, _, root := newTracker(t)
	p := filepath.Join(root, "secret.key")
	write(t, p, "x\n")
	observe(t, tr, p, ModeFull)
	newMode := fs.FileMode(0o600)
	if runtime.GOOS == "windows" {
		newMode = 0o444 // Windows only supports the read-only bit
	}
	if err := os.Chmod(p, newMode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(p, 0o644) })
	ch := observe(t, tr, p, ModeFull)
	if ch == nil || !ch.ModeChanged || ch.Action != pb.Action_ACTION_MODIFIED || ch.Diff != "" {
		t.Fatalf("chmod: %+v", ch)
	}
}

func TestTrackerNeverPersistsSecrets(t *testing.T) {
	tr, _, root := newTracker(t)
	shadowDir := filepath.Dir(tr.Store().objects)
	p := filepath.Join(root, "db.env")
	write(t, p, "DB_HOST=db\nDB_PASSWORD=hunter2-old\n")
	observe(t, tr, p, ModeFull)
	write(t, p, "DB_HOST=db\nDB_PASSWORD=hunter2-new\n")
	ch := observe(t, tr, p, ModeFull)

	s := redact.New([]byte("salt"))
	if strings.Contains(ch.Diff, "hunter2") ||
		!strings.Contains(ch.Diff, "-DB_PASSWORD="+s.Stub("hunter2-old")) ||
		!strings.Contains(ch.Diff, "+DB_PASSWORD="+s.Stub("hunter2-new")) {
		t.Fatalf("diff not scrubbed:\n%s", ch.Diff)
	}
	err := filepath.WalkDir(shadowDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, _ := os.ReadFile(path)
		if strings.HasSuffix(path, ".zst") {
			if raw, err = diff.Decompress(raw); err != nil {
				t.Errorf("corrupt object %s: %v", path, err)
			}
		}
		if bytes.Contains(raw, []byte("hunter2")) {
			t.Errorf("secret persisted in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTrackerIgnoresDirectoriesAndSymlinks(t *testing.T) {
	tr, _, root := newTracker(t)
	if ch := observe(t, tr, root, ModeFull); ch != nil {
		t.Fatalf("directory produced change: %+v", ch)
	}
	target := filepath.Join(root, "real.conf")
	write(t, target, "a\n")
	link := filepath.Join(root, "link.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks not permitted:", err)
	}
	if ch := observe(t, tr, link, ModeFull); ch != nil {
		t.Fatalf("symlink produced change: %+v", ch)
	}
}
