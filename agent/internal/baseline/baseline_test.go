package baseline

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/statetrack/statetrack/agent/internal/shadow"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/pkg/redact"
)

type testPolicy struct{}

func (testPolicy) Skip(p string) bool {
	return filepath.Base(p) == "cache" || strings.HasSuffix(p, ".log")
}

func (testPolicy) Mode(p string) shadow.Mode {
	if strings.Contains(filepath.ToSlash(p), "/www/") {
		return shadow.ModeMetadata
	}
	return shadow.ModeFull
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

func setup(t *testing.T) (*Walker, *shadow.Tracker, string) {
	t.Helper()
	store, err := shadow.Open(context.Background(), filepath.Join(t.TempDir(), "shadow"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	tr := shadow.NewTracker(store, redact.New([]byte("salt")), shadow.TrackerOptions{DiffContext: -1})
	return &Walker{Tracker: tr, Policy: testPolicy{}}, tr, t.TempDir()
}

func TestBaselineSeedsSilentlyThenDiffsAgainstBaseline(t *testing.T) {
	ctx := context.Background()
	w, tr, root := setup(t)
	etc := filepath.Join(root, "etc")
	write(t, filepath.Join(etc, "nginx", "nginx.conf"), "worker_processes 2;\n")
	write(t, filepath.Join(etc, "hosts"), "127.0.0.1 localhost\n")
	write(t, filepath.Join(etc, "cache", "big.bin"), "ignored")
	write(t, filepath.Join(etc, "app.log"), "ignored")
	write(t, filepath.Join(root, "www", "index.html"), "<h1>hi</h1>\n")

	st, err := w.Run(ctx, []string{etc, filepath.Join(root, "www")})
	if err != nil {
		t.Fatal(err)
	}
	if st.Files != 3 || st.RootsWalked != 2 || st.Skipped != 2 || st.Errors != 0 {
		t.Fatalf("stats: %+v", st)
	}

	// Pre-existing files must not surface as creations.
	for _, p := range []string{filepath.Join(etc, "nginx", "nginx.conf"), filepath.Join(etc, "hosts")} {
		if ch, err := tr.Observe(ctx, p, shadow.ModeFull); err != nil || ch != nil {
			t.Fatalf("baselined file %s reported change %+v (%v)", p, ch, err)
		}
	}

	// The first real edit diffs against the Day-0 content.
	conf := filepath.Join(etc, "nginx", "nginx.conf")
	write(t, conf, "worker_processes auto;\n")
	ch, err := tr.Observe(ctx, conf, shadow.ModeFull)
	if err != nil || ch == nil || ch.Action != pb.Action_ACTION_MODIFIED ||
		!strings.Contains(ch.Diff, "-worker_processes 2;\n+worker_processes auto;\n") {
		t.Fatalf("post-baseline edit: %+v %v", ch, err)
	}

	// Skipped paths were never indexed.
	if _, ok, _ := tr.Store().Get(ctx, filepath.Join(etc, "cache", "big.bin")); ok {
		t.Fatal("skipped directory was indexed")
	}
	// Metadata-mode roots store hashes only.
	e, ok, _ := tr.Store().Get(ctx, filepath.Join(root, "www", "index.html"))
	if !ok || e.HasContent {
		t.Fatalf("metadata-mode entry: %+v %v", e, ok)
	}
}

func TestBaselineRunsOncePerRoot(t *testing.T) {
	ctx := context.Background()
	w, _, root := setup(t)
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	write(t, filepath.Join(a, "1.conf"), "1\n")
	write(t, filepath.Join(b, "2.conf"), "2\n")

	if st, err := w.Run(ctx, []string{a}); err != nil || st.RootsWalked != 1 {
		t.Fatalf("first run: %+v %v", st, err)
	}
	// Restart with an extra root: only the new root is walked.
	st, err := w.Run(ctx, []string{a, b})
	if err != nil || st.RootsWalked != 1 || st.RootsSkipped != 1 || st.Files != 1 {
		t.Fatalf("second run: %+v %v", st, err)
	}
	if done, _ := w.Done(ctx, b+string(filepath.Separator)); !done {
		t.Fatal("root not marked done (path not cleaned?)")
	}
}

func TestBaselineInterruptedIsNotMarkedDone(t *testing.T) {
	w, _, root := setup(t)
	for i := 0; i < 20; i++ {
		write(t, filepath.Join(root, "etc", "f"+string(rune('a'+i))+".conf"), "x\n")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := w.Run(ctx, []string{filepath.Join(root, "etc")}); err == nil {
		t.Fatal("expected cancellation error")
	}
	if done, _ := w.Done(context.Background(), filepath.Join(root, "etc")); done {
		t.Fatal("interrupted baseline marked complete")
	}
	st, err := w.Run(context.Background(), []string{filepath.Join(root, "etc")})
	if err != nil || st.Files != 20 {
		t.Fatalf("resume: %+v %v", st, err)
	}
}

func TestBaselineMissingRoot(t *testing.T) {
	w, _, root := setup(t)
	st, err := w.Run(context.Background(), []string{filepath.Join(root, "does-not-exist")})
	if err != nil || st.Errors != 0 || st.RootsWalked != 1 {
		t.Fatalf("missing root: %+v %v", st, err)
	}
}

func TestBaselineSeedIsIdempotent(t *testing.T) {
	ctx := context.Background()
	w, tr, root := setup(t)
	p := filepath.Join(root, "etc", "x.conf")
	write(t, p, "v1\n")
	if _, err := w.Run(ctx, []string{filepath.Join(root, "etc")}); err != nil {
		t.Fatal(err)
	}
	before, _, _ := tr.Store().Get(ctx, p)
	if ok, err := tr.Seed(ctx, p, shadow.ModeFull); !ok || err != nil {
		t.Fatalf("Seed: %v %v", ok, err)
	}
	after, _, _ := tr.Store().Get(ctx, p)
	if before.Hash != after.Hash || !before.UpdatedAt.Equal(after.UpdatedAt) {
		t.Fatal("re-seeding an unchanged file rewrote its entry")
	}
}
