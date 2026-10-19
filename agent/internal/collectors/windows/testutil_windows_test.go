//go:build windows

package windows

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/statetrack/statetrack/agent/internal/debouncer"
	"github.com/statetrack/statetrack/agent/internal/engine"
	"github.com/statetrack/statetrack/agent/internal/limiter"
	"github.com/statetrack/statetrack/agent/internal/shadow"
	"github.com/statetrack/statetrack/agent/internal/spool"
	"github.com/statetrack/statetrack/pkg/diff"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/pkg/redact"
)

// testEngine is a minimal engine (shadow + spool + classifier) wired the
// same way app.open does, used by the native collector tests to assert the
// normalized MutationEvent a collector produces.
type testEngine struct {
	engine *engine.Engine
	spool  *spool.Spool
	store  *shadow.Store
	class  *limiter.Classifier
	dir    string
}

func newTestEngine(t *testing.T, extraCritical ...string) *testEngine {
	t.Helper()
	dir := t.TempDir()
	ctx := context.Background()

	store, err := shadow.Open(ctx, filepath.Join(dir, "shadow"))
	if err != nil {
		t.Fatal(err)
	}
	sp, err := spool.Open(ctx, filepath.Join(dir, "spool.db"), spool.Options{MaxBytes: 1 << 20})
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	scrubber := redact.New([]byte("0123456789abcdef"))
	tracker := shadow.NewTracker(store, scrubber, shadow.TrackerOptions{})
	class, err := limiter.NewClassifier(limiter.ClassifierConfig{ExtraCritical: extraCritical})
	if err != nil {
		t.Fatal(err)
	}
	e := &engine.Engine{
		HostID:     "test-host",
		Classifier: class,
		Breaker:    limiter.NewBreaker(limiter.DefaultBreakerConfig()),
		Tracker:    tracker,
		Debouncer:  debouncer.New(debouncer.Config{HostID: "test-host"}),
		Spool:      sp,
	}
	t.Cleanup(func() { sp.Close(); store.Close() })
	return &testEngine{engine: e, spool: sp, store: store, class: class, dir: dir}
}

func (e *testEngine) events() []*pb.MutationEvent {
	evs, err := e.spool.ReadBatch(context.Background(), 10000, 0)
	if err != nil {
		return nil
	}
	return evs
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// waitFor polls cond until it is true or the timeout elapses.
func waitFor(t *testing.T, cond func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

// waitEvent polls the spool for the first event matching match.
func waitEvent(t *testing.T, te *testEngine, timeout time.Duration, match func(*pb.MutationEvent) bool) *pb.MutationEvent {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, ev := range te.events() {
			if match(ev) {
				return ev
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no matching event within %s", timeout)
	return nil
}

// unzip decompresses the event's unified diff.
func unzip(t *testing.T, ev *pb.MutationEvent) string {
	t.Helper()
	if len(ev.UnifiedDiffZstd) == 0 {
		t.Fatalf("%s: no diff", ev.Summary)
	}
	s, err := diff.DecompressString(ev.UnifiedDiffZstd)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
