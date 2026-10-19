//go:build windows

package windows

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

func TestFSEmitsCreateEvent(t *testing.T) {
	te := newTestEngine(t)
	root := filepath.Join(te.dir, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}

	fs, err := NewFS(FSOptions{
		Roots:      []string{root},
		Classifier: te.class,
		Attrib:     Attributor{Notes: &Notes{TTL: DefaultNoteTTL}},
		Handle:     te.engine.HandleFile,
		Logger:     testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = fs.Run(ctx) }()

	waitFor(t, func() bool { return fs.Status() > 0 }, 5*time.Second)

	target := filepath.Join(root, "web.config")
	if err := os.WriteFile(target, []byte("setting=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ev := waitEvent(t, te, 5*time.Second, func(e *pb.MutationEvent) bool {
		return e.GetTarget().GetPathOrKey() == target
	})
	if ev.GetAction() != pb.Action_ACTION_CREATED {
		t.Fatalf("action = %v, want CREATED", ev.GetAction())
	}
	if ev.GetCategory() != pb.Category_CATEGORY_CONFIG {
		t.Fatalf("category = %v, want CONFIG", ev.GetCategory())
	}
	if !containsFold(unzip(t, ev), "setting=1") {
		t.Fatalf("diff = %q", unzip(t, ev))
	}
}

func TestFSEmitsModifyEvent(t *testing.T) {
	te := newTestEngine(t)
	root := filepath.Join(te.dir, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}

	fs, err := NewFS(FSOptions{
		Roots:      []string{root},
		Classifier: te.class,
		Attrib:     Attributor{Notes: &Notes{TTL: DefaultNoteTTL}},
		Handle:     te.engine.HandleFile,
		Logger:     testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = fs.Run(ctx) }()

	waitFor(t, func() bool { return fs.Status() > 0 }, 5*time.Second)

	// The FS collector only reports files that change after startup, so the
	// initial write is observed as a CREATE (pre-existing content is handled
	// by the app baseline, not the collector).
	target := filepath.Join(root, "web.config")
	if err := os.WriteFile(target, []byte("old=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, te, 5*time.Second, func(e *pb.MutationEvent) bool {
		return e.GetTarget().GetPathOrKey() == target && e.GetAction() == pb.Action_ACTION_CREATED
	})

	if err := os.WriteFile(target, []byte("old=true\nnew=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ev := waitEvent(t, te, 5*time.Second, func(e *pb.MutationEvent) bool {
		return e.GetTarget().GetPathOrKey() == target && e.GetAction() == pb.Action_ACTION_MODIFIED
	})
	if ev.GetCategory() != pb.Category_CATEGORY_CONFIG {
		t.Fatalf("category = %v, want CONFIG", ev.GetCategory())
	}
	if !containsFold(unzip(t, ev), "new=true") {
		t.Fatalf("diff = %q", unzip(t, ev))
	}
}
