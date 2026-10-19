//go:build windows

package windows

import (
	"context"
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

func TestRegistryEmitsCreateEvent(t *testing.T) {
	key := fmt.Sprintf(`Software\StateTrackTest\%d`, time.Now().UnixNano())
	rootPath := `HKCU\` + key
	// Mark the test key critical so a full content diff is produced (a
	// drift-level registry key is metadata-only by design).
	te := newTestEngine(t, rootPath+`\**`)

	// Create the watched root key first.
	if _, _, err := registry.CreateKey(registry.CURRENT_USER, key, registry.ALL_ACCESS); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.DeleteKey(registry.CURRENT_USER, key) })

	reg := NewRegistry(RegistryOptions{
		Keys:       []string{rootPath},
		Classifier: te.class,
		Attrib:     Attributor{Notes: &Notes{TTL: DefaultNoteTTL}},
		Handle:     te.engine.HandleDoc,
		Seed:       te.engine.SeedDoc,
		Known: func(ctx context.Context, k string) []string {
			p, _ := te.store.PathsUnder(ctx, k, '\\')
			return p
		},
		Logger: testLogger(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = reg.Run(ctx) }()

	// Baseline seeds the root key before watching.
	waitFor(t, func() bool {
		_, ok, _ := te.store.Get(context.Background(), rootPath)
		return ok
	}, 5*time.Second)

	childPath := rootPath + `\Child`
	child, _, err := registry.CreateKey(registry.CURRENT_USER, key+`\Child`, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	if err := child.SetStringValue("Name", "alice"); err != nil {
		t.Fatal(err)
	}
	child.Close()

	// Deterministic rescan; the live RegNotifyChangeKeyValue path drives
	// this automatically on a real host.
	reg.Rescan(ctx)

	ev := waitEvent(t, te, 5*time.Second, func(e *pb.MutationEvent) bool {
		return e.GetTarget().GetPathOrKey() == childPath
	})
	if ev.GetAction() != pb.Action_ACTION_CREATED {
		t.Fatalf("action = %v, want CREATED", ev.GetAction())
	}
	if ev.GetCategory() != pb.Category_CATEGORY_REGISTRY {
		t.Fatalf("category = %v, want REGISTRY", ev.GetCategory())
	}
	if ev.GetTarget().GetTargetType() != "registry" {
		t.Fatalf("target type = %q, want registry", ev.GetTarget().GetTargetType())
	}
	diff := unzip(t, ev)
	if !containsFold(diff, "Name") || !containsFold(diff, "alice") {
		t.Fatalf("diff = %q", diff)
	}
}

func TestRegistryEmitsModifyEvent(t *testing.T) {
	key := fmt.Sprintf(`Software\StateTrackTest\%d`, time.Now().UnixNano())
	rootPath := `HKCU\` + key
	childPath := rootPath + `\Child`
	te := newTestEngine(t, rootPath+`\**`)

	k, _, err := registry.CreateKey(registry.CURRENT_USER, key+`\Child`, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.SetStringValue("Name", "bob"); err != nil {
		t.Fatal(err)
	}
	k.Close()
	t.Cleanup(func() { _ = registry.DeleteKey(registry.CURRENT_USER, key) })

	reg := NewRegistry(RegistryOptions{
		Keys:       []string{rootPath},
		Classifier: te.class,
		Attrib:     Attributor{Notes: &Notes{TTL: DefaultNoteTTL}},
		Handle:     te.engine.HandleDoc,
		Seed:       te.engine.SeedDoc,
		Known: func(ctx context.Context, k string) []string {
			p, _ := te.store.PathsUnder(ctx, k, '\\')
			return p
		},
		Logger: testLogger(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = reg.Run(ctx) }()

	waitFor(t, func() bool {
		_, ok, _ := te.store.Get(context.Background(), childPath)
		return ok
	}, 5*time.Second)

	// Change the value.
	k2, err := registry.OpenKey(registry.CURRENT_USER, key+`\Child`, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	if err := k2.SetStringValue("Name", "alice"); err != nil {
		t.Fatal(err)
	}
	k2.Close()

	reg.Rescan(ctx)

	ev := waitEvent(t, te, 5*time.Second, func(e *pb.MutationEvent) bool {
		return e.GetTarget().GetPathOrKey() == childPath && e.GetAction() == pb.Action_ACTION_MODIFIED
	})
	if ev.GetCategory() != pb.Category_CATEGORY_REGISTRY {
		t.Fatalf("category = %v, want REGISTRY", ev.GetCategory())
	}
	diff := unzip(t, ev)
	if !containsFold(diff, "bob") || !containsFold(diff, "alice") {
		t.Fatalf("diff = %q", diff)
	}
}
