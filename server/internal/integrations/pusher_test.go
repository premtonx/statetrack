package integrations

import (
	"strings"
	"testing"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/server/internal/storage"
)

func TestFormatAnnotation(t *testing.T) {
	n := storage.Notification{
		ID:          "evt-1",
		Hostname:    "web-01",
		OccurredAt:  time.UnixMilli(1_700_000_000_000),
		ImpactLevel: pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL,
		Category:    pb.Category_CATEGORY_CONFIG,
		Summary:     "Modified /etc/passwd",
		ActorName:   "root",
	}
	a := FormatAnnotation("http://localhost:5173", n)
	if a.Time != 1_700_000_000_000 {
		t.Fatalf("time = %d", a.Time)
	}
	// The hover text is the whole value of a flag: level, what changed, the
	// actor and host, and the deep link. Read as one string so a change to any
	// part is caught here.
	for _, want := range []string{"[L1] Modified /etc/passwd", "root &middot; web-01", "/events/evt-1"} {
		if !strings.Contains(a.Text, want) {
			t.Fatalf("text %q missing %q", a.Text, want)
		}
	}
	wantTags := map[string]bool{
		"statetrack": true, "host:web-01": true, "level:L1": true, "category:config": true,
	}
	if len(a.Tags) != len(wantTags) {
		t.Fatalf("tags = %v", a.Tags)
	}
	for _, tag := range a.Tags {
		if !wantTags[tag] {
			t.Fatalf("unexpected tag %q", tag)
		}
	}
}

func TestNameMappings(t *testing.T) {
	if LevelName(pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT) != "L3" {
		t.Fatal("level mapping")
	}
	if CategoryName(pb.Category_CATEGORY_REGISTRY) != "registry" {
		t.Fatal("category mapping")
	}
	if ActionName(pb.Action_ACTION_UPGRADED) != "upgraded" {
		t.Fatal("action mapping")
	}
}
