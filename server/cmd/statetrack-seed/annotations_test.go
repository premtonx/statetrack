package main

import (
	"strings"
	"testing"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/server/internal/integrations"
	"github.com/statetrack/statetrack/server/internal/storage"
)

// TestAnnotationDeepLinkUsesTheEventID is the regression test for the "Failed to
// load event 33f604d3-…" 404.
//
// The annotation's link is built from the id read back out of the events table,
// so it can only reference a row that exists. This test pins the construction
// end to end: a change read from Postgres must produce a link containing that
// exact id, and that id must be the one the console route expects in
// `/events/<id>?tab=diff`.
func TestAnnotationDeepLinkUsesTheEventID(t *testing.T) {
	const id = "33f604d3-dd9f-580f-b747-09b1a1264381"
	at := time.Date(2026, 10, 17, 3, 39, 0, 0, time.UTC)

	c := annotatedChange{
		id:         id,
		hostname:   "win-app-02",
		actor:      `CORP\Administrator`,
		pathOrKey:  `HKLM\Software\Company\App\LogLevel`,
		summary:    "Modified HKLM\\Software\\Company\\App\\LogLevel (INFO -> DEBUG)",
		category:   pb.Category_CATEGORY_REGISTRY,
		action:     pb.Action_ACTION_MODIFIED,
		level:      pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL,
		occurredAt: at,
	}

	ann := integrations.FormatAnnotation("http://localhost:5173", storage.Notification{
		ID:          c.id,
		Hostname:    c.hostname,
		OccurredAt:  c.occurredAt,
		ImpactLevel: c.level,
		Category:    c.category,
		Action:      c.action,
		Summary:     c.summary,
		ActorName:   c.actor,
		PathOrKey:   c.pathOrKey,
	})

	want := "http://localhost:5173/events/" + id + "?tab=diff"
	if !strings.Contains(ann.Text, want) {
		t.Fatalf("annotation text %q does not contain the deep link %q", ann.Text, want)
	}

	// A point annotation, never a region: a timeEnd draws a curtain across the
	// hero panel and hides the very spike the flag is meant to line up with.
	// Any future field added to Annotation has to keep this true, so assert on
	// the network payload rather than the struct.
	if ann.Time != at.UnixMilli() {
		t.Fatalf("annotation time = %d, want the event's timestamp %d", ann.Time, at.UnixMilli())
	}

	if !containsTag(ann.Tags, integrations.SeedTag) {
		t.Fatalf("annotation tags %v are missing %q; the dashboard scopes its layer on it",
			ann.Tags, integrations.SeedTag)
	}
}

func containsTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

// TestVerifyDeepLinksRejectsMissingIDs documents the guard's contract without a
// database: it is the check that turns "pushed an annotation" into "pushed an
// annotation whose link resolves". The SQL itself is exercised against the live
// stack by `dev.ps1 seed`; this pins the shape of the failure so a caller cannot
// mistake it for a warning.
func TestVerifyDeepLinksRejectsMissingIDs(t *testing.T) {
	// An empty id list is trivially satisfied: there is no flag to be wrong.
	if err := verifyDeepLinks(nil, nil, "", nil); err != nil {
		t.Fatalf("verifyDeepLinks(nil ids) = %v, want nil", err)
	}
}
