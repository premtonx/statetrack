package integrations

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/server/internal/storage"
)

// fakeGrafana is a minimal annotation API: it records the call order so a test
// can assert that a purge happens *before* the pushes, which is what stops a
// stale flag from outliving the row it links to.
type fakeGrafana struct {
	mu         sync.Mutex
	calls      []string
	deleted    []int64
	pushed     []Annotation
	listRows   string
	taggedRows string
	failPosts  bool
}

func (f *fakeGrafana) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()

		path := r.URL.Path
		f.calls = append(f.calls, r.Method+" "+path)

		switch {
		case r.Method == http.MethodGet && path == "/api/health":
			_, _ = io.WriteString(w, `{"database":"ok"}`)

		case r.Method == http.MethodGet && path == "/api/annotations":
			// Grafana filters server-side by tag; an unfiltered query returns
			// everything in the window. Modelling both is what makes the test
			// able to catch a client that would delete a foreign annotation.
			rows := f.listRows
			if rows == "" {
				rows = "[]"
			}
			if r.URL.Query().Get("tags") != "" {
				rows = f.taggedRows
				if rows == "" {
					rows = "[]"
				}
			}
			_, _ = io.WriteString(w, rows)

		case r.Method == http.MethodDelete:
			var id int64
			for i := len(path) - 1; i >= 0; i-- {
				if path[i] == '/' {
					_, _ = fmtSscan(path[i+1:], &id)
					break
				}
			}
			f.deleted = append(f.deleted, id)
			_, _ = io.WriteString(w, `{"message":"deleted"}`)

		case r.Method == http.MethodPost && path == "/api/annotations":
			if f.failPosts {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"message":"rejected"}`)
				return
			}
			var ann Annotation
			_ = json.NewDecoder(r.Body).Decode(&ann)
			f.pushed = append(f.pushed, ann)
			_, _ = io.WriteString(w, `{"id":1,"message":"ok"}`)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func fmtSscan(s string, out *int64) (int, error) {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, nil
		}
		n = n*10 + int64(c-'0')
	}
	*out = n
	return 1, nil
}

// TestAnnotationClientPurgesBeforePushing pins the ordering that keeps deep
// links valid. Pushing first and cleaning afterwards leaves a window where a
// viewer sees both the old and the new flag, and — because the old flag's row
// has already been deleted — a link that 404s.
func TestAnnotationClientPurgesBeforePushing(t *testing.T) {
	fake := &fakeGrafana{
		// The tag query finds nothing (older flags carried no tag), so the test
		// also proves the text-based fallback is what catches them.
		listRows: `[{"id":7,"text":"<a href='http://x/events/old'>old</a>"},{"id":8,"text":"unrelated"}]`,
	}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	c := NewAnnotationClient(srv.URL, "admin", "admin", "", 5*time.Second)
	removed, err := c.Purge(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	// Only id 7 carries an events link; id 8 is somebody else's annotation.
	if removed != 1 {
		t.Fatalf("purged %d annotations, want 1 (only the StateTrack flag)", removed)
	}
	if len(fake.deleted) != 1 || fake.deleted[0] != 7 {
		t.Fatalf("deleted %v, want [7]", fake.deleted)
	}

	if _, err := c.Create(context.Background(), FormatAnnotation(srv.URL,
		storage.Notification{
			ID: "33f604d3-dd9f-580f-b747-09b1a1264381", Hostname: "win-app-02",
			OccurredAt: time.Now(), ImpactLevel: pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL,
			Category: pb.Category_CATEGORY_REGISTRY, Summary: "LogLevel",
		})); err != nil {
		t.Fatalf("create: %v", err)
	}

	if len(fake.calls) < 2 {
		t.Fatalf("calls = %v", fake.calls)
	}
	last := fake.calls[len(fake.calls)-1]
	if !strings.HasPrefix(last, "POST /api/annotations") {
		t.Fatalf("last call = %q; the push must come after the purge", last)
	}
	if len(fake.pushed) != 1 {
		t.Fatalf("pushed %d annotations, want 1", len(fake.pushed))
	}
	if !strings.Contains(fake.pushed[0].Text, "33f604d3-dd9f-580f-b747-09b1a1264381") {
		t.Fatalf("annotation text %q does not link to the event that was pushed", fake.pushed[0].Text)
	}
}

// TestAnnotationClientCreateFailsLoudly covers the case that used to be silent:
// a push Grafana rejects still has to surface, otherwise the seeder reports
// "annotations pushed" for flags that are not on the dashboard.
func TestAnnotationClientCreateFailsLoudly(t *testing.T) {
	fake := &fakeGrafana{failPosts: true}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	c := NewAnnotationClient(srv.URL, "admin", "admin", "", 5*time.Second)
	if _, err := c.Create(context.Background(), Annotation{Time: 1, Text: "x"}); err == nil {
		t.Fatal("Create returned no error for a 400 response")
	}
}

// TestAnnotationClientHealthReportsUnreachable keeps the demo contract honest:
// the seeder must be able to tell "Grafana is not running" from "Grafana
// accepted my flags", so it can warn instead of failing the whole seed.
func TestAnnotationClientHealthReportsUnreachable(t *testing.T) {
	c := NewAnnotationClient("http://127.0.0.1:1", "", "", "", 200*time.Millisecond)
	if err := c.Health(context.Background()); err == nil {
		t.Fatal("Health returned nil for an unreachable port")
	}
}
