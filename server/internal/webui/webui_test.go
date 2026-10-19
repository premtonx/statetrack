package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A checkout that has never run a web build embeds only the placeholder
// explainer. Booting must still serve something at "/" — a 404 there is the
// most confusing possible first impression for someone who just ran `go run`.
//
// What is embedded is decided at compile time, so a developer who has run
// `scripts/release.sh` (which stages `web/dist` into this directory) or a CI
// image build has a *real* console embedded and this assertion cannot hold.
// The two states are both legitimate, so the test asserts whichever one this
// binary was built with instead of failing on a clean checkout artifact.
func TestHandlerServesSomethingAtEveryRoute(t *testing.T) {
	h, err := Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	for _, path := range []string{"/", "/servers", "/drift"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", path, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
			t.Fatalf("%s: Content-Type = %q, want text/html", path, got)
		}
		body := rec.Body.String()
		if Available() {
			if !strings.Contains(body, "<div id=\"root\"") {
				t.Fatalf("%s: a built console is embedded but the body is not its shell", path)
			}
			continue
		}
		if !strings.Contains(body, "statetrack-placeholder") {
			t.Fatalf("%s: placeholder marker missing from body", path)
		}
		if !strings.Contains(body, "npm run build") {
			t.Fatalf("%s: body does not say how to build the console", path)
		}
	}
}

// The SPA fallback must not swallow anything under /api: a mistyped endpoint has
// to 404 as JSON-less 404, not return index.html for the console to fail parsing.
// The server mounts the API ahead of this handler, so the check here is that the
// console handler leaves unknown paths to the fallback while GET is required.
func TestHandlerRejectsWrites(t *testing.T) {
	h, err := Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /: status = %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("Allow = %q, want %q", got, "GET, HEAD")
	}
}
