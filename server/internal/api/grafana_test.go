package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/server/internal/integrations"
)

func TestParseGrafanaTime(t *testing.T) {
	t.Run("epoch milliseconds", func(t *testing.T) {
		got, err := parseGrafanaTime("1760649660000")
		if err != nil {
			t.Fatal(err)
		}
		if got.UnixMilli() != 1760649660000 {
			t.Fatalf("got %d", got.UnixMilli())
		}
	})

	t.Run("rfc3339", func(t *testing.T) {
		got, err := parseGrafanaTime("2026-10-15T19:51:00Z")
		if err != nil {
			t.Fatal(err)
		}
		want := time.Date(2026, 10, 15, 19, 51, 0, 0, time.UTC)
		if !got.Equal(want) {
			t.Fatalf("got %s, want %s", got, want)
		}
	})

	t.Run("relative now", func(t *testing.T) {
		before := time.Now().UTC()
		got, err := parseGrafanaTime("now")
		if err != nil {
			t.Fatal(err)
		}
		if got.Before(before.Add(-time.Second)) || got.After(time.Now().UTC().Add(time.Second)) {
			t.Fatalf("now resolved to %s", got)
		}
	})

	t.Run("relative now-6h", func(t *testing.T) {
		got, err := parseGrafanaTime("now-6h")
		if err != nil {
			t.Fatal(err)
		}
		want := time.Now().UTC().Add(-6 * time.Hour)
		if diff := got.Sub(want); diff > time.Second || diff < -time.Second {
			t.Fatalf("now-6h resolved to %s, want ~%s", got, want)
		}
	})

	t.Run("empty means open bound", func(t *testing.T) {
		got, err := parseGrafanaTime("   ")
		if err != nil {
			t.Fatal(err)
		}
		// A zero time maps to SQL NULL, which leaves that side of the range open.
		if !got.IsZero() {
			t.Fatalf("got %s, want the zero time", got)
		}
	})

	t.Run("garbage is an error", func(t *testing.T) {
		for _, bad := range []string{"yesterday", "now-", "15/10/2026", "now-3w"} {
			if _, err := parseGrafanaTime(bad); err == nil {
				t.Fatalf("%q was accepted", bad)
			}
		}
	})
}

func TestDecodeJSON(t *testing.T) {
	t.Run("empty body is a no-op", func(t *testing.T) {
		var dst struct {
			URL *string `json:"url"`
		}
		req := httptest.NewRequest("PUT", "/x", strings.NewReader(""))
		if err := decodeJSON(req, &dst); err != nil {
			t.Fatalf("empty body should be accepted as a partial update: %v", err)
		}
		if dst.URL != nil {
			t.Fatal("empty body produced a value")
		}
	})

	t.Run("unknown fields are ignored", func(t *testing.T) {
		// The console and the server version independently; a newer console
		// sending an extra field must not break an older server.
		var dst struct {
			URL *string `json:"url"`
		}
		req := httptest.NewRequest("PUT", "/x",
			strings.NewReader(`{"url":"http://g","future_toggle":true}`))
		if err := decodeJSON(req, &dst); err != nil {
			t.Fatal(err)
		}
		if dst.URL == nil || *dst.URL != "http://g" {
			t.Fatalf("url = %v", dst.URL)
		}
	})

	t.Run("malformed json is rejected", func(t *testing.T) {
		var dst map[string]any
		req := httptest.NewRequest("PUT", "/x", strings.NewReader(`{"url":`))
		if err := decodeJSON(req, &dst); err == nil {
			t.Fatal("truncated JSON was accepted")
		}
	})

	t.Run("oversized body is rejected", func(t *testing.T) {
		var dst struct {
			URL *string `json:"url"`
		}
		huge := `{"url":"` + strings.Repeat("a", 2<<20) + `"}`
		req := httptest.NewRequest("PUT", "/x", strings.NewReader(huge))
		// The limit reader truncates, so the JSON is invalid rather than
		// allocating gigabytes.
		if err := decodeJSON(req, &dst); err == nil {
			t.Fatal("a 2 MiB body was accepted")
		}
	})
}

func TestPrettyJSON(t *testing.T) {
	got := prettyJSON([]byte(`{"a":1,"b":[2,3]}`))
	if !strings.Contains(got, "\n") {
		t.Fatalf("output is not indented: %q", got)
	}
	var round map[string]any
	if err := json.Unmarshal([]byte(got), &round); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	// Invalid input must come back unchanged rather than as an empty string,
	// so the console still shows the operator something.
	if raw := "not json"; prettyJSON([]byte(raw)) != raw {
		t.Fatalf("invalid input was mangled")
	}
}

func TestSampleEvent(t *testing.T) {
	ev := sampleEvent("")
	if ev.Level != pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL {
		t.Fatalf("default sample level = %v, want L1", ev.Level)
	}
	// A test message must exercise the same fields production does, otherwise
	// it cannot reveal a formatting problem. DeepLink is filled in by the
	// handler (it needs the console base URL), so it is asserted there.
	if ev.Actor == "" || ev.Tool == "" || ev.Target == "" || ev.ID == "" {
		t.Fatalf("sample is missing fields the real payload fills: %+v", ev)
	}

	storm := sampleEvent("storm")
	if !storm.IsStorm {
		t.Fatal("the storm sample is not flagged as a storm")
	}
	if storm.SuppressedMutations == 0 {
		t.Fatal("the storm sample reports no suppressed mutations")
	}
}

// TestWebhookTestHandlerFillsDeepLink pins the property that makes the console's
// "Test notification" button meaningful: the message it sends carries a working
// deep link, so a broken template is visible before it is relied on.
func TestWebhookTestHandlerFillsDeepLink(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = readAllBody(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := &Server{OrgID: "org", UIBaseURL: "http://console:5173"}
	body := `{"provider":"teams","url":"` + srv.URL + `"}`
	rec := httptest.NewRecorder()
	s.webhookTest(rec, httptest.NewRequest("POST", "/api/v1/integrations/webhooks/test", strings.NewReader(body)))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(string(received), "http://console:5173/events/") {
		t.Fatalf("sample notification has no console deep link:\n%s", received)
	}
	if !strings.Contains(string(received), "?tab=diff") {
		t.Fatalf("sample deep link does not open the diff drawer:\n%s", received)
	}

	var resp webhookTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if !resp.OK || resp.Status != http.StatusOK {
		t.Fatalf("response = %+v", resp)
	}
	if resp.Rendered == "" {
		t.Fatal("the rendered body was not echoed back for inspection")
	}
}

func TestWebhookTestHandlerSignsGenericWebhook(t *testing.T) {
	var (
		received  []byte
		signature string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = readAllBody(r)
		signature = r.Header.Get(integrations.SignatureHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := &Server{OrgID: "org", UIBaseURL: "http://console:5173"}
	// The secret travels in the URL so the console needs only one field.
	body := `{"provider":"webhook","url":"` + srv.URL + `?secret=shhh&tag=siem"}`
	rec := httptest.NewRecorder()
	s.webhookTest(rec, httptest.NewRequest("POST", "/api/v1/integrations/webhooks/test", strings.NewReader(body)))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !integrations.VerifySignature("shhh", received, signature) {
		t.Fatalf("the delivered signature does not verify; sig=%q", signature)
	}

	var resp webhookTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Signature == "" {
		t.Fatal("the signature was not echoed for the receiver's author to compare")
	}
}

func TestWebhookTestHandlerRejectsBadInput(t *testing.T) {
	s := &Server{OrgID: "org"}

	cases := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{"missing url", `{"provider":"slack"}`, http.StatusBadRequest},
		{"unknown provider", `{"provider":"carrier-pigeon","url":"http://x"}`, http.StatusBadRequest},
		{"malformed json", `{"provider":`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			s.webhookTest(rec, httptest.NewRequest("POST", "/x", strings.NewReader(tc.body)))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

// TestWebhookTestHandlerReportsProviderRejection checks that a provider saying
// "no" is a 502 with the provider's words, not a 200.
func TestWebhookTestHandlerReportsProviderRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_webhook"}`))
	}))
	defer srv.Close()

	s := &Server{OrgID: "org"}
	body := `{"provider":"slack","url":"` + srv.URL + `"}`
	rec := httptest.NewRecorder()
	s.webhookTest(rec, httptest.NewRequest("POST", "/x", strings.NewReader(body)))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	var resp webhookTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.OK {
		t.Fatal("a rejection was reported as ok")
	}
	if !strings.Contains(resp.Detail, "invalid_webhook") {
		t.Fatalf("detail does not carry the provider's message: %q", resp.Detail)
	}
}

// readAllBody drains a request body in the test harness.
func readAllBody(r *http.Request) ([]byte, error) {
	return io.ReadAll(r.Body)
}

func TestLevelLabel(t *testing.T) {
	cases := map[int32]string{1: "L1", 2: "L2", 3: "L3", 4: "L4", 0: "L0", 99: "L0"}
	for level, want := range cases {
		if got := levelLabel(level); got != want {
			t.Fatalf("levelLabel(%d) = %q, want %q", level, got, want)
		}
	}
}

// TestProbeGrafanaAgainstStubServer exercises the connectivity check's
// branching without a real Grafana instance.
func TestProbeGrafanaAgainstStubServer(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantOK     bool
		wantDetail string
	}{
		{
			name:       "healthy grafana",
			status:     http.StatusOK,
			body:       `{"database":"ok","version":"11.2.0"}`,
			wantOK:     true,
			wantDetail: "version 11.2.0",
		},
		{
			name:       "login page behind a proxy",
			status:     http.StatusOK,
			body:       `<html><body>Sign in</body></html>`,
			wantOK:     false,
			wantDetail: "not Grafana's health JSON",
		},
		{
			name:       "not grafana",
			status:     http.StatusNotFound,
			body:       `{"message":"not found"}`,
			wantOK:     false,
			wantDetail: "404",
		},
		{
			name:       "token rejected",
			status:     http.StatusUnauthorized,
			body:       `{"message":"Unauthorized"}`,
			wantOK:     false,
			wantDetail: "rejected the API token",
		},
		{
			name:       "server error",
			status:     http.StatusInternalServerError,
			body:       `oops`,
			wantOK:     false,
			wantDetail: "HTTP 500",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seenAuth string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seenAuth = r.Header.Get("Authorization")
				if r.URL.Path != grafanaHealthPath {
					t.Errorf("probe hit %q, want %q", r.URL.Path, grafanaHealthPath)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			ok, detail, version := probeGrafana(t.Context(), srv.URL, "glsa_token")
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (detail %q)", ok, tc.wantOK, detail)
			}
			if !strings.Contains(detail, tc.wantDetail) {
				t.Fatalf("detail = %q, want it to mention %q", detail, tc.wantDetail)
			}
			if tc.wantOK && version != "11.2.0" {
				t.Fatalf("version = %q", version)
			}
			// The token is forwarded so a proxy fronting Grafana does not
			// reject the probe.
			if seenAuth != "Bearer glsa_token" {
				t.Fatalf("Authorization header = %q", seenAuth)
			}
		})
	}
}

func TestProbeGrafanaHandlesUnreachableHost(t *testing.T) {
	// A port that nothing listens on: the probe must report failure rather than
	// hang or panic.
	ok, detail, _ := probeGrafana(t.Context(), "http://127.0.0.1:1", "")
	if ok {
		t.Fatal("an unreachable host was reported as reachable")
	}
	if !strings.Contains(detail, "could not reach Grafana") {
		t.Fatalf("detail = %q", detail)
	}
}

// TestWebhookTestRequestShapes pins the request contract the console's
// Settings → Notifications form sends.
func TestWebhookTestRequestShapes(t *testing.T) {
	var req webhookTestRequest
	if err := json.Unmarshal([]byte(`{"provider":"slack","url":"https://hooks.slack.com/x","secret":"k"}`), &req); err != nil {
		t.Fatal(err)
	}
	if req.Provider != "slack" || req.URL == "" || req.Secret != "k" {
		t.Fatalf("decoded = %+v", req)
	}

	// An unknown provider must be rejected by Render, which the handler
	// surfaces as a 400 rather than a confusing 502.
	ch := integrations.Channel{Provider: "carrier-pigeon", URL: "http://x"}
	if _, _, _, err := integrations.Render(ch, sampleEvent("")); err == nil {
		t.Fatal("Render accepted an unknown provider")
	}
}
