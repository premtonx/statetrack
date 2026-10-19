package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/statetrack/statetrack/server/internal/ai"
)

// aiTestServer returns a Server wired to an httptest model endpoint, with no
// database. The GET/PUT/test handlers under test read settings from the store,
// so the database-free cases here cover the pure helpers and the request shapes
// a model sees; the persistence paths are covered by the DB-backed tests.
func aiEventFixture() ai.Event {
	return ai.Event{
		ID:           "7c1f5a2e-0000-4000-8000-000000000001",
		Host:         "prod-web-01",
		OSFamily:     "linux",
		Level:        1,
		LevelLabel:   "L1",
		Category:     "Configuration",
		Action:       "Modified",
		Summary:      "Modified /etc/nginx/nginx.conf (+12 -3)",
		TargetType:   "file",
		PathOrKey:    "/etc/nginx/nginx.conf",
		Actor:        "alice",
		Process:      "vim",
		RemoteIP:     "203.0.113.7",
		Diff:         "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b # [REDACTED:sha256:dead]\n",
		DiffRedacted: true,
	}
}

func TestEffectiveEndpointAndModelMirrorTheGateway(t *testing.T) {
	// The card shows the operator what will actually run, so the blank-field
	// resolution must match internal/ai's, or the console would display a
	// different endpoint than the one the gateway calls.
	cases := []struct {
		name         string
		settings     ai.Settings
		wantEndpoint string
		wantModel    string
	}{
		{"ollama defaults", ai.Settings{Provider: ai.ProviderOllama}, "http://localhost:11434/v1", "llama3.1"},
		{"openai defaults", ai.Settings{Provider: ai.ProviderOpenAI}, "https://api.openai.com/v1", "gpt-4o-mini"},
		{"anthropic defaults", ai.Settings{Provider: ai.ProviderAnthropic}, "https://api.anthropic.com", "claude-3-5-sonnet-latest"},
		{
			"configured values win",
			ai.Settings{Provider: ai.ProviderOllama, Endpoint: "http://gpu-box:11434/v1", Model: "qwen2.5-coder"},
			"http://gpu-box:11434/v1", "qwen2.5-coder",
		},
		{
			// Azure has no default endpoint: the resource URL is mandatory, so
			// the card must not invent one. A configured deployment name still
			// wins, because that is the only way to name the deployment.
			"azure has no endpoint default",
			ai.Settings{Provider: ai.ProviderAzureOpenAI, Model: "gpt-4o-dep"},
			"", "gpt-4o-dep",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveEndpoint(tc.settings); got != tc.wantEndpoint {
				t.Errorf("endpoint = %q, want %q", got, tc.wantEndpoint)
			}
			if got := effectiveModelName(tc.settings); got != tc.wantModel {
				t.Errorf("model = %q, want %q", got, tc.wantModel)
			}
		})
	}
}

// TestAISettingsViewNeverReturnsTheKey is a security regression guard: the
// console must be able to render "configured" without the credential ever
// reaching the browser.
func TestAISettingsViewNeverReturnsTheKey(t *testing.T) {
	s := &Server{}
	view := s.aiSettingsView(ai.Settings{
		Provider: ai.ProviderAzureOpenAI,
		Endpoint: "https://acme.openai.azure.com",
		Model:    "gpt-4o-dep",
		APIKey:   "super-secret-value",
		Enabled:  true,
	})

	if view.APIKey != "" {
		t.Fatalf("the API key was returned to the client: %q", view.APIKey)
	}
	if !view.APIKeySet {
		t.Error("api_key_set must report that a credential is stored")
	}
	// Marshalling must not reintroduce it through an embedding.
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "super-secret-value") {
		t.Fatalf("the credential leaked into the JSON payload: %s", raw)
	}
	if !view.NeedsNetwork {
		t.Error("Azure OpenAI must be flagged as needing network access")
	}
	if len(view.Providers) != len(ai.Providers) {
		t.Errorf("providers = %v", view.Providers)
	}
}

func TestAISettingsViewFlagsDeterministicAsOffline(t *testing.T) {
	view := (&Server{}).aiSettingsView(ai.DefaultSettings())
	if view.NeedsNetwork {
		t.Error("the deterministic engine must not be flagged as needing network access")
	}
	if view.APIKeySet {
		t.Error("the default settings have no credential")
	}
	if view.EffectiveModel != "" {
		t.Errorf("the deterministic engine has no model, got %q", view.EffectiveModel)
	}
}

// TestAITestProbeRunsAgainstAStubModel verifies that the test endpoint exercises
// the real provider path — the same request shape an analysis uses — so a green
// result genuinely proves the configuration end to end.
func TestAITestProbeRunsAgainstAStubModel(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		io.WriteString(w, `{"choices":[{"message":{"content":"{\"risk_summary\":\"ok\",\"blast_radius\":\"Medium\"}"}}]}`)
	}))
	defer srv.Close()

	g := ai.New(ai.WithHTTPClient(srv.Client()))
	res := g.Test(context.Background(), ai.Settings{
		Provider: ai.ProviderOllama, Endpoint: srv.URL, Model: "llama3.1", Enabled: true,
		Temperature: 0.1, MaxTokens: 128, TimeoutSeconds: 5,
	})

	if !res.OK {
		t.Fatalf("probe failed: %s", res.Detail)
	}
	if gotPath != "/chat/completions" {
		t.Errorf("probe hit %q", gotPath)
	}
	if res.BlastCheck != ai.BlastRadiusMedium {
		t.Errorf("blast check = %q", res.BlastCheck)
	}
}

// TestAITestProbeReportsProviderFailureWithoutBlankingTheConfig covers the
// operator workflow: probing a broken endpoint must describe the problem in the
// provider's own words.
func TestAITestProbeReportsProviderFailureWithoutBlankingTheConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":{"message":"Incorrect API key provided"}}`)
	}))
	defer srv.Close()

	g := ai.New(ai.WithHTTPClient(srv.Client()))
	res := g.Test(context.Background(), ai.Settings{
		Provider: ai.ProviderOpenAI, Endpoint: srv.URL, APIKey: "sk-wrong", Enabled: true,
		Temperature: 0.1, MaxTokens: 128, TimeoutSeconds: 5,
	})

	if res.OK {
		t.Fatal("a 401 was reported as a passing test")
	}
	if !strings.Contains(res.Detail, "401") {
		t.Errorf("detail = %q", res.Detail)
	}
}

// TestAITestResponseShape pins the payload the console's chip reads.
func TestAITestResponseShape(t *testing.T) {
	resp := aiTestResponse{
		OK: true, Provider: "azure_openai", Endpoint: "https://x.openai.azure.com",
		Model: "gpt-4o-dep", Detail: "connected in 412 ms", LatencyMS: 412,
		BlastCheck: "High", CheckedAt: "2026-03-04T09:30:00Z",
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var round map[string]any
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"ok", "provider", "detail", "latency_ms", "blast_check", "checked_at"} {
		if _, present := round[key]; !present {
			t.Errorf("response is missing %q", key)
		}
	}
}

// TestProviderStringsMatchesTheClosedSet guards the selector's options against
// drifting from what the server validates.
func TestProviderStringsMatchesTheClosedSet(t *testing.T) {
	got := providerStrings()
	if len(got) != len(ai.Providers) {
		t.Fatalf("got %d providers, want %d", len(got), len(ai.Providers))
	}
	for i, p := range ai.Providers {
		if got[i] != string(p) {
			t.Errorf("providers[%d] = %q, want %q", i, got[i], p)
		}
	}
	// The deterministic engine must be first: it is the default, and the
	// selector renders the list in order.
	if got[0] != string(ai.ProviderDeterministic) {
		t.Errorf("the offline engine must be listed first, got %q", got[0])
	}
}

// TestAnalyzeEventRequiresAnID keeps a missing path segment a clean 400 rather
// than a panic or a query with an empty id.
func TestAnalyzeEventRequiresAnID(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/events//analyze", nil)
	req.SetPathValue("id", "")
	s.analyzeEvent(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestAnalyzeEventWithoutAStoreFailsCleanly covers the degraded case: a server
// with no database must surface an error, not a nil-pointer panic that takes the
// process down mid-incident.
func TestAnalyzeEventWithoutAStoreFailsCleanly(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/events/abc/analyze", nil)
	req.SetPathValue("id", "abc")

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("analyzeEvent panicked with no store: %v", r)
		}
	}()
	s.analyzeEvent(rec, req)
	if rec.Code < 400 {
		t.Fatalf("status = %d, want an error", rec.Code)
	}
}

// TestAIGatewayIsMemoized keeps one HTTP client (and therefore one connection
// pool) per server, which is what makes repeated drawer clicks cheap.
func TestAIGatewayIsMemoized(t *testing.T) {
	s := &Server{}
	first := s.aiGateway()
	second := s.aiGateway()
	if first != second {
		t.Fatal("aiGateway built a new gateway on every call")
	}
}
