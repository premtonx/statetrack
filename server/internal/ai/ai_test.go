package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// sampleEvent is the fixture every test analyzes: a Level 1 nginx config change
// with a scrubbed credential in the diff, which is the shape the feature exists
// for.
func sampleEvent() Event {
	return Event{
		ID:           "7c1f5a2e-0000-4000-8000-000000000001",
		Host:         "prod-web-01",
		OSFamily:     "linux",
		OccurredAt:   time.Date(2026, 3, 4, 9, 30, 0, 0, time.UTC),
		Level:        1,
		LevelLabel:   "Level 1 · Critical",
		Category:     "Configuration",
		Action:       "Modified",
		Summary:      "Modified /etc/nginx/nginx.conf (+12 -3)",
		TargetType:   "file",
		PathOrKey:    "/etc/nginx/nginx.conf",
		Actor:        "alice",
		Process:      "vim",
		RemoteIP:     "203.0.113.7",
		RuleName:     "web-server-config",
		Diff:         "--- a/etc/nginx/nginx.conf\n+++ b/etc/nginx/nginx.conf\n@@ -1,3 +1,3 @@\n-server 10.0.0.4;\n+server 10.0.0.9;\n+proxy_set_header Authorization \"[REDACTED:sha256:9f2a]\"\n",
		DiffRedacted: true,
	}
}

// TestDeterministicFallbackWorksOffline pins the package's central promise: with
// no provider configured, the analysis is still complete. An empty drawer on a
// first click would make the feature look broken on the default install.
func TestDeterministicFallbackWorksOffline(t *testing.T) {
	g := New()
	out := g.Analyze(context.Background(), DefaultSettings(), sampleEvent())

	if out.Provider != string(ProviderDeterministic) {
		t.Fatalf("provider = %q, want deterministic", out.Provider)
	}
	if out.ProviderLabel != "Built-in Offline Heuristics" {
		t.Errorf("label = %q", out.ProviderLabel)
	}
	if out.Fallback {
		t.Errorf("the deterministic engine is not a fallback when explicitly selected")
	}
	if strings.TrimSpace(out.RiskSummary) == "" {
		t.Fatal("risk summary must never be empty")
	}
	if out.BlastRadius != BlastRadiusHigh {
		t.Errorf("blast radius = %q, want High for a Level 1 change", out.BlastRadius)
	}
	if strings.TrimSpace(out.RollbackCommand) == "" {
		t.Error("a Level 1 nginx change should yield a rollback command")
	}
	if !out.Scrubbed {
		t.Error("a diff with redaction stubs must be reported as scrubbed")
	}
	if out.GeneratedAt.IsZero() {
		t.Error("generated_at must be set")
	}
}

// TestBandForNeverUnderstatesSeverity is the guard against the worst failure of
// a coarse classifier: a Level 1 change reported as "Low". An operator reads the
// band before the prose, so understating it suppresses action.
func TestBandForNeverUnderstatesSeverity(t *testing.T) {
	g := New()
	// An unidentifiable target at Level 1: the component cannot be classified,
	// which previously risked a Low band from the derived plan.
	ev := sampleEvent()
	ev.PathOrKey = ""
	ev.TargetType = ""
	ev.Level = 1
	if got := g.Analyze(context.Background(), DefaultSettings(), ev).BlastRadius; got != BlastRadiusHigh {
		t.Fatalf("Level 1 with an unknown component = %q, want High", got)
	}

	for level, want := range map[int32]string{
		2: BlastRadiusMedium,
		3: BlastRadiusLow,
		4: BlastRadiusLow,
	} {
		ev.Level = level
		if got := g.Analyze(context.Background(), DefaultSettings(), ev).BlastRadius; got != want {
			t.Errorf("level %d = %q, want %q", level, got, want)
		}
	}
}

// TestOllamaRequestShape verifies the local/air-gapped path sends an
// OpenAI-compatible body to the Ollama chat-completions route and uses the
// configured endpoint verbatim, and that the prompt carries the scrubbed diff
// and no un-redacted secret.
func TestOllamaRequestShape(t *testing.T) {
	var gotPath, gotAuth string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"content":"{\"risk_summary\":\"Reloads the TLS listener.\",\"blast_radius\":\"High\",\"rollback_command\":\"nginx -t && systemctl reload nginx\",\"verification_command\":\"curl -fsS localhost/healthz\"}"}}]}`)
	}))
	defer srv.Close()

	s := DefaultSettings()
	s.Provider = ProviderOllama
	s.Endpoint = srv.URL
	s.Model = "llama3.1"
	s.Enabled = true

	out := New().Analyze(context.Background(), s, sampleEvent())

	if out.Provider != string(ProviderOllama) || out.ProviderLabel != "Local Ollama" {
		t.Fatalf("provider = %q / %q", out.Provider, out.ProviderLabel)
	}
	if out.Fallback {
		t.Fatalf("unexpected fallback: %s", out.FallbackReason)
	}
	if gotPath != "/chat/completions" {
		t.Errorf("path = %q, want /chat/completions", gotPath)
	}
	if gotAuth != "" {
		t.Errorf("no API key was configured, so no Authorization header should be sent; got %q", gotAuth)
	}
	if body["model"] != "llama3.1" {
		t.Errorf("model = %v", body["model"])
	}
	msgs, _ := body["messages"].([]any)
	if len(msgs) != 2 {
		t.Fatalf("expected a system and a user message, got %d", len(msgs))
	}
	user := msgs[1].(map[string]any)["content"].(string)
	if !strings.Contains(user, "[REDACTED:sha256:9f2a]") {
		t.Error("the scrubbed diff must be sent to the model")
	}
	if strings.Contains(user, "proxy_set_header") && !strings.Contains(user, "[REDACTED:") {
		t.Error("a diff line was sent without its redaction stub")
	}
	// The model's command must reach the caller untouched.
	if out.RollbackCommand != "nginx -t && systemctl reload nginx" {
		t.Errorf("rollback = %q", out.RollbackCommand)
	}
	if out.BlastRadius != BlastRadiusHigh {
		t.Errorf("blast radius = %q", out.BlastRadius)
	}
}

// TestOpenAICompatibleAppliesDefaultEndpoint checks that a blank endpoint
// resolves to the provider default rather than an error or a request to "".
func TestOpenAICompatibleAppliesDefaultEndpoint(t *testing.T) {
	if got := baseEndpoint(Settings{Provider: ProviderOllama}); got != "http://localhost:11434/v1" {
		t.Errorf("ollama default = %q", got)
	}
	if got := baseEndpoint(Settings{Provider: ProviderOpenAI}); got != "https://api.openai.com/v1" {
		t.Errorf("openai default = %q", got)
	}
	if got := baseEndpoint(Settings{Provider: ProviderOpenAI, Endpoint: "https://proxy.internal/v1/"}); got != "https://proxy.internal/v1/" {
		t.Errorf("configured endpoint must win; got %q", got)
	}
}

// TestAzureOpenAIRequestShape verifies the three Azure-specific details: the
// deployment in the path, api-version in the query, and the api-key header.
// Getting any of them wrong is a 404 or a 401 in production, not here.
func TestAzureOpenAIRequestShape(t *testing.T) {
	var gotPath, gotQuery, gotKey, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		gotKey, gotAuth = r.Header.Get("api-key"), r.Header.Get("Authorization")
		io.WriteString(w, `{"choices":[{"message":{"content":"{\"risk_summary\":\"ok\",\"blast_radius\":\"Medium\"}"}}]}`)
	}))
	defer srv.Close()

	s := DefaultSettings()
	s.Provider = ProviderAzureOpenAI
	s.Endpoint = srv.URL
	s.Model = "gpt-4o-deployment"
	s.APIVersion = "2024-10-21"
	s.APIKey = "azure-secret"
	s.Enabled = true

	out := New().Analyze(context.Background(), s, sampleEvent())

	if out.Provider != string(ProviderAzureOpenAI) || out.ProviderLabel != "Azure OpenAI" {
		t.Fatalf("provider = %q / %q (fallback: %s)", out.Provider, out.ProviderLabel, out.FallbackReason)
	}
	if want := "/openai/deployments/gpt-4o-deployment/chat/completions"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if !strings.Contains(gotQuery, "api-version=2024-10-21") {
		t.Errorf("query = %q, want api-version", gotQuery)
	}
	if gotKey != "azure-secret" {
		t.Errorf("api-key header = %q", gotKey)
	}
	if gotAuth != "" {
		t.Error("Azure authenticates with api-key, not a bearer token")
	}
}

// TestAzureUsesDefaultAPIVersion when the operator leaves the version blank, so
// saving a deployment name alone is enough to get a working configuration.
func TestAzureUsesDefaultAPIVersion(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		io.WriteString(w, `{"choices":[{"message":{"content":"{\"risk_summary\":\"ok\"}"}}]}`)
	}))
	defer srv.Close()

	s := DefaultSettings()
	s.Provider = ProviderAzureOpenAI
	s.Endpoint = srv.URL
	s.Model = "dep"
	s.Enabled = true

	New().Analyze(context.Background(), s, sampleEvent())
	if !strings.Contains(gotQuery, "api-version=2024-08-01-preview") {
		t.Errorf("query = %q, want the default api-version", gotQuery)
	}
}

// TestAnthropicRequestShape covers the provider with a genuinely different wire
// format: a top-level system prompt, a mandatory max_tokens, and an x-api-key
// header.
func TestAnthropicRequestShape(t *testing.T) {
	var gotPath, gotKey, gotVersion string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		io.WriteString(w, `{"content":[{"type":"text","text":"{\"risk_summary\":\"Rolls back the listener.\",\"blast_radius\":\"critical\"}"}]}`)
	}))
	defer srv.Close()

	s := DefaultSettings()
	s.Provider = ProviderAnthropic
	s.Endpoint = srv.URL
	s.Model = "claude-3-5-sonnet-latest"
	s.APIKey = "sk-ant-test"
	s.Enabled = true

	out := New().Analyze(context.Background(), s, sampleEvent())

	if out.Provider != string(ProviderAnthropic) {
		t.Fatalf("provider = %q (fallback: %s)", out.Provider, out.FallbackReason)
	}
	if gotPath != "/v1/messages" {
		t.Errorf("path = %q, want /v1/messages", gotPath)
	}
	if gotKey != "sk-ant-test" || gotVersion == "" {
		t.Errorf("x-api-key = %q, anthropic-version = %q", gotKey, gotVersion)
	}
	if _, ok := body["system"]; !ok {
		t.Error("Anthropic takes the system prompt as a top-level field")
	}
	if body["max_tokens"] == nil {
		t.Error("Anthropic requires max_tokens")
	}
	// "critical" is folded onto the closed set rather than passed through.
	if out.BlastRadius != BlastRadiusHigh {
		t.Errorf("blast radius = %q, want High", out.BlastRadius)
	}
}

// TestFallbackOnProviderFailure is the availability guarantee: a model that is
// down must still produce a complete analysis, and must say that it fell back so
// an operator does not mistake a heuristic for a model's judgement.
func TestFallbackOnProviderFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":{"message":"invalid api key"}}`)
	}))
	defer srv.Close()

	s := DefaultSettings()
	s.Provider = ProviderOpenAI
	s.Endpoint = srv.URL
	s.APIKey = "wrong"
	s.Enabled = true

	out := New().Analyze(context.Background(), s, sampleEvent())

	if !out.Fallback {
		t.Fatal("a 401 must be reported as a fallback")
	}
	if !strings.Contains(out.FallbackReason, "401") {
		t.Errorf("fallback reason should name the status: %q", out.FallbackReason)
	}
	if out.Provider != string(ProviderDeterministic) {
		t.Errorf("provider = %q, want deterministic", out.Provider)
	}
	if strings.TrimSpace(out.RiskSummary) == "" || strings.TrimSpace(out.RollbackCommand) == "" {
		t.Error("the fallback analysis must still be complete")
	}
}

// TestFallbackOnUnreachableEndpoint covers the air-gapped deployment where a
// configured cloud provider simply cannot be dialed.
func TestFallbackOnUnreachableEndpoint(t *testing.T) {
	s := DefaultSettings()
	s.Provider = ProviderOpenAI
	// Port 1 is not listening.
	s.Endpoint = "http://127.0.0.1:1/v1"
	s.TimeoutSeconds = 3
	s.Enabled = true

	out := New().Analyze(context.Background(), s, sampleEvent())
	if !out.Fallback {
		t.Fatal("an unreachable endpoint must fall back")
	}
	if !strings.Contains(out.FallbackReason, "could not reach") {
		t.Errorf("fallback reason = %q", out.FallbackReason)
	}
}

// TestDisabledFallsBackWithoutCalling asserts that disabling live AI is a
// configuration choice rather than a failure, so it is not reported as a
// fallback the operator needs to fix.
func TestDisabledFallsBackWithoutCalling(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	s := DefaultSettings()
	s.Provider = ProviderOpenAI
	s.Endpoint = srv.URL
	s.Enabled = false

	out := New().Analyze(context.Background(), s, sampleEvent())
	if called {
		t.Error("a disabled gateway must not touch the network")
	}
	if out.Provider != string(ProviderDeterministic) {
		t.Errorf("provider = %q", out.Provider)
	}
	if out.Fallback {
		t.Error("a deliberate disable is not a fallback")
	}
}

// TestModelProseIsParsedLEniently covers how models actually answer: JSON buried
// in a fenced block, with prose before and after.
func TestModelProseIsParsedLeniently(t *testing.T) {
	reply := "Here is my analysis of the change.\n\n```json\n{\n  \"risk_summary\": \"Reloads the listener with a new upstream.\",\n  \"blast_radius\": \"high\",\n  \"rollback_command\": \"nginx -t && systemctl reload nginx\",\n  \"verification_command\": \"curl -fsS localhost/healthz\"\n}\n```\n\nLet me know if you need more detail."

	parsed, err := parseModelReply(reply)
	if err != nil {
		t.Fatalf("expected the fenced reply to parse: %v", err)
	}
	if parsed.BlastRadius != "high" {
		t.Errorf("blast radius = %q", parsed.BlastRadius)
	}
	if !strings.Contains(parsed.RiskSummary, "Reloads the listener") {
		t.Errorf("risk summary = %q", parsed.RiskSummary)
	}
}

// TestModelReplyWithTrailingBraceInString guards the brace-balancing scanner:
// a naive "first { to last }" slice would break here.
func TestModelReplyWithTrailingBraceInString(t *testing.T) {
	reply := `{"risk_summary":"Sets the header to \"{x}\" and reloads.","blast_radius":"Medium"} and that is all.`
	parsed, err := parseModelReply(reply)
	if err != nil {
		t.Fatalf("expected the object to parse: %v", err)
	}
	if !strings.Contains(parsed.RiskSummary, "{x}") {
		t.Errorf("risk summary = %q", parsed.RiskSummary)
	}
}

// TestParseModelReplyRejectsUnusableAnswers ensures a reply that answers no
// question degrades to the deterministic engine instead of rendering an empty
// drawer.
func TestParseModelReplyRejectsUnusableAnswers(t *testing.T) {
	for name, reply := range map[string]string{
		"empty":         "",
		"prose only":    "I cannot help with that.",
		"no summary":    `{"blast_radius":"High"}`,
		"truncated":     `{"risk_summary":"Started but never fin`,
		"blank summary": `{"risk_summary":"   "}`,
	} {
		if _, err := parseModelReply(reply); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// TestPartialModelReplyIsFilledFromHeuristics covers the hybrid case: a model
// that gives a good assessment but forgets the command still yields a runnable
// one, because a rollback button that does nothing is worse than the heuristic.
func TestPartialModelReplyIsFilledFromHeuristics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"message":{"content":"{\"risk_summary\":\"Reloads the TLS listener.\",\"blast_radius\":\"High\"}"}}]}`)
	}))
	defer srv.Close()

	s := DefaultSettings()
	s.Provider = ProviderOllama
	s.Endpoint = srv.URL
	s.Enabled = true

	out := New().Analyze(context.Background(), s, sampleEvent())
	if out.Fallback {
		t.Fatalf("a valid partial reply is not a fallback: %s", out.FallbackReason)
	}
	if out.RiskSummary != "Reloads the TLS listener." {
		t.Errorf("the model's prose must be kept: %q", out.RiskSummary)
	}
	if strings.TrimSpace(out.RollbackCommand) == "" {
		t.Error("the missing command must be filled from the deterministic engine")
	}
}

// TestNormalizeSettingsClampsUnsafeValues makes a settings row written by an
// older build usable instead of a zero-timeout request that fails every time.
func TestNormalizeSettingsClampsUnsafeValues(t *testing.T) {
	got := NormalizeSettings(Settings{Provider: "gpt5", Temperature: 4, MaxTokens: -1, TimeoutSeconds: 0})
	if got.Provider != ProviderDeterministic {
		t.Errorf("unknown provider = %q, want deterministic", got.Provider)
	}
	if got.Temperature != DefaultSettings().Temperature {
		t.Errorf("temperature = %v, want the default", got.Temperature)
	}
	if got.MaxTokens <= 0 || got.TimeoutSeconds <= 0 {
		t.Errorf("max_tokens=%d timeout=%d, want positive defaults", got.MaxTokens, got.TimeoutSeconds)
	}
}

// TestSystemPromptForbidsSecretRecovery is a regression guard on the prompt
// text itself: the prompt is the boundary the security review inspects, so a
// future edit that invites the model to reconstruct redacted values must fail a
// test rather than ship.
func TestSystemPromptForbidsSecretRecovery(t *testing.T) {
	if !strings.Contains(SystemPrompt, "Never speculate about redacted values") {
		t.Error("the system prompt must forbid reasoning about redacted content")
	}
	if !strings.Contains(SystemPrompt, "Do NOT invent a backup path") {
		t.Error("the system prompt must forbid inventing rollback paths")
	}
	if !strings.Contains(SystemPrompt, "kubectl") {
		t.Error("the system prompt must cover the Kubernetes command family")
	}
}

// TestUserPromptIsDeterministic protects the reproducibility property: the same
// event must always produce byte-identical prompts, so a model's answer can be
// reasoned about and a prompt injection is visible in review.
func TestUserPromptIsDeterministic(t *testing.T) {
	ev := sampleEvent()
	ev.Metadata = map[string]string{"zeta": "1", "alpha": "2", "middle": "3"}
	first := UserPrompt(ev)
	for i := 0; i < 20; i++ {
		if got := UserPrompt(ev); got != first {
			t.Fatalf("prompts differ between runs:\n%s\n---\n%s", first, got)
		}
	}
	if strings.Index(first, "alpha") > strings.Index(first, "zeta") {
		t.Error("metadata keys must be sorted in the prompt")
	}
}

// TestUserPromptOmitsAbsentFields keeps the prompt compact, which matters for a
// local model with a small context window.
func TestUserPromptOmitsAbsentFields(t *testing.T) {
	prompt := UserPrompt(Event{ID: "x", Host: "h", Diff: ""})
	if strings.Contains(prompt, "originating_ip:") {
		t.Error("empty fields must be omitted")
	}
	if !strings.Contains(prompt, "no text diff recorded") {
		t.Error("a hash-only change must be explained to the model")
	}
}

// TestTestProbeReportsFailure lets an operator see why their endpoint is broken
// without waiting for a real incident.
func TestTestProbeReportsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"error":{"message":"quota exceeded"}}`)
	}))
	defer srv.Close()

	s := DefaultSettings()
	s.Provider = ProviderAzureOpenAI
	s.Endpoint = srv.URL
	s.Model = "dep"
	s.Enabled = true

	res := New().Test(context.Background(), s)
	if res.OK {
		t.Fatal("expected the probe to report failure")
	}
	if !strings.Contains(res.Detail, "403") {
		t.Errorf("detail = %q", res.Detail)
	}
}

// TestTestProbeSucceedsOnDeterministic so the Test button is instant and always
// green for the default configuration, which is what makes the default honest.
func TestTestProbeSucceedsOnDeterministic(t *testing.T) {
	res := New().Test(context.Background(), DefaultSettings())
	if !res.OK {
		t.Fatalf("deterministic test should pass: %s", res.Detail)
	}
	if !strings.Contains(res.Detail, "offline heuristics") {
		t.Errorf("detail = %q", res.Detail)
	}
}

// TestProviderLabels pins the badge text the console renders. These strings are
// the user-visible contract from the specification.
func TestProviderLabels(t *testing.T) {
	for provider, want := range map[string]string{
		"ollama":        "Local Ollama",
		"azure_openai":  "Azure OpenAI",
		"openai":        "OpenAI",
		"anthropic":     "Anthropic",
		"deterministic": "Built-in Offline Heuristics",
		"nonsense":      "Built-in Offline Heuristics",
	} {
		if got := ProviderLabel(provider); got != want {
			t.Errorf("ProviderLabel(%q) = %q, want %q", provider, got, want)
		}
	}
}

// TestIsValidProviderRejectsTypos keeps a bad value out of the settings row,
// where it would otherwise disable analysis silently.
func TestIsValidProviderRejectsTypos(t *testing.T) {
	for _, OK := range []string{"deterministic", "ollama", "azure_openai", "openai", "anthropic"} {
		if !IsValidProvider(OK) {
			t.Errorf("%q should be valid", OK)
		}
	}
	for _, bad := range []string{"", "gpt", "Azure", "open-ai"} {
		if IsValidProvider(bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

// TestHasRedactions pins the placeholder contract with the agent's edge
// scrubber.
func TestHasRedactions(t *testing.T) {
	if !HasRedactions("token = \"[REDACTED:sha256:abc]\"") {
		t.Error("a stub must be detected")
	}
	if HasRedactions("token = \"hunter2\"") {
		t.Error("plain text must not be reported as scrubbed")
	}
}

// TestAnalyzeNeverReturnsError ensures a failure surfaces rather than being
// silently rewritten as success.
func TestAnalyzeNeverReturnsError(t *testing.T) {
	var out Analysis
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Analyze must not panic: %v", r)
			}
		}()
		out = New().Analyze(context.Background(), Settings{Provider: ProviderOpenAI, Enabled: true, Endpoint: ""}, Event{})
	}()
	if !out.Fallback {
		t.Error("a provider with no usable endpoint must fall back")
	}
	if out.RiskSummary == "" {
		t.Error("even an empty event must yield some risk text")
	}
}
