package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// stubBackend is an in-memory Backend, so the whole protocol can be exercised
// without a database. It records the last filter it was given, which is how the
// tests assert that validated arguments actually reach the data layer rather
// than being parsed and dropped.
type stubBackend struct {
	changes    []Change
	diff       Diff
	summary    HostSummary
	analysis   Analysis
	postmortem PostMortem

	lastFilter ChangeFilter
	lastHost   string
	lastWindow time.Duration
	lastFormat string
	lastID     string

	listErr error
	diffErr error
}

func (b *stubBackend) ListChanges(_ context.Context, _ Caller, f ChangeFilter) ([]Change, error) {
	b.lastFilter = f
	if b.listErr != nil {
		return nil, b.listErr
	}
	return b.changes, nil
}

func (b *stubBackend) GetDiff(_ context.Context, _ Caller, id string) (Diff, error) {
	b.lastID = id
	if b.diffErr != nil {
		return Diff{}, b.diffErr
	}
	return b.diff, nil
}

func (b *stubBackend) HostSummary(_ context.Context, _ Caller, host string, window time.Duration) (HostSummary, error) {
	b.lastHost, b.lastWindow = host, window
	return b.summary, nil
}

func (b *stubBackend) Analyze(_ context.Context, _ Caller, id string) (Analysis, error) {
	b.lastID = id
	return b.analysis, nil
}

func (b *stubBackend) PostMortem(_ context.Context, _ Caller, id string, window time.Duration, format string) (PostMortem, error) {
	b.lastID, b.lastWindow, b.lastFormat = id, window, format
	return b.postmortem, nil
}

func stubFixture() *stubBackend {
	return &stubBackend{
		changes: []Change{{
			ID: "7c1f5a2e-0000-4000-8000-000000000001", Host: "prod-web-01",
			OccurredAt: "2026-03-04T09:30:00Z", Level: 1, LevelLabel: "L1",
			Category: "config", Action: "Modified", Summary: "Modified /etc/nginx/nginx.conf",
			TargetType: "file", PathOrKey: "/etc/nginx/nginx.conf", Actor: "alice",
			Process: "vim", RemoteIP: "203.0.113.7", HasDiff: true,
		}},
		diff: Diff{
			ID: "7c1f5a2e-0000-4000-8000-000000000001", Host: "prod-web-01",
			OccurredAt: "2026-03-04T09:30:00Z", Level: 1, LevelLabel: "L1",
			Summary: "Modified /etc/nginx/nginx.conf", TargetType: "file",
			PathOrKey:    "/etc/nginx/nginx.conf",
			Diff:         "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b # [REDACTED:sha256:dead]\n",
			DiffRedacted: true,
			Actor:        "alice", RemoteIP: "203.0.113.7", Process: "vim",
			Lineage: []string{"sshd", "bash", "sudo", "vim"},
		},
		summary: HostSummary{
			Host: "prod-web-01", OS: "linux", Online: true, LastSeenSeconds: 8,
			Window: "1h", DriftTargetsCount: 42,
			Counts: map[string]int64{"total": 7, "l1_critical": 1, "l2_grouped": 2, "l3_drift": 4, "l4_forensic": 0},
			LatestCritical: &Change{
				ID: "7c1f5a2e-0000-4000-8000-000000000001", OccurredAt: "2026-03-04T09:30:00Z",
				PathOrKey: "/etc/nginx/nginx.conf", Summary: "Modified /etc/nginx/nginx.conf", Actor: "alice",
			},
		},
		analysis: Analysis{
			Provider: "azure_openai", ProviderLabel: "Azure OpenAI", Model: "gpt-4o-dep",
			RiskSummary: "Reloads the TLS listener.", BlastRadius: "High",
			RollbackCommand:     "nginx -t && systemctl reload nginx",
			VerificationCommand: "curl -fsS localhost/healthz",
			Scrubbed:            true, LatencyMS: 412,
		},
		postmortem: PostMortem{
			EventID:  "7c1f5a2e-0000-4000-8000-000000000001",
			Filename: "statetrack-postmortem-prod-web-01-7c1f5a2e.md",
			Format:   "markdown",
			Markdown: "# Incident Post-Mortem: Modified /etc/nginx/nginx.conf\n",
		},
	}
}

func testServer(b *stubBackend) *Server {
	return New(b, WithClock(func() time.Time { return time.Date(2026, 3, 4, 9, 30, 0, 0, time.UTC) }))
}

func fullCaller() Caller {
	return Caller{OrgID: "org-1", Name: "cursor", Scopes: []string{"read:mcp", "read:summary", "admin:write"}}
}

// call runs one tools/call and returns the decoded result.
func call(t *testing.T, s *Server, caller Caller, tool string, args map[string]any) ToolResult {
	t.Helper()
	params := map[string]any{"name": tool}
	if args != nil {
		params["arguments"] = args
	}
	rawParams, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: rawParams})

	resp := s.Handle(context.Background(), caller, body)
	if resp == nil {
		t.Fatal("no response for a request with an id")
	}
	if resp.Error != nil {
		t.Fatalf("tools/call returned an error: %v", resp.Error)
	}
	result, ok := resp.Result.(ToolResult)
	if !ok {
		t.Fatalf("result = %T, want ToolResult", resp.Result)
	}
	return result
}

/* -------------------------------------------------------------------------- */
/* Protocol                                                                   */
/* -------------------------------------------------------------------------- */

// TestInitializeHandshake verifies the MCP handshake: the protocol revision, the
// advertised capability set, and this build's identity. A client uses all three
// to decide whether to talk to this server at all.
func TestInitializeHandshake(t *testing.T) {
	s := testServer(stubFixture())
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`)

	resp := s.Handle(context.Background(), fullCaller(), body)
	if resp == nil {
		t.Fatal("initialize returned no response")
	}
	if resp.Error != nil {
		t.Fatalf("initialize errored: %v", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("result = %T", resp.Result)
	}
	if result["protocolVersion"] != ProtocolVersion {
		t.Errorf("protocolVersion = %v", result["protocolVersion"])
	}
	caps, ok := result["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("capabilities = %T", result["capabilities"])
	}
	if _, hasTools := caps["tools"]; !hasTools {
		t.Error("the tools capability is not advertised")
	}
	// Advertising resources or prompts this server does not serve would make a
	// client render empty panes.
	if _, has := caps["resources"]; has {
		t.Error("the server advertises resources it does not serve")
	}
	info, ok := result["serverInfo"].(map[string]any)
	if !ok {
		t.Fatalf("serverInfo = %T", result["serverInfo"])
	}
	if info["name"] != ServerName || info["version"] != ServerVersion {
		t.Errorf("serverInfo = %v", info)
	}
}

func TestPingReturnsAnEmptyResult(t *testing.T) {
	s := testServer(stubFixture())
	resp := s.Handle(context.Background(), fullCaller(), []byte(`{"jsonrpc":"2.0","id":"abc","method":"ping"}`))
	if resp == nil || resp.Error != nil {
		t.Fatalf("ping failed: %+v", resp)
	}
	// The id must come back verbatim, including its type.
	if string(resp.ID) != `"abc"` {
		t.Errorf("id = %s, want %q", resp.ID, "abc")
	}
	if _, ok := resp.Result.(map[string]any); !ok {
		t.Fatalf("ping result = %T, want an empty object", resp.Result)
	}
}

// TestNumericIDIsEchoedVerbatim catches the common framing bug where an id is
// decoded into a string and returned as `"1"` instead of `1`, which breaks id
// matching in every client that counts.
func TestNumericIDIsEchoedVerbatim(t *testing.T) {
	s := testServer(stubFixture())
	resp := s.Handle(context.Background(), fullCaller(), []byte(`{"jsonrpc":"2.0","id":42,"method":"ping"}`))
	if resp == nil {
		t.Fatal("no response")
	}
	if string(resp.ID) != "42" {
		t.Errorf("id = %s, want 42 (a number, not a string)", resp.ID)
	}
}

// TestNotificationGetsNoResponse: replying to a notification is a protocol
// violation that some clients treat as a fatal framing error.
func TestNotificationGetsNoResponse(t *testing.T) {
	s := testServer(stubFixture())
	resp := s.Handle(context.Background(), fullCaller(),
		[]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if resp != nil {
		t.Fatalf("a notification produced a response: %+v", resp)
	}
}

func TestToolsListExposesAllFiveTools(t *testing.T) {
	s := testServer(stubFixture())
	resp := s.Handle(context.Background(), fullCaller(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if resp == nil || resp.Error != nil {
		t.Fatalf("tools/list failed: %+v", resp)
	}
	result := resp.Result.(map[string]any)
	rawTools, ok := result["tools"].([]Tool)
	if !ok {
		t.Fatalf("tools = %T", result["tools"])
	}
	if len(rawTools) != 5 {
		t.Fatalf("got %d tools, want 5", len(rawTools))
	}

	seen := map[string]bool{}
	for _, tool := range rawTools {
		seen[tool.Name] = true
		if tool.Description == "" {
			t.Errorf("%s has no description", tool.Name)
		}
		// Every tool must ship a usable schema: an empty or non-object schema
		// makes the tool uncallable from a spec-compliant client.
		var schema map[string]any
		if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
			t.Fatalf("%s schema is not valid JSON: %v", tool.Name, err)
		}
		if schema["type"] != "object" {
			t.Errorf("%s schema type = %v, want object", tool.Name, schema["type"])
		}
		if _, has := schema["properties"]; !has {
			t.Errorf("%s schema declares no properties", tool.Name)
		}
	}
	for _, want := range ToolNames {
		if !seen[want] {
			t.Errorf("tool %q is missing from tools/list", want)
		}
	}
}

// TestToolSchemasDeclareTheirRequiredFields is the guard against a schema that
// documents a parameter it does not declare, which makes a model send the
// documented name and the server reject it.
func TestToolSchemasDeclareTheirRequiredFields(t *testing.T) {
	for _, tool := range Tools() {
		var schema struct {
			Properties map[string]any `json:"properties"`
			Required   []string       `json:"required"`
		}
		if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
			t.Fatal(err)
		}
		for _, req := range schema.Required {
			if _, declared := schema.Properties[req]; !declared {
				t.Errorf("%s requires %q but does not declare it", tool.Name, req)
			}
		}
	}
}

func TestUnknownMethodIsMethodNotFound(t *testing.T) {
	s := testServer(stubFixture())
	resp := s.Handle(context.Background(), fullCaller(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/purge"}`))
	if resp == nil || resp.Error == nil {
		t.Fatal("an unknown method was accepted")
	}
	if resp.Error.Code != CodeMethodNotFound {
		t.Errorf("code = %d, want %d", resp.Error.Code, CodeMethodNotFound)
	}
}

func TestMalformedJSONIsAParseError(t *testing.T) {
	s := testServer(stubFixture())
	resp := s.Handle(context.Background(), fullCaller(), []byte(`{"jsonrpc":`))
	if resp == nil || resp.Error == nil {
		t.Fatal("malformed JSON was accepted")
	}
	if resp.Error.Code != CodeParseError {
		t.Errorf("code = %d, want %d", resp.Error.Code, CodeParseError)
	}
}

func TestWrongProtocolVersionIsRejected(t *testing.T) {
	s := testServer(stubFixture())
	resp := s.Handle(context.Background(), fullCaller(), []byte(`{"jsonrpc":"1.0","id":1,"method":"ping"}`))
	if resp == nil || resp.Error == nil {
		t.Fatal("a wrong jsonrpc version was accepted")
	}
	if resp.Error.Code != CodeInvalidRequest {
		t.Errorf("code = %d, want %d", resp.Error.Code, CodeInvalidRequest)
	}
}

/* -------------------------------------------------------------------------- */
/* Tools                                                                      */
/* -------------------------------------------------------------------------- */

func TestListChangesTool(t *testing.T) {
	b := stubFixture()
	s := testServer(b)

	res := call(t, s, fullCaller(), "statetrack_list_changes", map[string]any{
		"host": "prod-web-01", "impact_level": "1", "category": "config", "window": "6h", "limit": 10,
	})
	if res.IsError {
		t.Fatalf("tool reported an error: %s", res.Content[0].Text)
	}
	// The validated arguments must reach the data layer, not be parsed and
	// dropped: a filter that silently stops filtering returns the whole fleet
	// and reads as a successful answer to a narrower question.
	if b.lastFilter.Host != "prod-web-01" {
		t.Errorf("host = %q", b.lastFilter.Host)
	}
	if b.lastFilter.ImpactLevel != 1 {
		t.Errorf("impact_level = %d", b.lastFilter.ImpactLevel)
	}
	if b.lastFilter.Category != 1 {
		t.Errorf("category = %d, want 1 (config)", b.lastFilter.Category)
	}
	if b.lastFilter.Window != 6*time.Hour {
		t.Errorf("window = %s, want 6h", b.lastFilter.Window)
	}
	if b.lastFilter.Limit != 10 {
		t.Errorf("limit = %d", b.lastFilter.Limit)
	}
	if text := res.Content[0].Text; !strings.Contains(text, "7c1f5a2e") {
		t.Errorf("the rendered list does not carry the event id:\n%s", text)
	}
}

// TestListChangesAppliesDefaults keeps the tool callable with no arguments, so
// a model can discover the recent changes without guessing a window.
func TestListChangesAppliesDefaults(t *testing.T) {
	b := stubFixture()
	call(t, testServer(b), fullCaller(), "statetrack_list_changes", nil)

	if b.lastFilter.Window != 24*time.Hour {
		t.Errorf("default window = %s, want 24h", b.lastFilter.Window)
	}
	if b.lastFilter.Limit != 25 {
		t.Errorf("default limit = %d, want 25", b.lastFilter.Limit)
	}
	if !b.lastFilter.RootOnly {
		t.Error("root_only must default to true so aggregated children do not consume the page")
	}
}

// TestListChangesClampsAnOversizedLimit: asking for 10,000 rows is a mistaken
// request, not an attack, so it is clamped rather than refused.
func TestListChangesClampsAnOversizedLimit(t *testing.T) {
	b := stubFixture()
	call(t, testServer(b), fullCaller(), "statetrack_list_changes", map[string]any{"limit": 100000})
	if b.lastFilter.Limit != 200 {
		t.Errorf("limit = %d, want it clamped to 200", b.lastFilter.Limit)
	}
}

func TestListChangesAcceptsAStringEncodedNumber(t *testing.T) {
	// Several MCP clients serialize every argument as a string; rejecting that
	// would make the tool uncallable from them for no benefit.
	b := stubFixture()
	res := call(t, testServer(b), fullCaller(), "statetrack_list_changes", map[string]any{"limit": "15"})
	if res.IsError {
		t.Fatalf("a string-encoded limit was rejected: %s", res.Content[0].Text)
	}
	if b.lastFilter.Limit != 15 {
		t.Errorf("limit = %d, want 15", b.lastFilter.Limit)
	}
}

func TestGetDiffTool(t *testing.T) {
	b := stubFixture()
	s := testServer(b)
	evID := "7c1f5a2e-0000-4000-8000-000000000001"

	res := call(t, s, fullCaller(), "statetrack_get_diff", map[string]any{"event_id": evID})
	if res.IsError {
		t.Fatalf("tool reported an error: %s", res.Content[0].Text)
	}
	if b.lastID != evID {
		t.Errorf("backend received id %q", b.lastID)
	}
	text := res.Content[0].Text
	// The lineage is the "who" answer; the stub is the "what".
	for _, want := range []string{"203.0.113.7", "sshd → bash → sudo → vim", "[REDACTED:sha256:dead]"} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered diff is missing %q:\n%s", want, text)
		}
	}
	// The scrubbing notice must be present when the diff carries stubs.
	if !strings.Contains(text, "stubs at the host") {
		t.Error("the rendered diff does not state that it was scrubbed")
	}
}

func TestGetDiffRequiresAnEventID(t *testing.T) {
	s := testServer(stubFixture())
	params, _ := json.Marshal(map[string]any{"name": "statetrack_get_diff", "arguments": map[string]any{}})
	body, _ := json.Marshal(Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params})

	resp := s.Handle(context.Background(), fullCaller(), body)
	if resp == nil || resp.Error == nil {
		t.Fatal("a missing event_id was accepted")
	}
	if resp.Error.Code != CodeInvalidParams {
		t.Errorf("code = %d, want %d", resp.Error.Code, CodeInvalidParams)
	}
	// The error must name the offending field so a model can repair its call.
	if data, ok := resp.Error.Data.(map[string]string); !ok || data["field"] != "event_id" {
		t.Errorf("the error does not name the bad field: %+v", resp.Error)
	}
}

// TestNotFoundBecomesCodeNotFound is the difference between a model telling its
// user "there is no such change" and it reporting "the server is broken".
func TestNotFoundBecomesCodeNotFound(t *testing.T) {
	b := stubFixture()
	b.diffErr = fmt.Errorf("change %s: %w", "abc", ErrNotFound)
	s := testServer(b)

	params, _ := json.Marshal(map[string]any{
		"name": "statetrack_get_diff", "arguments": map[string]any{"event_id": "abc"},
	})
	body, _ := json.Marshal(Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params})

	resp := s.Handle(context.Background(), fullCaller(), body)
	if resp == nil || resp.Error == nil {
		t.Fatal("a missing resource was reported as success")
	}
	if resp.Error.Code != CodeNotFound {
		t.Errorf("code = %d, want %d (body %+v)", resp.Error.Code, CodeNotFound, resp.Error)
	}
}

// TestInternalFailureIsAnIsErrorResult: a protocol error cannot be acted on by a
// model, whereas an isError tool result it can read and explain.
func TestInternalFailureIsAnIsErrorResult(t *testing.T) {
	b := stubFixture()
	b.listErr = errors.New("database is unavailable")
	s := testServer(b)

	res := call(t, s, fullCaller(), "statetrack_list_changes", nil)
	if !res.IsError {
		t.Fatal("a backend failure was reported as success")
	}
	if !strings.Contains(res.Content[0].Text, "database is unavailable") {
		t.Errorf("the failure reason was dropped: %s", res.Content[0].Text)
	}
}

func TestHostSummaryTool(t *testing.T) {
	b := stubFixture()
	s := testServer(b)

	res := call(t, s, fullCaller(), "statetrack_get_host_summary", map[string]any{
		"host": "prod-web-01", "window": "1h",
	})
	if res.IsError {
		t.Fatalf("tool reported an error: %s", res.Content[0].Text)
	}
	if b.lastHost != "prod-web-01" || b.lastWindow != time.Hour {
		t.Errorf("backend received host=%q window=%s", b.lastHost, b.lastWindow)
	}
	text := res.Content[0].Text
	for _, want := range []string{"online", "Tracked configuration targets", "42", "7 total", "critical"} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered summary is missing %q:\n%s", want, text)
		}
	}
}

func TestHostSummaryRequiresAHost(t *testing.T) {
	s := testServer(stubFixture())
	params, _ := json.Marshal(map[string]any{"name": "statetrack_get_host_summary", "arguments": map[string]any{}})
	body, _ := json.Marshal(Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params})

	resp := s.Handle(context.Background(), fullCaller(), body)
	if resp == nil || resp.Error == nil || resp.Error.Code != CodeInvalidParams {
		t.Fatalf("a missing host was accepted: %+v", resp)
	}
}

func TestAnalyzeAndRollbackTool(t *testing.T) {
	b := stubFixture()
	s := testServer(b)

	res := call(t, s, fullCaller(), "statetrack_analyze_and_rollback", map[string]any{
		"event_id": "7c1f5a2e-0000-4000-8000-000000000001",
	})
	if res.IsError {
		t.Fatalf("tool reported an error: %s", res.Content[0].Text)
	}
	text := res.Content[0].Text
	// The engine must be named, the commands must be present and fenced, and the
	// scrubbing must be declared.
	for _, want := range []string{
		"Azure OpenAI", "gpt-4o-dep", "Blast radius: High",
		"nginx -t && systemctl reload nginx", "curl -fsS localhost/healthz",
		"no secret value left the host",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered analysis is missing %q:\n%s", want, text)
		}
	}
	if !strings.Contains(text, "```bash") {
		t.Error("the rollback command is not fenced as a copyable block")
	}
}

// TestAnalyzeDeclaresAFallbackLoudly: a model must never present a rule-based
// answer as a model's judgement.
func TestAnalyzeDeclaresAFallbackLoudly(t *testing.T) {
	b := stubFixture()
	b.analysis = Analysis{
		Provider: "deterministic", ProviderLabel: "Built-in Offline Heuristics",
		RiskSummary: "Editing a web-tier configuration affects routing.",
		BlastRadius: "High", Fallback: true, FallbackReason: "HTTP 401: invalid api key",
	}
	res := call(t, testServer(b), fullCaller(), "statetrack_analyze_and_rollback", map[string]any{
		"event_id": "7c1f5a2e-0000-4000-8000-000000000001",
	})
	text := res.Content[0].Text
	if !strings.Contains(text, "Built-in Offline Heuristics") {
		t.Error("the engine name is missing")
	}
	if !strings.Contains(text, "unreachable") {
		t.Error("the fallback was not declared")
	}
	if !strings.Contains(text, "invalid api key") {
		t.Error("the fallback reason was dropped")
	}
}

func TestExportPostmortemTool(t *testing.T) {
	b := stubFixture()
	s := testServer(b)

	res := call(t, s, fullCaller(), "statetrack_export_postmortem", map[string]any{
		"event_id": "7c1f5a2e-0000-4000-8000-000000000001", "window": "30m", "format": "json",
	})
	if res.IsError {
		t.Fatalf("tool reported an error: %s", res.Content[0].Text)
	}
	if b.lastFormat != "json" {
		t.Errorf("format = %q, want json", b.lastFormat)
	}
	if b.lastWindow != 30*time.Minute {
		t.Errorf("window = %s, want 30m", b.lastWindow)
	}
	if !strings.Contains(res.Content[0].Text, "Incident Post-Mortem") {
		t.Errorf("the markdown document was not returned:\n%s", res.Content[0].Text)
	}
	structured, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structured content = %T", res.StructuredContent)
	}
	if structured["filename"] == nil {
		t.Error("the structured result does not carry the download filename")
	}
}

func TestExportPostmortemRejectsAnUnknownFormat(t *testing.T) {
	s := testServer(stubFixture())
	params, _ := json.Marshal(map[string]any{
		"name": "statetrack_export_postmortem",
		"arguments": map[string]any{
			"event_id": "7c1f5a2e-0000-4000-8000-000000000001", "format": "pdf",
		},
	})
	body, _ := json.Marshal(Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params})

	resp := s.Handle(context.Background(), fullCaller(), body)
	if resp == nil || resp.Error == nil {
		t.Fatal("an unknown format was accepted")
	}
	// The error must list the accepted values so a model can retry validly.
	if !strings.Contains(resp.Error.Message, "markdown") {
		t.Errorf("the error does not list the accepted values: %q", resp.Error.Message)
	}
}

func TestUnknownToolNamesTheAvailableOnes(t *testing.T) {
	s := testServer(stubFixture())
	params, _ := json.Marshal(map[string]any{"name": "statetrack_drop_database", "arguments": map[string]any{}})
	body, _ := json.Marshal(Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params})

	resp := s.Handle(context.Background(), fullCaller(), body)
	if resp == nil || resp.Error == nil {
		t.Fatal("an unknown tool was accepted")
	}
	if resp.Error.Code != CodeInvalidParams {
		t.Errorf("code = %d, want %d", resp.Error.Code, CodeInvalidParams)
	}
	if !strings.Contains(resp.Error.Message, "statetrack_list_changes") {
		t.Errorf("the error does not list the available tools: %q", resp.Error.Message)
	}
}

/* -------------------------------------------------------------------------- */
/* Authorization                                                              */
/* -------------------------------------------------------------------------- */

// TestScopeIsEnforced: a credential without read:mcp must not reach any tool,
// and the refusal must be a forbidden error rather than a not-found that would
// look like the resource was missing.
func TestScopeIsEnforced(t *testing.T) {
	s := testServer(stubFixture())
	// A key minted for the monitoring pollers: read:summary but not read:mcp.
	caller := Caller{OrgID: "org-1", Scopes: []string{"read:summary"}}

	for _, tool := range ToolNames {
		args := map[string]any{}
		if tool != "statetrack_list_changes" {
			args["event_id"] = "7c1f5a2e-0000-4000-8000-000000000001"
			args["host"] = "prod-web-01"
		}
		params, _ := json.Marshal(map[string]any{"name": tool, "arguments": args})
		body, _ := json.Marshal(Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params})

		resp := s.Handle(context.Background(), caller, body)
		if resp == nil || resp.Error == nil {
			t.Fatalf("%s was reachable without the %s scope", tool, ScopeRead)
		}
		if resp.Error.Code != CodeForbidden {
			t.Errorf("%s: code = %d, want %d (forbidden)", tool, resp.Error.Code, CodeForbidden)
		}
	}

	// The same caller with the scope added is served, proving the gate is the
	// scope and not something else about the caller.
	mcpCaller := Caller{OrgID: "org-1", Scopes: []string{"read:summary", ScopeRead}}
	if res := call(t, s, mcpCaller, "statetrack_list_changes", nil); res.IsError {
		t.Errorf("a read:mcp key was refused a read: %s", res.Content[0].Text)
	}
}

// TestSessionCallerIsUnrestricted matches the HTTP API's convention: scope
// enforcement is a property of machine credentials, not of a human in the
// console.
func TestSessionCallerIsUnrestricted(t *testing.T) {
	c := Caller{OrgID: "org-1", Name: "a.chen"}
	if !c.Allowed(ScopeRead) {
		t.Error("a session caller was scope-restricted")
	}
}

// TestCallerWithoutAnOrgIsRefused: every read is org-scoped, so a credential
// that resolves to no org must not be able to query at all.
func TestCallerWithoutAnOrgIsRefused(t *testing.T) {
	s := testServer(stubFixture())
	params, _ := json.Marshal(map[string]any{"name": "statetrack_list_changes"})
	body, _ := json.Marshal(Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params})

	resp := s.Handle(context.Background(), Caller{}, body)
	if resp == nil || resp.Error == nil {
		t.Fatal("a caller with no org was served")
	}
	if resp.Error.Code != CodeForbidden {
		t.Errorf("code = %d, want %d", resp.Error.Code, CodeForbidden)
	}
}

/* -------------------------------------------------------------------------- */
/* Argument parsing                                                           */
/* -------------------------------------------------------------------------- */

func TestParseWindowForms(t *testing.T) {
	cases := map[string]time.Duration{
		"30m": 30 * time.Minute,
		"2h":  2 * time.Hour,
		"7d":  7 * 24 * time.Hour,
		"90s": 90 * time.Second,
		"6":   6 * time.Hour, // a bare number reads as hours
	}
	for raw, want := range cases {
		got, err := ParseWindow(raw)
		if err != nil {
			t.Errorf("ParseWindow(%q): %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("ParseWindow(%q) = %s, want %s", raw, got, want)
		}
	}
	for _, bad := range []string{"", "yesterday", "next week", "abc"} {
		if _, err := ParseWindow(bad); err == nil {
			t.Errorf("ParseWindow(%q) was accepted", bad)
		}
	}
}

// TestWindowIsClamped: asking for a 30-day window is a mistaken request, not an
// attack, and a bounded answer is more useful than a refusal.
func TestWindowIsClamped(t *testing.T) {
	b := stubFixture()
	call(t, testServer(b), fullCaller(), "statetrack_list_changes", map[string]any{"window": "365d"})
	if b.lastFilter.Window != 30*24*time.Hour {
		t.Errorf("window = %s, want it clamped to 30d", b.lastFilter.Window)
	}
}

func TestEnumRejectsAnUnknownValue(t *testing.T) {
	s := testServer(stubFixture())
	params, _ := json.Marshal(map[string]any{
		"name":      "statetrack_list_changes",
		"arguments": map[string]any{"impact_level": "critical"},
	})
	body, _ := json.Marshal(Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params})

	resp := s.Handle(context.Background(), fullCaller(), body)
	if resp == nil || resp.Error == nil || resp.Error.Code != CodeInvalidParams {
		t.Fatalf("an unknown enum value was accepted: %+v", resp)
	}
}

// TestWrongTypeIsRejectedNotCoerced: silently dropping a `host` filter would
// return the whole fleet and read as a successful answer to a narrower question.
func TestWrongTypeIsRejectedNotCoerced(t *testing.T) {
	s := testServer(stubFixture())
	params, _ := json.Marshal(map[string]any{
		"name":      "statetrack_list_changes",
		"arguments": map[string]any{"host": map[string]any{"nested": true}},
	})
	body, _ := json.Marshal(Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params})

	resp := s.Handle(context.Background(), fullCaller(), body)
	if resp == nil || resp.Error == nil {
		t.Fatal("a wrong-typed argument was coerced")
	}
	if data, ok := resp.Error.Data.(map[string]string); !ok || data["field"] != "host" {
		t.Errorf("the error does not name the bad field: %+v", resp.Error)
	}
}

func TestArgumentsMustBeAnObject(t *testing.T) {
	s := testServer(stubFixture())
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"statetrack_list_changes","arguments":"host=prod"}}`)
	resp := s.Handle(context.Background(), fullCaller(), body)
	if resp == nil || resp.Error == nil || resp.Error.Code != CodeInvalidParams {
		t.Fatalf("a string arguments value was accepted: %+v", resp)
	}
}

func TestFormatEventID(t *testing.T) {
	if err := FormatEventID("7c1f5a2e-0000-4000-8000-000000000001"); err != nil {
		t.Errorf("a well-formed id was rejected: %v", err)
	}
	for _, bad := range []string{"", "abc", "not-a-uuid-at-all-but-long-enough!", "7c1f5a2e_0000_4000_8000_000000000001"} {
		if err := FormatEventID(bad); err == nil {
			t.Errorf("FormatEventID(%q) was accepted", bad)
		}
	}
}

/* -------------------------------------------------------------------------- */
/* Determinism                                                                */
/* -------------------------------------------------------------------------- */

// TestRenderersAreDeterministic protects the transcript-reproducibility
// property: the same call twice must produce byte-identical text, so a tool
// result can be diffed and a model's context is stable.
func TestRenderersAreDeterministic(t *testing.T) {
	b := stubFixture()
	s := testServer(b)

	first := call(t, s, fullCaller(), "statetrack_list_changes", nil).Content[0].Text
	for i := 0; i < 10; i++ {
		if got := call(t, s, fullCaller(), "statetrack_list_changes", nil).Content[0].Text; got != first {
			t.Fatalf("rendering twice produced different text:\n%s\n---\n%s", first, got)
		}
	}
}

// TestNoBackendIsAnInternalError rather than a nil-pointer panic that takes the
// process down mid-incident.
func TestNoBackendIsAnInternalError(t *testing.T) {
	s := New(nil)
	params, _ := json.Marshal(map[string]any{"name": "statetrack_list_changes"})
	body, _ := json.Marshal(Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params})

	resp := s.Handle(context.Background(), fullCaller(), body)
	if resp == nil || resp.Error == nil {
		t.Fatal("a missing backend was not reported")
	}
	if resp.Error.Code != CodeInternalError {
		t.Errorf("code = %d, want %d", resp.Error.Code, CodeInternalError)
	}
}
