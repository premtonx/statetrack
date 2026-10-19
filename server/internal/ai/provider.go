package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// maxReplyBytes bounds how much of a provider's response is read. A misbehaving
// endpoint returning a gigabyte of HTML must not be able to exhaust the
// server's memory.
const maxReplyBytes = 256 << 10

// callProvider dispatches to the right wire format.
func (g *Gateway) callProvider(ctx context.Context, s Settings, ev Event) (string, error) {
	switch s.Provider {
	case ProviderAnthropic:
		return g.callAnthropic(ctx, s, ev)
	case ProviderAzureOpenAI:
		return g.callAzureOpenAI(ctx, s, ev)
	case ProviderOllama, ProviderOpenAI:
		return g.callOpenAICompatible(ctx, s, ev)
	default:
		return "", fmt.Errorf("provider %q is not a network provider", s.Provider)
	}
}

// callOpenAICompatible calls the `/chat/completions` endpoint both OpenAI and
// Ollama expose. The two differ only in the default endpoint and the model
// naming, so they share one code path — which is what makes pointing the
// gateway at a new OpenAI-compatible server a configuration change, not a code
// change.
func (g *Gateway) callOpenAICompatible(ctx context.Context, s Settings, ev Event) (string, error) {
	endpoint := strings.TrimRight(baseEndpoint(s), "/") + "/chat/completions"

	body := map[string]any{
		"model": effectiveModel(s),
		"messages": []map[string]string{
			{"role": "system", "content": SystemPrompt},
			{"role": "user", "content": UserPrompt(ev)},
		},
		"temperature": s.Temperature,
		"max_tokens":  s.MaxTokens,
		// Ask for structured output where the server supports it; a server that
		// does not simply ignores the field, and the parser is lenient anyway.
		"response_format": map[string]string{"type": "json_object"},
	}
	raw, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if key := strings.TrimSpace(s.APIKey); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}

	payload, status, err := g.do(req)
	if err != nil {
		return "", err
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("HTTP %d: %s", status, snippet(payload))
	}

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		return "", fmt.Errorf("decode reply: %w", err)
	}
	if out.Error != nil && out.Error.Message != "" {
		return "", errors.New(out.Error.Message)
	}
	if len(out.Choices) == 0 || strings.TrimSpace(out.Choices[0].Message.Content) == "" {
		return "", errors.New("the model returned no content")
	}
	return out.Choices[0].Message.Content, nil
}

// callAzureOpenAI calls an Azure deployment. Azure differs from OpenAI in three
// ways that matter: the deployment name is a path segment, `api-version` is a
// required query parameter, and the credential travels in an `api-key` header
// rather than an Authorization bearer.
func (g *Gateway) callAzureOpenAI(ctx context.Context, s Settings, ev Event) (string, error) {
	base := strings.TrimRight(baseEndpoint(s), "/")
	if base == "" {
		return "", errors.New("azure_openai requires a resource endpoint")
	}
	deployment := effectiveModel(s)
	if strings.TrimSpace(deployment) == "" {
		return "", errors.New("azure_openai requires a deployment name")
	}
	apiVersion := strings.TrimSpace(s.APIVersion)
	if apiVersion == "" {
		apiVersion = "2024-08-01-preview"
	}

	endpoint := fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s",
		base, url.PathEscape(deployment), url.QueryEscape(apiVersion))

	body := map[string]any{
		"messages": []map[string]string{
			{"role": "system", "content": SystemPrompt},
			{"role": "user", "content": UserPrompt(ev)},
		},
		"temperature":     s.Temperature,
		"max_tokens":      s.MaxTokens,
		"response_format": map[string]string{"type": "json_object"},
	}
	raw, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("api-key", strings.TrimSpace(s.APIKey))

	payload, status, err := g.do(req)
	if err != nil {
		return "", err
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("HTTP %d: %s", status, snippet(payload))
	}

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		return "", fmt.Errorf("decode reply: %w", err)
	}
	if out.Error != nil && out.Error.Message != "" {
		return "", errors.New(out.Error.Message)
	}
	if len(out.Choices) == 0 || strings.TrimSpace(out.Choices[0].Message.Content) == "" {
		return "", errors.New("the model returned no content")
	}
	return out.Choices[0].Message.Content, nil
}

// callAnthropic calls the Messages API, which uses a distinct request/response
// shape: a top-level `system` string, `max_tokens` mandatory, and content
// returned as an array of blocks.
func (g *Gateway) callAnthropic(ctx context.Context, s Settings, ev Event) (string, error) {
	base := strings.TrimRight(baseEndpoint(s), "/")
	if base == "" {
		base = DefaultEndpoint(ProviderAnthropic)
	}
	endpoint := base + "/v1/messages"

	body := map[string]any{
		"model":       effectiveModel(s),
		"max_tokens":  s.MaxTokens,
		"temperature": s.Temperature,
		"system":      SystemPrompt,
		"messages": []map[string]string{
			{"role": "user", "content": UserPrompt(ev)},
		},
	}
	raw, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("x-api-key", strings.TrimSpace(s.APIKey))

	payload, status, err := g.do(req)
	if err != nil {
		return "", err
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("HTTP %d: %s", status, snippet(payload))
	}

	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		return "", fmt.Errorf("decode reply: %w", err)
	}
	if out.Error != nil && out.Error.Message != "" {
		return "", errors.New(out.Error.Message)
	}
	var sb strings.Builder
	for _, block := range out.Content {
		if block.Type == "text" {
			sb.WriteString(block.Text)
		}
	}
	if strings.TrimSpace(sb.String()) == "" {
		return "", errors.New("the model returned no content")
	}
	return sb.String(), nil
}

// do performs one request and returns the bounded body and status. A transport
// error is returned as-is so the caller's fallback reason names the real cause
// (a refused connection reads very differently from an auth rejection).
func (g *Gateway) do(req *http.Request) ([]byte, int, error) {
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("could not reach the model endpoint: %w", err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes))
	return payload, resp.StatusCode, nil
}

// TestResult reports a connectivity probe's outcome.
type TestResult struct {
	OK         bool
	Provider   string
	Endpoint   string
	Model      string
	Detail     string
	LatencyMS  int64
	BlastCheck string
}

// Test performs a minimal live call so an operator can validate credentials and
// reachability without touching a real event. It runs the same provider path as
// a real analysis against a synthetic change, so a passing test genuinely proves
// the configuration works end to end rather than only that DNS resolves.
func (g *Gateway) Test(ctx context.Context, s Settings) TestResult {
	s = NormalizeSettings(s)
	res := TestResult{
		Provider: string(s.Provider),
		Endpoint: baseEndpoint(s),
		Model:    effectiveModel(s),
	}
	if s.Provider == ProviderDeterministic {
		res.OK = true
		res.Detail = "Built-in offline heuristics are active; no model or network required."
		return res
	}
	if !s.Enabled {
		res.OK = false
		res.Detail = "Live AI calls are disabled; analysis will use the built-in offline heuristics."
		return res
	}
	if !NeedsNetwork(s.Provider) {
		res.OK = true
		res.Detail = "This provider does not require a live connection."
		return res
	}
	if strings.TrimSpace(s.Endpoint) == "" && DefaultEndpoint(s.Provider) == "" {
		res.OK = false
		res.Detail = "An endpoint URL is required for " + ProviderLabel(string(s.Provider)) + "."
		return res
	}

	budget := time.Duration(s.TimeoutSeconds) * time.Second
	if budget > 30*time.Second {
		budget = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	probe := Event{
		ID:         "00000000-0000-4000-8000-0000000000ff",
		Host:       "prod-web-01",
		OSFamily:   "linux",
		Level:      1,
		LevelLabel: "Level 1 · Critical",
		Category:   "Configuration",
		Action:     "Modified",
		Summary:    "Modified /etc/nginx/nginx.conf (+12 -3)",
		TargetType: "file",
		PathOrKey:  "/etc/nginx/nginx.conf",
		Actor:      "alice",
		Process:    "vim",
		Diff:       "--- a/etc/nginx/nginx.conf\n+++ b/etc/nginx/nginx.conf\n@@ -1 +1 @@\n-server 10.0.0.4;\n+server 10.0.0.9;\n",
	}

	started := g.now()
	reply, err := g.callProvider(ctx, s, probe)
	res.LatencyMS = g.now().Sub(started).Milliseconds()
	if err != nil {
		res.OK = false
		res.Detail = err.Error()
		return res
	}
	parsed, err := parseModelReply(reply)
	if err != nil {
		res.OK = false
		res.Detail = "the model replied, but its answer was not valid analysis JSON: " + err.Error()
		return res
	}
	res.OK = true
	res.BlastCheck = normalizeBlastRadius(parsed.BlastRadius)
	res.Detail = fmt.Sprintf("connected in %d ms · model returned a %s blast-radius assessment",
		res.LatencyMS, res.BlastCheck)
	return res
}

// baseEndpoint resolves the configured endpoint, falling back to the provider's
// documented default so a blank field means "the usual address" rather than an
// error.
func baseEndpoint(s Settings) string {
	if e := strings.TrimSpace(s.Endpoint); e != "" {
		return e
	}
	return DefaultEndpoint(s.Provider)
}

// SystemPrompt instructs the model. It is a constant so the prompt can be
// asserted on in a test and reviewed in one place — the security review of this
// package is, in effect, a review of this string.
const SystemPrompt = `You are StateTrack's change-risk analyzer for production infrastructure.

You will receive one recorded configuration change: the affected host, the
actor lineage, and the SCRUBBED unified diff. Secret-looking values in the diff
have already been replaced with [REDACTED:sha256:...] stubs at the host, before
the change was transmitted. Never speculate about redacted values, and never ask
for the original content.

Answer the operator's three questions:
1. How does this change impact the workload, in at most two sentences?
2. How bad is the blast radius if it is wrong: Low, Medium or High?
3. What is the exact command to safely roll it back, and what command proves
   the service is healthy afterwards?

Rules for the rollback command:
- It must be runnable as written on the affected platform (bash for Linux,
  powershell.exe syntax for Windows, kubectl for a Kubernetes resource).
- Validate before reloading where the service supports it (nginx -t,
  apachectl configtest, haproxy -c).
- If no safe generic command exists, leave it empty and explain why in
  rollback_notes. Do NOT invent a backup path you were not shown.

Reply with ONLY a JSON object, no prose and no code fences:
{
  "risk_summary": "one or two sentences",
  "blast_radius": "Low" | "Medium" | "High",
  "affected_services": ["..."],
  "rollback_command": "shell command or empty string",
  "verification_command": "shell command or empty string",
  "rollback_notes": "one caveat, or empty string"
}`

// UserPrompt renders the change as a compact, deterministic block. Fields are
// emitted in a fixed order and metadata keys are sorted, so the same event
// always produces the same prompt — which makes a model's answer reproducible
// and a prompt-injection diff visible in a review.
func UserPrompt(ev Event) string {
	var sb strings.Builder
	sb.WriteString("CHANGE\n")
	writeField(&sb, "event_id", ev.ID)
	writeField(&sb, "host", ev.Host)
	writeField(&sb, "os_family", ev.OSFamily)
	writeField(&sb, "severity", ev.LevelLabel)
	writeField(&sb, "category", ev.Category)
	writeField(&sb, "action", ev.Action)
	writeField(&sb, "target_type", ev.TargetType)
	writeField(&sb, "path_or_key", ev.PathOrKey)
	writeField(&sb, "summary", ev.Summary)
	writeField(&sb, "actor", ev.Actor)
	writeField(&sb, "process", ev.Process)
	writeField(&sb, "originating_ip", ev.RemoteIP)
	writeField(&sb, "matched_rule", ev.RuleName)
	writeField(&sb, "command_line", ev.Cmdline)

	if len(ev.Metadata) > 0 {
		keys := make([]string, 0, len(ev.Metadata))
		for k := range ev.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sb.WriteString("\nMETADATA\n")
		for _, k := range keys {
			writeField(&sb, k, ev.Metadata[k])
		}
	}

	sb.WriteString("\nSCRUBBED UNIFIED DIFF\n")
	if strings.TrimSpace(ev.Diff) == "" {
		sb.WriteString("(no text diff recorded; hashes and metadata only)\n")
	} else {
		sb.WriteString("```diff\n")
		sb.WriteString(strings.TrimRight(ev.Diff, "\n"))
		sb.WriteString("\n```\n")
	}
	return sb.String()
}

// writeField emits one `key: value` line, skipping empty values so the prompt
// does not carry a wall of blank fields.
func writeField(sb *strings.Builder, key, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	fmt.Fprintf(sb, "%s: %s\n", key, value)
}

// snippet trims a provider's error body for an error message.
func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	if s == "" {
		return "(empty response)"
	}
	return s
}
