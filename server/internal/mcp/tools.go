package mcp

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Tool is a tool definition as returned by `tools/list`.
//
// InputSchema is a JSON Schema object. It is built by the helpers below rather
// than written as a string literal so the properties, the required list and the
// documentation cannot drift apart: a schema that documents a parameter it does
// not declare is worse than no schema, because a model will confidently send the
// documented name and the server will reject it.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// ToolNames lists the exposed tools in the order they should be presented. The
// order is deliberate: it is roughly the order an engineer investigates an
// incident in — find the change, read the diff, check the host, get the
// rollback, write it up.
var ToolNames = []string{
	"statetrack_list_changes",
	"statetrack_get_diff",
	"statetrack_get_host_summary",
	"statetrack_analyze_and_rollback",
	"statetrack_export_postmortem",
}

// Tools returns the tool definitions.
func Tools() []Tool {
	return []Tool{
		listChangesTool(),
		getDiffTool(),
		getHostSummaryTool(),
		analyzeAndRollbackTool(),
		exportPostmortemTool(),
	}
}

// ScopeRead gates every tool on this server.
//
// The name matches the vocabulary the console mints keys with. It is
// deliberately distinct from `read:summary` so an operator can authorise a
// Checkmk poller to read the host rollup without also handing it a conversational
// interface to the whole change stream — the two are different capabilities and
// conflating them would mean granting one grants both.
const ScopeRead = "read:mcp"

func listChangesTool() Tool {
	return Tool{
		Name: "statetrack_list_changes",
		Description: strings.TrimSpace(`
List recently recorded infrastructure changes, newest first.
Use this to find the change behind an incident before asking for its diff, or to
see everything that happened on a host in a window.
Filters combine with AND; omit one to leave it open.`) + "\n\n" +
			"Each result includes the event id, which is the argument for " +
			"statetrack_get_diff and statetrack_analyze_and_rollback.",
		InputSchema: schema(map[string]any{
			"host": prop("string", "Hostname to filter by, exactly as the agent reports it (e.g. prod-web-01)."),
			"impact_level": enumProp([]string{"1", "2", "3", "4"},
				"Impact level: 1 critical, 2 grouped transaction, 3 drift, 4 forensic sampling."),
			"category": enumProp([]string{
				"config", "package", "service", "user", "registry", "network", "process", "agent_health",
			}, "Change category."),
			"search":    prop("string", "Substring match against the change summary and target path."),
			"actor":     prop("string", "Filter by the username the change is attributed to."),
			"window":    prop("string", "How far back to look. A Go duration (30m, 2h) or a day count (7d). Default 24h."),
			"limit":     prop("integer", "Maximum changes to return, 1-200. Default 25."),
			"root_only": prop("boolean", "Exclude aggregated child rows inside a Level 2 transaction. Default true."),
		}, nil),
	}
}

func getDiffTool() Tool {
	return Tool{
		Name: "statetrack_get_diff",
		Description: strings.TrimSpace(`
Fetch the scrubbed unified diff and the actor lineage for one change event.
The id comes from statetrack_list_changes. The diff has secret-looking values
replaced with [REDACTED:sha256:...] stubs at the host, so it is safe to read and
to quote; do not attempt to reconstruct the original values.`),
		InputSchema: schema(map[string]any{
			"event_id": prop("string", "The change event id (a UUID) from statetrack_list_changes."),
		}, []string{"event_id"}),
	}
}

func getHostSummaryTool() Tool {
	return Tool{
		Name: "statetrack_get_host_summary",
		Description: strings.TrimSpace(`
Report a host's or Kubernetes cluster's current health: online status, how many
configuration targets it tracks, a per-level count of changes in the window, and
the most recent critical change.
Accepts a hostname (prod-web-01) or a cluster/host id. Use it to answer "is this
box healthy?" rather than listing its changes.`),
		InputSchema: schema(map[string]any{
			"host":   prop("string", "Hostname or host/cluster id, as returned by statetrack_list_changes."),
			"window": prop("string", "Change window to roll up. A Go duration (15m, 1h) or a day count (7d). Default 1h."),
		}, []string{"host"}),
	}
}

func analyzeAndRollbackTool() Tool {
	return Tool{
		Name: "statetrack_analyze_and_rollback",
		Description: strings.TrimSpace(`
Assess the operational risk of one change and return the exact command to undo it.
Answers: how the change impacts the workload, its blast radius (Low/Medium/High),
a copy-pasteable rollback command for the affected platform, and a verification
command to prove the service is healthy afterwards.
The analysis runs the operator's configured AI provider, or the built-in offline
heuristics when no model is configured. The response states which engine answered,
so you can tell a model's judgement from a rule-based one. Treat a rollback command
as a proposal to show the operator, not as something to execute.`),
		InputSchema: schema(map[string]any{
			"event_id": prop("string", "The change event id (a UUID) to analyze."),
		}, []string{"event_id"}),
	}
}

func exportPostmortemTool() Tool {
	return Tool{
		Name: "statetrack_export_postmortem",
		Description: strings.TrimSpace(`
Generate the Markdown post-mortem bundle for an incident change: executive
summary, change-control verdict, root-cause attribution, the scrubbed diff, the
correlated timeline, the rollback plan, monitoring links and the audit trail.
Use this to write an incident report, or to gather all the facts about one event
in a single call.`),
		InputSchema: schema(map[string]any{
			"event_id": prop("string", "The incident change event id (a UUID)."),
			"window":   prop("string", "Corroborating window either side of the incident. A Go duration (30m, 2h) or a day count. Default 30m, capped at 24h."),
			"format":   enumProp([]string{"markdown", "json"}, "Return the Markdown document, or the structured bundle. Default markdown."),
		}, []string{"event_id"}),
	}
}

// schema assembles a JSON Schema object. Required keys are emitted only when
// non-empty, because an explicit empty `required` array is accepted by some
// clients and rejected by others, and omitting it is universally correct.
func schema(properties map[string]any, required []string) json.RawMessage {
	out := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		sorted := append([]string(nil), required...)
		sort.Strings(sorted)
		out["required"] = sorted
	}
	raw, err := json.Marshal(out)
	if err != nil {
		// The map is built from constants, so marshalling cannot fail. A panic
		// is correct here: a tool that ships without a schema would be silently
		// uncallable, which is a build-time bug, not a runtime condition.
		panic("mcp: cannot encode tool schema: " + err.Error())
	}
	return raw
}

func prop(kind, description string) map[string]any {
	return map[string]any{"type": kind, "description": description}
}

func enumProp(values []string, description string) map[string]any {
	return map[string]any{"type": "string", "description": description, "enum": values}
}

/* -------------------------------------------------------------------------- */
/* Argument decoding                                                          */
/* -------------------------------------------------------------------------- */

// Args is a decoded `tools/call` argument object, with typed accessors that
// report a named-field error rather than silently coercing a bad value.
//
// The point of routing every read through these is that validation and the error
// message stay together: a handler cannot accidentally accept `limit: "banana"`
// as zero, and a model that sends one gets told exactly which field was wrong.
type Args struct {
	name string
	raw  map[string]json.RawMessage
}

// Call is a decoded `tools/call` request: the tool to run and its arguments.
type Call struct {
	Name string
	Args *Args
}

// DecodeCall parses the params object of a tools/call request.
//
// A missing arguments object is valid: the required-field decision belongs to
// the accessor for each field, which is the only place that knows whether the
// field is required. A task that tried to enforce required fields here would
// need the per-tool schema, which is exactly what the accessor approach avoids
// duplicating.
func DecodeCall(params json.RawMessage) (Call, error) {
	if len(params) == 0 {
		return Call{}, NewFieldError("name", "tools/call requires a params object with a name")
	}
	var body struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &body); err != nil {
		return Call{}, NewError(CodeInvalidParams, "the params object could not be decoded: %v", err)
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		return Call{}, NewFieldError("name", "params.name is required and must name a tool")
	}
	args := &Args{name: name, raw: map[string]json.RawMessage{}}
	if len(body.Arguments) == 0 || string(body.Arguments) == "null" {
		return Call{Name: name, Args: args}, nil
	}
	if err := json.Unmarshal(body.Arguments, &args.raw); err != nil {
		return Call{}, NewFieldError("arguments", "arguments must be a JSON object, got %s", summarize(body.Arguments))
	}
	return Call{Name: name, Args: args}, nil
}

// Name returns the tool the call names.
func (a *Args) Name() string { return a.name }

// String returns an optional string field. A field that is present but the wrong
// type is an error, not a zero value: silently dropping a `host` filter would
// return the whole fleet and read as a successful answer to a narrower question.
func (a *Args) String(field string) (string, error) {
	raw, ok := a.raw[field]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", NewFieldError(field, "%s must be a string, got %s", field, summarize(raw))
	}
	return strings.TrimSpace(s), nil
}

// RequiredString returns a string field, erroring when it is absent or blank.
func (a *Args) RequiredString(field string) (string, error) {
	s, err := a.String(field)
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", NewFieldError(field, "%s is required", field)
	}
	return s, nil
}

// Int returns an optional integer field, clamped to [min, max]. A value outside
// the range is clamped rather than refused: asking for 10,000 rows is a mistaken
// request, not an attack, and returning 200 is more useful than an error.
func (a *Args) Int(field string, min, max, def int) (int, error) {
	raw, ok := a.raw[field]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return def, nil
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		// Accept a string-encoded number: several clients serialize every
		// argument as a string, and rejecting that would make the tool
		// uncallable from them for no benefit.
		var s string
		if err2 := json.Unmarshal(raw, &s); err2 != nil {
			return 0, NewFieldError(field, "%s must be an integer, got %s", field, summarize(raw))
		}
		if _, err2 := fmt.Sscanf(s, "%d", &n); err2 != nil {
			return 0, NewFieldError(field, "%s must be an integer, got %q", field, s)
		}
	}
	if n < min {
		return min, nil
	}
	if n > max {
		return max, nil
	}
	return n, nil
}

// Bool returns an optional boolean field, with a default when absent.
func (a *Args) Bool(field string, def bool) (bool, error) {
	raw, ok := a.raw[field]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return def, nil
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		var s string
		if err2 := json.Unmarshal(raw, &s); err2 != nil {
			return false, NewFieldError(field, "%s must be a boolean, got %s", field, summarize(raw))
		}
		switch strings.ToLower(s) {
		case "true", "1", "yes":
			return true, nil
		case "false", "0", "no", "":
			return false, nil
		default:
			return false, NewFieldError(field, "%s must be a boolean, got %q", field, s)
		}
	}
	return b, nil
}

// Enum returns an optional field constrained to a closed set. The error lists
// the accepted values, which is what lets a model emit a valid call on retry
// rather than trying another guess.
func (a *Args) Enum(field string, allowed []string, def string) (string, error) {
	s, err := a.String(field)
	if err != nil {
		return "", err
	}
	if s == "" {
		return def, nil
	}
	lower := strings.ToLower(s)
	for _, want := range allowed {
		if lower == want {
			return want, nil
		}
	}
	return "", NewFieldError(field, "%s must be one of %s, got %q",
		field, strings.Join(allowed, ", "), s)
}

// Window parses a duration field into an absolute lower bound.
//
// It accepts the Go duration forms ("30m", "2h") plus a day count ("7d"), which
// is what an operator or a model naturally writes. The bound is returned as a
// time rather than a duration because every caller needs the absolute instant,
// and computing it once here means the storage layer's clock and the caller's
// cannot disagree.
func (a *Args) Window(field string, def, max time.Duration) (time.Duration, error) {
	s, err := a.String(field)
	if err != nil {
		return 0, err
	}
	if s == "" {
		return def, nil
	}
	d, err := ParseWindow(s)
	if err != nil {
		return 0, NewFieldError(field, "%s: %v", field, err)
	}
	if d <= 0 {
		return 0, NewFieldError(field, "%s must be positive, got %q", field, s)
	}
	if max > 0 && d > max {
		return max, nil
	}
	return d, nil
}

// ParseWindow parses the human duration forms accepted by the tools.
func ParseWindow(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return 0, fmt.Errorf("empty window")
	}
	// A bare "7" or "24" reads as hours, which is the more useful interpretation
	// for a change window than seconds.
	if n, err := time.ParseDuration(raw + "h"); err == nil {
		return n, nil
	}
	var days float64
	if _, err := fmt.Sscanf(raw, "%fd", &days); err == nil {
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid window %q: use forms like 30m, 6h or 7d", raw)
	}
	return d, nil
}

// summarize renders a raw JSON value for an error message, truncated so a
// gigabyte argument cannot be echoed back to the caller.
func summarize(raw json.RawMessage) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > 60 {
		s = s[:60] + "…"
	}
	if s == "" {
		s = "nothing"
	}
	return s
}
