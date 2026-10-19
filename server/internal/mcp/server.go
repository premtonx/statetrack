package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Caller identifies who is asking. It is deliberately tiny: this package needs
// to enforce scopes and to scope every read to one org, and nothing else about a
// principal is the protocol's business.
type Caller struct {
	// OrgID scopes every read. A tool call must never be able to span orgs, so
	// it is required rather than optional — an empty value is rejected at the
	// transport rather than silently returning another tenant's data.
	OrgID string
	// Name is recorded in logs and shown in the analyze/post-mortem output as
	// the requester, so an operator can see which client pulled a bundle.
	Name string
	// Scopes are the permissions the credential carries. An empty slice means
	// "a console session", which is unrestricted: scope enforcement is a
	// property of machine credentials, matching the HTTP API's convention.
	Scopes []string
}

// Allowed reports whether the caller's credential carries a scope.
func (c Caller) Allowed(scope string) bool {
	if len(c.Scopes) == 0 {
		// A session (a human in the console) is not subject to machine scopes.
		return true
	}
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// Backend is the data access every tool resolves through. The MCP package never
// touches storage directly, which is what lets the protocol be tested without a
// database and lets the stdio binary share the identical dispatch over HTTP.
type Backend interface {
	// ListChanges returns recent changes matching the filter, newest first.
	ListChanges(ctx context.Context, caller Caller, f ChangeFilter) ([]Change, error)
	// GetDiff returns one change's scrubbed diff and actor lineage.
	GetDiff(ctx context.Context, caller Caller, eventID string) (Diff, error)
	// HostSummary returns the health rollup for a host or cluster.
	HostSummary(ctx context.Context, caller Caller, host string, window time.Duration) (HostSummary, error)
	// Analyze runs the configured analyzer over one change.
	Analyze(ctx context.Context, caller Caller, eventID string) (Analysis, error)
	// PostMortem renders the incident bundle for one change.
	PostMortem(ctx context.Context, caller Caller, eventID string, window time.Duration, format string) (PostMortem, error)
}

/* -------------------------------------------------------------------------- */
/* Backend value types                                                        */
/* -------------------------------------------------------------------------- */

// ChangeFilter is the decoded, validated argument set for statetrack_list_changes.
//
// It is a struct of already-parsed values rather than the raw JSON, so a backend
// implementation cannot be handed an unvalidated string and make its own
// interpretation of what "7d" means. Parsing and validation happen exactly once,
// in the tool layer.
type ChangeFilter struct {
	Host        string
	ImpactLevel int
	Category    int
	Search      string
	Actor       string
	Window      time.Duration
	Limit       int
	RootOnly    bool
}

// Change is one change as the MCP client sees it. It is a flat, stable shape
// rather than the storage row: a client pins to these field names, so a schema
// change to the events table must not silently alter a tool's output.
type Change struct {
	ID         string `json:"id"`
	Host       string `json:"host"`
	OccurredAt string `json:"occurred_at"`
	Level      int32  `json:"level"`
	LevelLabel string `json:"level_label"`
	Category   string `json:"category"`
	Action     string `json:"action"`
	Summary    string `json:"summary"`
	TargetType string `json:"target_type"`
	PathOrKey  string `json:"path_or_key"`
	Actor      string `json:"actor,omitempty"`
	Process    string `json:"process,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	RuleName   string `json:"rule_name,omitempty"`
	HasDiff    bool   `json:"has_diff"`
	ChildCount int32  `json:"child_count"`
}

// Diff is the statetrack_get_diff result: the scrubbed diff plus the lineage
// that answers "who did this and how did they get in".
type Diff struct {
	ID           string `json:"id"`
	Host         string `json:"host"`
	OccurredAt   string `json:"occurred_at"`
	Level        int32  `json:"level"`
	LevelLabel   string `json:"level_label"`
	Summary      string `json:"summary"`
	TargetType   string `json:"target_type"`
	PathOrKey    string `json:"path_or_key"`
	Diff         string `json:"diff,omitempty"`
	DiffRedacted bool   `json:"diff_redacted"`
	HashBefore   string `json:"hash_before,omitempty"`
	HashAfter    string `json:"hash_after,omitempty"`
	// Actor lineage, flattened: SSH source, then the process chain, then the
	// mutating tool. A client renders this as the "who" answer.
	Actor    string   `json:"actor,omitempty"`
	UID      string   `json:"uid,omitempty"`
	RemoteIP string   `json:"remote_ip,omitempty"`
	Process  string   `json:"process,omitempty"`
	Cmdline  string   `json:"cmdline,omitempty"`
	Lineage  []string `json:"lineage,omitempty"`
	// Children are the aggregated changes inside a Level 2 transaction.
	Children []Change `json:"children,omitempty"`
}

// HostSummary is the statetrack_get_host_summary result.
type HostSummary struct {
	Host              string           `json:"host"`
	OS                string           `json:"os,omitempty"`
	Online            bool             `json:"online"`
	LastSeenSeconds   int64            `json:"last_seen_seconds"`
	Window            string           `json:"window"`
	DriftTargetsCount int64            `json:"drift_targets_count"`
	Counts            map[string]int64 `json:"counts"`
	LatestCritical    *Change          `json:"latest_critical,omitempty"`
	ConsoleURL        string           `json:"console_url,omitempty"`
}

// Analysis is the statetrack_analyze_and_rollback result. It mirrors the HTTP
// endpoint's payload so a client that uses both sees one shape.
type Analysis struct {
	EventID             string   `json:"event_id"`
	Provider            string   `json:"provider"`
	ProviderLabel       string   `json:"provider_label"`
	Model               string   `json:"model,omitempty"`
	RiskSummary         string   `json:"risk_summary"`
	BlastRadius         string   `json:"blast_radius"`
	AffectedServices    []string `json:"affected_services,omitempty"`
	RollbackCommand     string   `json:"rollback_command,omitempty"`
	VerificationCommand string   `json:"verification_command,omitempty"`
	RollbackNotes       string   `json:"rollback_notes,omitempty"`
	Fallback            bool     `json:"fallback"`
	FallbackReason      string   `json:"fallback_reason,omitempty"`
	Scrubbed            bool     `json:"scrubbed"`
	LatencyMS           int64    `json:"latency_ms"`
}

// PostMortem is the statetrack_export_postmortem result.
type PostMortem struct {
	EventID  string `json:"event_id"`
	Filename string `json:"filename"`
	Format   string `json:"format"`
	Markdown string `json:"markdown"`
	// Structured is the JSON bundle, present only when format=json. It embeds
	// the same Markdown, so a client never has to choose between them.
	Structured any `json:"structured,omitempty"`
}

/* -------------------------------------------------------------------------- */
/* Server                                                                     */
/* -------------------------------------------------------------------------- */

// Server dispatches JSON-RPC requests to a Backend. It is stateless and safe for
// concurrent use.
type Server struct {
	backend Backend
	// now is injectable so a test can pin the window bounds and the serverInfo.
	now func() time.Time
}

// Option customises a Server.
type Option func(*Server)

// WithClock substitutes the clock, so a test can assert stable window bounds.
func WithClock(now func() time.Time) Option {
	return func(s *Server) {
		if now != nil {
			s.now = now
		}
	}
}

// New builds a Server over a backend.
func New(backend Backend, opts ...Option) *Server {
	s := &Server{backend: backend, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Handle processes one JSON-RPC request and returns the response. A nil response
// means the request was a notification and nothing should be written back.
//
// Every error path is converted into a JSON-RPC error object rather than
// returned: the protocol has no notion of a failed connection once a request is
// being handled, so a transport that propagated an error would have to invent
// framing semantics that clients do not expect.
func (s *Server) Handle(ctx context.Context, caller Caller, raw []byte) *Response {
	var req Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return &Response{JSONRPC: JSONRPCVersion, Error: NewError(CodeParseError,
			"the request body is not valid JSON: %v", err)}
	}
	return s.handle(ctx, caller, req)
}

func (s *Server) handle(ctx context.Context, caller Caller, req Request) *Response {
	// A notification gets no response. The id is echoed only when it is present,
	// which is what keeps a numeric id numeric.
	if req.IsNotification() {
		return nil
	}
	resp := &Response{JSONRPC: JSONRPCVersion, ID: req.ID}

	if req.JSONRPC != "" && req.JSONRPC != JSONRPCVersion {
		resp.Error = NewError(CodeInvalidRequest,
			"jsonrpc must be %q, got %q", JSONRPCVersion, req.JSONRPC)
		return resp
	}

	switch req.Method {
	case "initialize":
		resp.Result = s.initialize()
	case "ping":
		// The spec's ping returns an empty result, not a payload.
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": Tools()}
	case "tools/call":
		result, callErr := s.callTool(ctx, caller, req.Params)
		if callErr != nil {
			resp.Error = callErr
			return resp
		}
		resp.Result = result
	case "notifications/initialized", "notifications/cancelled":
		// Acknowledged and ignored: this server holds no per-session state, so
		// there is nothing to initialize or cancel. These arrive as
		// notifications, but a client that mistakenly stamps an id on one must
		// still get a valid empty result rather than a method-not-found.
		resp.Result = map[string]any{}
	default:
		resp.Error = NewError(CodeMethodNotFound, "unknown method %q", req.Method)
	}
	return resp
}

// initialize is the handshake result: the protocol revision, this build's
// identity, and the capabilities the client uses to decide what to expose.
func (s *Server) initialize() map[string]any {
	return map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities": map[string]any{
			// Only tools. Advertising resources or prompts this server does not
			// serve would make a client show empty panes.
			"tools": map[string]any{"listChanged": false},
		},
		"serverInfo": map[string]any{
			"name":    ServerName,
			"version": ServerVersion,
		},
		"instructions": "StateTrack exposes recorded infrastructure changes. Start with " +
			"statetrack_list_changes to find the event id, then statetrack_get_diff to read it, " +
			"statetrack_get_host_summary to check host health, statetrack_analyze_and_rollback for " +
			"the rollback plan, and statetrack_export_postmortem to write the incident report.",
	}
}

// callTool validates the arguments and dispatches to the backend.
func (s *Server) callTool(ctx context.Context, caller Caller, params json.RawMessage) (ToolResult, *Error) {
	call, err := DecodeCall(params)
	if err != nil {
		return ToolResult{}, AsError(err)
	}
	if !knownTool(call.Name) {
		// A distinct code from method-not-found: the JSON-RPC method exists, the
		// tool name does not. The message lists what does, so a model can retry.
		return ToolResult{}, NewError(CodeInvalidParams,
			"unknown tool %q; available tools: %s", call.Name, strings.Join(ToolNames, ", "))
	}
	if s.backend == nil {
		return ToolResult{}, NewError(CodeInternalError, "no backend is configured")
	}
	if caller.OrgID == "" {
		return ToolResult{}, NewError(CodeForbidden, "the credential is not scoped to an organisation")
	}
	// One scope gates the whole surface, checked once so a new tool cannot be
	// added without inheriting it. The analyzer's own cost is controlled
	// separately by the AI gateway's enabled flag — an operator who does not want
	// live model calls turns them off and the deterministic engine answers for
	// free — so a second scope here would guard nothing that setting does not.
	if !caller.Allowed(ScopeRead) {
		return ToolResult{}, NewError(CodeForbidden,
			"this credential does not carry the %s scope", ScopeRead)
	}

	switch call.Name {
	case "statetrack_list_changes":
		return s.listChanges(ctx, caller, call.Args)
	case "statetrack_get_diff":
		return s.getDiff(ctx, caller, call.Args)
	case "statetrack_get_host_summary":
		return s.getHostSummary(ctx, caller, call.Args)
	case "statetrack_analyze_and_rollback":
		return s.analyzeAndRollback(ctx, caller, call.Args)
	case "statetrack_export_postmortem":
		return s.exportPostMortem(ctx, caller, call.Args)
	default:
		// Unreachable: knownTool gated this. Kept explicit so adding a name to
		// ToolNames without a case is a compile-time-visible omission in review
		// rather than a silent fallthrough.
		return ToolResult{}, NewError(CodeInvalidParams, "tool %q is not implemented", call.Name)
	}
}

func knownTool(name string) bool {
	for _, n := range ToolNames {
		if n == name {
			return true
		}
	}
	return false
}

/* -------------------------------------------------------------------------- */
/* Tool handlers                                                              */
/* -------------------------------------------------------------------------- */

func (s *Server) listChanges(ctx context.Context, caller Caller, args *Args) (ToolResult, *Error) {
	host, err := args.String("host")
	if err != nil {
		return ToolResult{}, AsError(err)
	}
	search, err := args.String("search")
	if err != nil {
		return ToolResult{}, AsError(err)
	}
	actor, err := args.String("actor")
	if err != nil {
		return ToolResult{}, AsError(err)
	}
	level, err := args.Enum("impact_level", []string{"1", "2", "3", "4"}, "")
	if err != nil {
		return ToolResult{}, AsError(err)
	}
	category, err := args.Enum("category", categoryArgs(), "")
	if err != nil {
		return ToolResult{}, AsError(err)
	}
	window, err := args.Window("window", 24*time.Hour, 30*24*time.Hour)
	if err != nil {
		return ToolResult{}, AsError(err)
	}
	limit, err := args.Int("limit", 1, 200, 25)
	if err != nil {
		return ToolResult{}, AsError(err)
	}
	rootOnly, err := args.Bool("root_only", true)
	if err != nil {
		return ToolResult{}, AsError(err)
	}

	filter := ChangeFilter{
		Host:        host,
		ImpactLevel: levelNumber(level),
		Category:    categoryNumber(category),
		Search:      search,
		Actor:       actor,
		Window:      window,
		Limit:       limit,
		RootOnly:    rootOnly,
	}
	changes, err := s.backend.ListChanges(ctx, caller, filter)
	if err != nil {
		return s.toolFailure(err)
	}
	if changes == nil {
		changes = []Change{}
	}
	return ToolResult{
		Content:           TextContent(RenderChanges(changes, filter)),
		StructuredContent: map[string]any{"changes": changes, "count": len(changes)},
	}, nil
}

func (s *Server) getDiff(ctx context.Context, caller Caller, args *Args) (ToolResult, *Error) {
	eventID, err := args.RequiredString("event_id")
	if err != nil {
		return ToolResult{}, AsError(err)
	}
	diff, backendErr := s.backend.GetDiff(ctx, caller, eventID)
	if backendErr != nil {
		return s.toolFailure(backendErr)
	}
	return ToolResult{
		Content:           TextContent(RenderDiff(diff)),
		StructuredContent: diff,
	}, nil
}

func (s *Server) getHostSummary(ctx context.Context, caller Caller, args *Args) (ToolResult, *Error) {
	host, err := args.RequiredString("host")
	if err != nil {
		return ToolResult{}, AsError(err)
	}
	window, err := args.Window("window", time.Hour, 30*24*time.Hour)
	if err != nil {
		return ToolResult{}, AsError(err)
	}
	summary, backendErr := s.backend.HostSummary(ctx, caller, host, window)
	if backendErr != nil {
		return s.toolFailure(backendErr)
	}
	return ToolResult{
		Content:           TextContent(RenderHostSummary(summary)),
		StructuredContent: summary,
	}, nil
}

func (s *Server) analyzeAndRollback(ctx context.Context, caller Caller, args *Args) (ToolResult, *Error) {
	eventID, err := args.RequiredString("event_id")
	if err != nil {
		return ToolResult{}, AsError(err)
	}
	analysis, backendErr := s.backend.Analyze(ctx, caller, eventID)
	if backendErr != nil {
		return s.toolFailure(backendErr)
	}
	return ToolResult{
		Content:           TextContent(RenderAnalysis(analysis)),
		StructuredContent: analysis,
	}, nil
}

func (s *Server) exportPostMortem(ctx context.Context, caller Caller, args *Args) (ToolResult, *Error) {
	eventID, err := args.RequiredString("event_id")
	if err != nil {
		return ToolResult{}, AsError(err)
	}
	window, err := args.Window("window", 30*time.Minute, 24*time.Hour)
	if err != nil {
		return ToolResult{}, AsError(err)
	}
	format, err := args.Enum("format", []string{"markdown", "json"}, "markdown")
	if err != nil {
		return ToolResult{}, AsError(err)
	}

	bundle, backendErr := s.backend.PostMortem(ctx, caller, eventID, window, format)
	if backendErr != nil {
		return s.toolFailure(backendErr)
	}
	structured := any(map[string]any{
		"event_id": bundle.EventID,
		"filename": bundle.Filename,
		"format":   bundle.Format,
	})
	if bundle.Structured != nil {
		structured = bundle.Structured
	}
	return ToolResult{
		Content:           TextContent(bundle.Markdown),
		StructuredContent: structured,
	}, nil
}

// toolFailure distinguishes a missing resource from an internal failure.
//
// The distinction is the difference between a model telling its user "there is
// no change with that id" and it reporting "the server is broken", and getting it
// wrong sends a user to debug the wrong system. A *Error from the backend keeps
// its code; a sentinel not-found becomes CodeNotFound; everything else is an
// isError tool result carrying the message, because the model can read and
// explain that but cannot act on a protocol error.
func (s *Server) toolFailure(err error) (ToolResult, *Error) {
	if err == nil {
		return ToolResult{}, nil
	}
	if mcpErr, ok := err.(*Error); ok {
		return ToolResult{}, mcpErr
	}
	if IsNotFound(err) {
		return ToolResult{}, NewError(CodeNotFound, "%s", err.Error())
	}
	return ErrorResult(err), nil
}

/* -------------------------------------------------------------------------- */
/* Argument vocabulary                                                        */
/* -------------------------------------------------------------------------- */

// categoryArgs is the closed set of category names, in the order the proto
// defines them. Named strings rather than numbers because a model choosing
// between "config" and "registry" is far more reliable than one choosing between
// 1 and 5.
func categoryArgs() []string {
	return []string{"config", "package", "service", "user", "registry", "network", "process", "agent_health"}
}

// categoryNumber maps a category name onto the stored numeric value, matching
// pb.Category.
func categoryNumber(name string) int {
	switch name {
	case "config":
		return 1
	case "package":
		return 2
	case "service":
		return 3
	case "user":
		return 4
	case "registry":
		return 5
	case "network":
		return 6
	case "process":
		return 7
	case "agent_health":
		return 8
	default:
		return 0
	}
}

// levelNumber maps a level string onto its numeric value; an empty level means
// "any".
func levelNumber(level string) int {
	switch level {
	case "1", "2", "3", "4":
		return int(level[0] - '0')
	default:
		return 0
	}
}

// FormatEventID validates that an id looks like one before it reaches storage,
// so a malformed id is a clean not-found rather than a failed UUID cast that
// surfaces as a 500.
func FormatEventID(id string) error {
	id = strings.TrimSpace(id)
	if len(id) != 36 {
		return fmt.Errorf("event_id %q is not a valid change event id", id)
	}
	for i, r := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return fmt.Errorf("event_id %q is not a valid change event id", id)
			}
			continue
		}
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return fmt.Errorf("event_id %q is not a valid change event id", id)
		}
	}
	return nil
}
