// Native Model Context Protocol (MCP) server, over HTTP.
//
// This file is the transport half of internal/mcp: it resolves the console
// credential in the request into a mcp.Caller, and adapts the storage layer onto
// the mcp.Backend interface. The protocol, the tool schemas and the argument
// validation live in the mcp package so the HTTP entry point and the stdio
// binary share them — a client must get the same answer however it connected, and
// the only way to guarantee that is for there to be one implementation.
//
// Nothing here is a "chatbot endpoint": it is a read-only tool surface that an
// external client (Cursor, Claude Desktop, Windsurf) drives. The console itself
// never calls it, which is what keeps the dashboard free of AI widgets.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/server/internal/mcp"
	"github.com/statetrack/statetrack/server/internal/postmortem"
	"github.com/statetrack/statetrack/server/internal/storage"
)

// mcpMaxRequestBytes bounds a single JSON-RPC request. MCP arguments are small
// and fixed-shape, so a large body is either a mistake or an attempt to exhaust
// the server's memory.
const mcpMaxRequestBytes = 256 << 10

// mcpMethod serves the JSON-RPC 2.0 MCP endpoint.
//
//	POST /api/v1/mcp
//
// The endpoint accepts a single request object or a batch array. A batch is
// handled because the MCP specification's HTTP transport permits it and some
// clients pipeline `initialize` with an initial `tools/list`; answering only the
// first would leave those clients waiting. Each element is dispatched
// independently, which is what the spec requires — one bad call in a batch must
// not fail the others.
//
// Notifications are dropped from the response. Returning an array that contains
// only notification replies would be an empty but non-empty-shaped response,
// which is exactly the case a client mis-frames.
func (s *Server) mcpEndpoint(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, mcpMaxRequestBytes))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, mcp.ErrorResponse(
			mcp.NewError(mcp.CodeParseError, "the request body could not be read: %v", err)))
		return
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		writeJSON(w, http.StatusBadRequest, mcp.ErrorResponse(
			mcp.NewError(mcp.CodeParseError, "the request body is empty")))
		return
	}

	caller := s.mcpCaller(r)
	server := s.mcpServer()

	// A batch is detected by the first non-whitespace byte rather than by
	// trying to decode twice, so a syntax error inside the array is still
	// reported as a parse error rather than as a malformed single request.
	if firstByte(body) == '[' {
		var batch []json.RawMessage
		if err := json.Unmarshal(body, &batch); err != nil {
			writeJSON(w, http.StatusOK, mcp.ErrorResponse(
				mcp.NewError(mcp.CodeParseError, "the request body is not valid JSON: %v", err)))
			return
		}
		responses := make([]*mcp.Response, 0, len(batch))
		for _, raw := range batch {
			if resp := server.Handle(r.Context(), caller, raw); resp != nil {
				responses = append(responses, resp)
			}
		}
		// An all-notification batch has nothing to say. The spec's HTTP
		// transport answers 202 with an empty body for that case, which is
		// distinct from an empty JSON array.
		if len(responses) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		writeJSON(w, http.StatusOK, responses)
		return
	}

	resp := server.Handle(r.Context(), caller, body)
	if resp == nil {
		// A single notification: accepted, nothing to return.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	// JSON-RPC errors travel in a 200 body, not as an HTTP status: the HTTP
	// layer succeeded in delivering a protocol error, and a client that
	// branched on the HTTP code would mis-handle a tool-call validation
	// failure as a transport outage.
	writeJSON(w, http.StatusOK, resp)
}

// mcpCaller resolves the authenticated principal into the protocol's Caller.
//
// The org comes from the server, never from the request: a client cannot name the
// org it wants to read, which is what makes the per-tool org scoping meaningful.
// An anonymous request resolves to an empty org and is refused by the protocol
// dispatcher, so this cannot be used to reach another tenant.
func (s *Server) mcpCaller(r *http.Request) mcp.Caller {
	p := PrincipalFrom(r.Context())
	if p == nil {
		return mcp.Caller{}
	}
	return mcp.Caller{
		OrgID:  s.OrgID,
		Name:   p.ActorEmail(),
		Scopes: p.Scopes,
	}
}

// mcpServer returns the process-wide protocol server. It is stateless, so one
// instance serves every request.
func (s *Server) mcpServer() *mcp.Server {
	if s.mcp == nil {
		s.mcp = mcp.New(&mcpBackend{s: s})
	}
	return s.mcp
}

// firstByte returns the first non-whitespace byte of a body.
func firstByte(body []byte) byte {
	for _, b := range body {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return b
		}
	}
	return 0
}

/* -------------------------------------------------------------------------- */
/* Backend                                                                    */
/* -------------------------------------------------------------------------- */

// mcpBackend adapts storage and the AI gateway onto the MCP protocol's Backend.
//
// Every method takes the protocol's own value types and returns them, so the
// protocol package never imports storage. That is what keeps the tool surface
// testable without a database: the protocol tests drive a stub, and only this
// adapter needs the real thing.
type mcpBackend struct {
	s *Server
}

// ListChanges maps the validated filter onto a storage query.
//
// The window is turned into an absolute lower bound here rather than passed as a
// duration, so the query's clock and the protocol's clock are the same one.
func (b *mcpBackend) ListChanges(ctx context.Context, caller mcp.Caller, f mcp.ChangeFilter) ([]mcp.Change, error) {
	events, _, err := b.s.Store.ListEvents(ctx, caller.OrgID, storage.EventFilter{
		HostID:      "", // the host filter is by hostname, resolved below
		Actor:       f.Actor,
		Search:      f.Search,
		ImpactLevel: f.ImpactLevel,
		Category:    f.Category,
		Limit:       f.Limit,
		From:        time.Now().Add(-f.Window),
		RootOnly:    f.RootOnly,
	})
	if err != nil {
		return nil, err
	}
	// The host filter is applied by hostname rather than by id because that is
	// what a caller (a human or a model) knows: it read the name off a list. The
	// storage filter takes an id, so the name is resolved once for the whole
	// query rather than per row.
	if f.Host != "" {
		events = filterByHostname(events, f.Host)
	}

	out := make([]mcp.Change, 0, len(events))
	for _, e := range events {
		out = append(out, toMCPChange(e))
	}
	return out, nil
}

// GetDiff maps one event onto the protocol's diff result, including the actor
// lineage and any aggregated children.
func (b *mcpBackend) GetDiff(ctx context.Context, caller mcp.Caller, eventID string) (mcp.Diff, error) {
	if err := mcp.FormatEventID(eventID); err != nil {
		return mcp.Diff{}, fmt.Errorf("change %s: %w", eventID, mcp.ErrNotFound)
	}
	detail, err := b.s.Store.GetEvent(ctx, caller.OrgID, eventID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return mcp.Diff{}, fmt.Errorf("change %s: %w", eventID, mcp.ErrNotFound)
		}
		return mcp.Diff{}, err
	}
	return b.toMCPDiff(detail), nil
}

// HostSummary maps the storage rollup onto the protocol's shape. The counts map
// is built explicitly rather than marshalled from the struct so the protocol's
// field names are stated once, in the protocol package.
func (b *mcpBackend) HostSummary(ctx context.Context, caller mcp.Caller, host string, window time.Duration) (mcp.HostSummary, error) {
	summary, err := b.s.Store.HostSummary(ctx, caller.OrgID, host, time.Now().Add(-window))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return mcp.HostSummary{}, fmt.Errorf("host %s: %w", host, mcp.ErrNotFound)
		}
		return mcp.HostSummary{}, err
	}

	out := mcp.HostSummary{
		Host:              summary.Host,
		OS:                summary.OS,
		Online:            summary.Online,
		LastSeenSeconds:   summary.LastSeenSeconds,
		Window:            canonicalWindow(window),
		DriftTargetsCount: summary.DriftTargetsCount,
		Counts: map[string]int64{
			"total":       summary.Counts.Total,
			"l1_critical": summary.Counts.L1Critical,
			"l2_grouped":  summary.Counts.L2Grouped,
			"l3_drift":    summary.Counts.L3Drift,
			"l4_forensic": summary.Counts.L4Forensic,
		},
	}
	if summary.LatestCritical != nil {
		lc := summary.LatestCritical
		out.LatestCritical = &mcp.Change{
			ID: lc.ID, OccurredAt: lc.OccurredAt.UTC().Format(time.RFC3339),
			Level: 1, LevelLabel: levelLabel(1),
			Summary: lc.Summary, PathOrKey: lc.Target, Actor: lc.Actor,
			Process: lc.Tool, RuleName: lc.RuleName,
		}
	}
	// The deep link uses the hostname, not the key the caller passed, so a
	// summary fetched by id still links to a working console URL.
	out.ConsoleURL = strings.TrimRight(b.s.UIBaseURL, "/") + "/hosts/" + summary.Host
	return out, nil
}

// Analyze runs the AI gateway over one change.
//
// It reuses the exact assembly the HTTP analyze endpoint uses, so a drawer click
// and an MCP tool call cannot produce different analyses for the same event.
func (b *mcpBackend) Analyze(ctx context.Context, caller mcp.Caller, eventID string) (mcp.Analysis, error) {
	if err := mcp.FormatEventID(eventID); err != nil {
		return mcp.Analysis{}, fmt.Errorf("change %s: %w", eventID, mcp.ErrNotFound)
	}
	detail, err := b.s.Store.GetEvent(ctx, caller.OrgID, eventID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return mcp.Analysis{}, fmt.Errorf("change %s: %w", eventID, mcp.ErrNotFound)
		}
		return mcp.Analysis{}, err
	}
	settings, err := b.s.Store.GetAISettings(ctx, caller.OrgID)
	if err != nil {
		return mcp.Analysis{}, err
	}

	analysis := b.s.aiGateway().Analyze(ctx, settings, b.s.eventForAnalysisFrom(ctx, caller.OrgID, detail))
	return mcp.Analysis{
		EventID:             detail.ID,
		Provider:            analysis.Provider,
		ProviderLabel:       analysis.ProviderLabel,
		Model:               analysis.Model,
		RiskSummary:         analysis.RiskSummary,
		BlastRadius:         analysis.BlastRadius,
		AffectedServices:    analysis.AffectedServices,
		RollbackCommand:     analysis.RollbackCommand,
		VerificationCommand: analysis.VerificationCommand,
		RollbackNotes:       analysis.RollbackNotes,
		Fallback:            analysis.Fallback,
		FallbackReason:      analysis.FallbackReason,
		Scrubbed:            analysis.Scrubbed,
		LatencyMS:           analysis.LatencyMS,
	}, nil
}

// PostMortem renders the incident bundle for one change.
//
// The assembly is shared with the HTTP endpoint (buildPostMortem), so the
// document a client pulls through MCP is byte-identical to the one the console
// downloads. That is the property that makes the export trustworthy: two
// implementations would drift, and then a transcript and a compliance record
// would disagree about the same incident.
func (b *mcpBackend) PostMortem(ctx context.Context, caller mcp.Caller, eventID string, window time.Duration, format string) (mcp.PostMortem, error) {
	if err := mcp.FormatEventID(eventID); err != nil {
		return mcp.PostMortem{}, fmt.Errorf("change %s: %w", eventID, mcp.ErrNotFound)
	}
	bundle, err := b.s.Store.GatherPostMortem(ctx, caller.OrgID, eventID, window)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return mcp.PostMortem{}, fmt.Errorf("change %s: %w", eventID, mcp.ErrNotFound)
		}
		return mcp.PostMortem{}, err
	}

	report := b.s.buildPostMortem(ctx, caller.Name, bundle, "±"+canonicalWindow(window))
	out := mcp.PostMortem{
		EventID:  eventID,
		Filename: postmortem.Filename(bundle.Hostname, eventID, "md"),
		Format:   format,
		Markdown: postmortem.Render(report),
	}
	if format == "json" {
		raw, err := postmortem.RenderJSON(report)
		if err != nil {
			return mcp.PostMortem{}, err
		}
		// The structured field is returned as decoded JSON rather than a string
		// so a client can index into it, which is the point of asking for it.
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return mcp.PostMortem{}, err
		}
		out.Structured = decoded
		out.Filename = postmortem.Filename(bundle.Hostname, eventID, "json")
	}
	return out, nil
}

/* -------------------------------------------------------------------------- */
/* Mapping helpers                                                            */
/* -------------------------------------------------------------------------- */

// toMCPChange flattens a storage event onto the protocol's stable shape.
func toMCPChange(e storage.Event) mcp.Change {
	return mcp.Change{
		ID:         e.ID,
		Host:       e.Hostname,
		OccurredAt: e.OccurredAt.UTC().Format(time.RFC3339),
		Level:      e.ImpactLevel,
		LevelLabel: levelLabel(e.ImpactLevel),
		Category:   categoryKey(e.Category),
		Action:     actionVerb(e.Action),
		Summary:    e.Summary,
		TargetType: e.TargetType,
		PathOrKey:  e.PathOrKey,
		Actor:      e.ActorUsername,
		Process:    e.ProcessName,
		RemoteIP:   e.RemoteIP,
		RuleName:   e.Metadata["rule_name"],
		HasDiff:    e.HasDiff,
		ChildCount: e.ChildCount,
	}
}

// toMCPDiff flattens one event's detail, including its lineage and children.
func (b *mcpBackend) toMCPDiff(d storage.EventDetail) mcp.Diff {
	out := mcp.Diff{
		ID:           d.ID,
		Host:         d.Hostname,
		OccurredAt:   d.OccurredAt.UTC().Format(time.RFC3339),
		Level:        d.ImpactLevel,
		LevelLabel:   levelLabel(d.ImpactLevel),
		Summary:      d.Summary,
		TargetType:   d.TargetType,
		PathOrKey:    d.PathOrKey,
		Diff:         d.Diff,
		DiffRedacted: strings.Contains(d.Diff, "[REDACTED:"),
		HashBefore:   d.HashBefore,
		HashAfter:    d.HashAfter,
		Actor:        d.ActorUsername,
		UID:          d.ActorSID,
		RemoteIP:     d.RemoteIP,
		Process:      d.ProcessName,
		Cmdline:      d.Cmdline,
		Lineage:      d.ProcessLineage,
	}
	for _, child := range d.Children {
		out.Children = append(out.Children, toMCPChange(child))
	}
	return out
}

// filterByHostname narrows a page of events to one hostname.
//
// It filters in Go rather than in SQL because the storage filter takes a host id
// and the names are already on the page: resolving the name to an id would be a
// second query, and the page size is bounded at 200, so the linear scan is
// cheaper than the round trip.
func filterByHostname(events []storage.Event, hostname string) []storage.Event {
	want := strings.ToLower(strings.TrimSpace(hostname))
	out := make([]storage.Event, 0, len(events))
	for _, e := range events {
		if strings.ToLower(e.Hostname) == want {
			out = append(out, e)
		}
	}
	return out
}

// categoryKey renders a category as the protocol's vocabulary word, matching the
// enum the tool schemas advertise.
func categoryKey(c int32) string {
	switch pb.Category(c) {
	case pb.Category_CATEGORY_CONFIG:
		return "config"
	case pb.Category_CATEGORY_REGISTRY:
		return "registry"
	case pb.Category_CATEGORY_PACKAGE:
		return "package"
	case pb.Category_CATEGORY_SERVICE:
		return "service"
	case pb.Category_CATEGORY_USER:
		return "user"
	case pb.Category_CATEGORY_NETWORK:
		return "network"
	case pb.Category_CATEGORY_PROCESS:
		return "process"
	case pb.Category_CATEGORY_AGENT_HEALTH:
		return "agent_health"
	default:
		return ""
	}
}
