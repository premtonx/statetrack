// Incident post-mortem bundle generation ("War Room Export").
//
// The endpoint's job is to be the only thing an SRE has to click during or after
// an incident. Everything the document needs is assembled here from storage and
// rendered by internal/postmortem; this file's real work is the *joins*:
// correlating the change ticket, deriving the blast radius from the target, and
// filling in the monitoring deep links the app layer owns.
//
// Two response formats from one endpoint rather than two routes, because the
// content negotiation is trivial (a `format` query parameter) while the assembly
// is not — duplicating the assembly to satisfy two URL shapes would guarantee the
// Markdown and the JSON eventually disagree.
package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/server/internal/ai"
	"github.com/statetrack/statetrack/server/internal/itsm"
	"github.com/statetrack/statetrack/server/internal/postmortem"
	"github.com/statetrack/statetrack/server/internal/storage"
)

// postMortem serves the incident bundle.
//
//	GET /api/v1/events/{id}/post-mortem?window=30m&format=md|json
//
// `format=md` (the default) returns `text/markdown` with a Content-Disposition
// attachment header, so a browser click downloads a file and a fetch() from the
// console gets the text to preview. `format=json` returns the structured bundle,
// which embeds the same Markdown.
func (s *Server) postMortem(w http.ResponseWriter, r *http.Request) {
	eventID := strings.TrimSpace(r.PathValue("id"))
	if eventID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "event id is required"})
		return
	}

	window, label, err := parsePostMortemWindow(r.URL.Query().Get("window"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	bundle, err := s.Store.GatherPostMortem(r.Context(), s.OrgID, eventID, window)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "event not found", "id": eventID})
			return
		}
		writeErr(w, err)
		return
	}

	report := s.buildPostMortem(r.Context(), requesterName(r), bundle, label)

	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))) {
	case "json":
		raw, err := postmortem.RenderJSON(report)
		if err != nil {
			writeErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// The console fetches JSON to preview and to offer a download, so the
		// attachment disposition is only set when explicitly requested.
		if r.URL.Query().Get("download") == "1" {
			setAttachment(w, postmortem.Filename(bundle.Hostname, eventID, "json"))
		}
		_, _ = w.Write(raw)
	default:
		md := postmortem.Render(report)
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		// A markdown response is almost always wanted as a file, so the default
		// flips the other way: JSON previews inline, Markdown downloads.
		//
		// The body is written before the header block below only in the sense
		// that the console's preview fetch passes download=0; both paths emit
		// the same bytes, so the preview and the download cannot differ.
		if r.URL.Query().Get("download") != "0" {
			setAttachment(w, postmortem.Filename(bundle.Hostname, eventID, "md"))
		}
		_, _ = w.Write([]byte(md))
	}
}

// setAttachment writes the Content-Disposition header. The filename is already
// restricted to a safe alphabet by postmortem.Filename, so it cannot inject a
// header value or a path separator.
func setAttachment(w http.ResponseWriter, filename string) {
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
}

// buildPostMortem converts raw storage rows into the renderable bundle, filling
// in every derived field the report depends on.
//
// It takes a context and the requester's name rather than an *http.Request so the
// MCP transport can produce a byte-identical document to the HTTP endpoint's:
// two assembly paths would drift, and then a transcript and a compliance record
// would disagree about the same incident.
//
// Derivation lives here rather than in the renderer because it needs the
// server's configuration (UI base URL, ITSM enforcement) and the org's ticket
// set — the renderer is a pure function on purpose, so a report can be produced
// and asserted on in a test without a database or a config.
func (s *Server) buildPostMortem(ctx context.Context, requestedBy string, b storage.PostMortemBundle, windowLabel string) postmortem.Bundle {
	ev := b.Event
	host := firstNonEmptyStr(b.Hostname, ev.Hostname)
	inCluster := isKubernetesTarget(ev.TargetType)

	report := postmortem.Bundle{
		GeneratedAt: time.Now().UTC(),
		Window: postmortem.Window{
			From:  b.WindowStart.UTC(),
			To:    b.WindowEnd.UTC(),
			Label: windowLabel,
		},
		Event: postmortem.Event{
			ID:             ev.ID,
			Host:           host,
			Time:           ev.OccurredAt.UTC(),
			Level:          ev.ImpactLevel,
			LevelLabel:     levelLabel(ev.ImpactLevel),
			Category:       categoryName(ev.Category),
			Action:         actionVerb(ev.Action),
			Summary:        ev.Summary,
			TargetType:     ev.TargetType,
			PathOrKey:      ev.PathOrKey,
			RuleName:       ev.Metadata["rule_name"],
			Classification: ev.Metadata["classification"],
			Metadata:       ev.Metadata,
		},
		Diff:         ev.Diff,
		DiffRedacted: strings.Contains(ev.Diff, "[REDACTED:"),
		Attribution: postmortem.Attribution{
			Actor:     ev.ActorUsername,
			UID:       ev.ActorSID,
			LoginUser: ev.LoginUID,
			RemoteIP:  ev.RemoteIP,
			Process:   ev.ProcessName,
			PID:       ev.PID,
			PPID:      ev.PPID,
			Cmdline:   ev.Cmdline,
			Lineage:   ev.ProcessLineage,
			Source:    attributionSource(ev),
		},
		Monitoring: s.monitoringLinks(ctx, b),
		BlastRadius: postmortem.DeriveBlastRadius(postmortem.RemediationInput{
			TargetType:  ev.TargetType,
			PathOrKey:   ev.PathOrKey,
			Action:      actionVerb(ev.Action),
			LevelLabel:  levelLabel(ev.ImpactLevel),
			OSFamily:    b.OSFamily,
			DiffPresent: ev.Diff != "",
			Cluster:     clusterScopeOf(ev.PathOrKey, inCluster),
		}),
	}
	if tags := ev.Metadata["rule_tags"]; tags != "" {
		report.Event.RuleTags = strings.Split(tags, ",")
	}
	// A cluster resource's "location" is its namespace, which is the useful
	// context in a report; record it explicitly rather than leaving a reader to
	// decode the path.
	if inCluster {
		report.Event.KubernetesContext = kubernetesContext(ev.PathOrKey)
	}
	if base := strings.TrimRight(s.UIBaseURL, "/"); base != "" {
		report.IncidentConsoleURL = base + "/events/" + ev.ID + "?tab=diff"
	}
	// The requester is passed in rather than read from the context because both
	// transports already know it (a console session's actor, or the MCP client
	// that asked for the bundle) and the report's footer should credit the actual
	// requester in either case.
	report.GeneratedBy = requestedBy

	for _, e := range b.Timeline {
		host := firstNonEmptyStr(b.Hostname, e.Hostname)
		report.Timeline = append(report.Timeline, postmortem.TimelineEntry{
			ID:         e.ID,
			Time:       e.OccurredAt.UTC(),
			Level:      e.ImpactLevel,
			Summary:    e.Summary,
			PathOrKey:  e.PathOrKey,
			Actor:      e.ActorUsername,
			Host:       host,
			IsIncident: e.ID == ev.ID,
		})
	}
	for _, e := range b.ControlPlane {
		report.ControlPlane = append(report.ControlPlane, postmortem.AuditEntry{
			Time:     e.OccurredAt.UTC(),
			Actor:    e.ActorEmail,
			Role:     e.ActorRole,
			Action:   e.Action,
			Target:   e.Target,
			SourceIP: e.SourceIP,
		})
	}

	s.attachCompliance(ctx, &report, b, host)
	s.attachAnalysis(ctx, &report, b)
	return report
}

// attachAnalysis runs the AI gateway (or its deterministic offline fallback)
// over the incident and attaches the result to the report.
//
// Failure is tolerated: the derived blast radius in section 6 is always present,
// so a report whose AI section is missing is still a complete document. Blocking
// a post-mortem export on a model being reachable would be the worst possible
// trade during an outage, which is precisely when the report is produced.
//
// A model is never *required* here even when one is configured: the gateway's
// deterministic fallback means an air-gapped site gets the same section populated
// from the heuristics, credited to the offline engine.
func (s *Server) attachAnalysis(ctx context.Context, report *postmortem.Bundle, b storage.PostMortemBundle) {
	settings, err := s.Store.GetAISettings(ctx, s.OrgID)
	if err != nil {
		s.logger().Debug("post-mortem ai settings", "err", err)
		return
	}

	// A disabled gateway with no configured provider would produce a section
	// that only repeats section 6's derived plan, so it is skipped. The check is
	// on the *effective* provider, not the enabled flag alone: an operator who
	// selected deterministic explicitly still gets the section, because that is
	// the analysis they asked for.
	if !settings.Enabled && settings.Provider == ai.ProviderDeterministic {
		return
	}

	analysisCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), aiAnalysisTimeout)
	defer cancel()

	analysis := s.aiGateway().Analyze(analysisCtx, settings, s.eventForAnalysisFrom(ctx, s.OrgID, b.Event))
	report.Analysis = &postmortem.AIAnalysis{
		Engine:              analysis.ProviderLabel,
		Model:               analysis.Model,
		Fallback:            analysis.Fallback,
		FallbackReason:      analysis.FallbackReason,
		RiskSummary:         analysis.RiskSummary,
		BlastRadius:         analysis.BlastRadius,
		AffectedServices:    analysis.AffectedServices,
		RollbackCommand:     analysis.RollbackCommand,
		VerificationCommand: analysis.VerificationCommand,
		RollbackNotes:       analysis.RollbackNotes,
		Scrubbed:            analysis.Scrubbed,
	}
}

// attachCompliance correlates the incident against the org's change tickets and
// records the verdict on the report.
//
// Failure is tolerated: a report without a compliance section is still a useful
// incident document, and refusing to produce one because the ITSM mirror is
// empty would be the worst possible trade during an outage.
func (s *Server) attachCompliance(ctx context.Context, report *postmortem.Bundle, b storage.PostMortemBundle, host string) {
	settings, err := s.Store.GetITSMSettings(ctx, s.OrgID)
	if err != nil {
		s.logger().Debug("post-mortem itsm settings", "err", err)
		return
	}
	tickets, err := s.Store.PostMortemTickets(ctx, s.OrgID, host)
	if err != nil {
		s.logger().Debug("post-mortem change tickets", "err", err)
		return
	}

	ev := b.Event
	result := itsm.Correlate(itsm.Event{
		ID:         ev.ID,
		Hostname:   host,
		PathOrKey:  ev.PathOrKey,
		TargetType: ev.TargetType,
		Level:      ev.ImpactLevel,
		OccurredAt: ev.OccurredAt,
		Summary:    ev.Summary,
		Actor:      ev.ActorUsername,
		Cmdline:    ev.Cmdline,
		Metadata:   ev.Metadata,
	}, toITSTickets(tickets), itsm.Options{
		Enforcement:  itsm.Enforcement(settings.Enforcement),
		WindowGrace:  time.Duration(settings.WindowGraceMinutes) * time.Minute,
		MinLevel:     int32(settings.MinLevel),
		ExemptActors: settings.ExemptActors,
		Now:          time.Now(),
	})

	report.Compliance = string(result.Compliance)
	report.ComplianceReason = result.Reason
	if result.Ticket == nil {
		return
	}
	t := result.Ticket
	report.ChangeTicket = &postmortem.ChangeTicket{
		Ref:         t.Ref,
		Kind:        string(t.Kind),
		Status:      string(t.Status),
		StatusLabel: t.Status.Label(),
		Summary:     t.Summary,
		URL:         t.URL,
		RequestedBy: t.RequestedBy,
		Authorized:  t.Status.Authorized(),
	}
}

// toITSTickets maps storage rows onto the correlation package's ticket type.
func toITSTickets(rows []storage.ChangeTicket) []itsm.Ticket {
	out := make([]itsm.Ticket, 0, len(rows))
	for _, t := range rows {
		out = append(out, itsm.Ticket{
			ID:           t.ID,
			Kind:         itsm.Kind(t.Kind),
			Ref:          t.Ref,
			Status:       itsm.NormalizeStatus(t.Status),
			Summary:      t.Summary,
			URL:          t.URL,
			Hosts:        t.Hosts,
			Environments: t.Environments,
			Paths:        t.Paths,
			WindowStart:  t.WindowStart,
			WindowEnd:    t.WindowEnd,
			RequestedBy:  t.RequestedBy,
			UpdatedAt:    t.UpdatedAt,
		})
	}
	return out
}

// monitoringLinks builds the Grafana deep links for the incident window.
//
// The annotation link is a plain Grafana URL with `from`/`to` in milliseconds
// and the host interpolated, rather than the StateTrack API: the point of the
// link in a post-mortem is to put a human in front of the panel, and a link that
// renders JSON would not do that.
//
// A Grafana lookup failure is not fatal: every deployment has the machine-
// readable host summary, so the section degrades to that one link.
func (s *Server) monitoringLinks(ctx context.Context, b storage.PostMortemBundle) postmortem.Monitoring {
	out := postmortem.Monitoring{HostSummaryURL: s.hostSummaryLink(b.Hostname)}

	settings, err := s.Store.GetGrafanaSettings(ctx, s.OrgID)
	if err != nil || strings.TrimSpace(settings.URL) == "" {
		return out
	}
	base := strings.TrimRight(settings.URL, "/")
	from := b.WindowStart.UTC().UnixMilli()
	to := b.WindowEnd.UTC().UnixMilli()
	// The dashboard UID/slug is the one the integration ships (see
	// integrations/grafana), so the link works on a provisioned install.
	out.GrafanaAnnotationURL = fmt.Sprintf(
		"%s/d/statetrack-overview/statetrack-overview?from=%d&to=%d&var-host=%s",
		base, from, to, url.QueryEscape(b.Hostname))
	out.GrafanaHostDashboardURL = fmt.Sprintf(
		"%s/d/statetrack-overview/statetrack-overview?from=%d&to=%d&var-host=%s",
		base, from, to, url.QueryEscape(b.Hostname))
	return out
}

// hostSummaryLink builds the poller-rollup URL for a host, which is the
// machine-readable health snapshot a responder can hand to another team.
func (s *Server) hostSummaryLink(hostname string) string {
	base := strings.TrimRight(s.UIBaseURL, "/")
	if base == "" || hostname == "" {
		return ""
	}
	return base + "/api/v1/hosts/" + url.PathEscape(hostname) + "/summary?window=1h"
}

// parsePostMortemWindow resolves the `window` query parameter into a duration
// and its display label.
func parsePostMortemWindow(raw string) (time.Duration, string, error) {
	if strings.TrimSpace(raw) == "" {
		return storage.PostMortemWindow, "±30m", nil
	}
	d, err := parseWindowDuration(raw)
	if err != nil {
		return 0, "", err
	}
	if d <= 0 {
		return 0, "", fmt.Errorf("window must be positive, got %q", raw)
	}
	// Clamped rather than refused: a 30-day window is a mistaken request, not an
	// attack, and a report is more useful than a 400.
	if d > storage.MaxPostMortemWindow {
		d = storage.MaxPostMortemWindow
	}
	return d, "±" + canonicalWindow(d), nil
}

// attributionSource names how the actor was determined. The agent stamps the
// method in metadata for Kubernetes changes; for host changes the process tree
// is the mechanism.
func attributionSource(ev storage.EventDetail) string {
	switch {
	case ev.Metadata["attribution"] != "":
		return ev.Metadata["attribution"]
	case isKubernetesTarget(ev.TargetType):
		return "kubernetes-managed-fields"
	case ev.ProcessName != "":
		return "process-tree"
	case ev.TargetType == "registry":
		return "registry-key-owner"
	default:
		return ""
	}
}

// isKubernetesTarget reports whether a target type names a cluster resource
// rather than a filesystem path or registry key.
//
// The agent's Kubernetes collector reports `k8s_<resource>` target types
// (k8s_configmap, k8s_secret, k8s_deployment, …), which is what this keys on;
// the path prefix is checked too so a hand-seeded row following the documented
// `/k8s/<cluster>/<ns>/<plural>/<name>` shape is recognised as well.
func isKubernetesTarget(targetType string) bool {
	return strings.HasPrefix(targetType, "k8s_") || targetType == "k8s" || targetType == "kubernetes"
}

// kubernetesContext renders a cluster resource's location for the report header.
func kubernetesContext(pathOrKey string) string {
	// /k8s/<cluster>/<namespace>/<plural>/<name>
	parts := strings.Split(strings.TrimPrefix(pathOrKey, "/"), "/")
	if len(parts) >= 5 && parts[0] == "k8s" {
		cluster, ns, plural, name := parts[1], parts[2], parts[3], parts[4]
		if ns == "_cluster" {
			ns = "cluster-scoped"
		}
		return fmt.Sprintf("%s %q in namespace %s on cluster %s",
			strings.TrimSuffix(plural, "s"), name, ns, cluster)
	}
	return pathOrKey
}

// clusterScopeOf extracts the cluster name from a Kubernetes key, for the
// remediation advice (which needs the cluster to render a kubectl context).
func clusterScopeOf(pathOrKey string, inCluster bool) string {
	if !inCluster {
		return ""
	}
	parts := strings.Split(strings.TrimPrefix(pathOrKey, "/"), "/")
	if len(parts) >= 2 && parts[0] == "k8s" {
		return parts[1]
	}
	return ""
}

// categoryName renders an event category for prose. Kept local rather than
// reusing the pusher's formatter so the report's vocabulary is independent of
// the notification channel's.
func categoryName(c int32) string {
	switch pb.Category(c) {
	case pb.Category_CATEGORY_CONFIG:
		return "Configuration"
	case pb.Category_CATEGORY_REGISTRY:
		return "Registry"
	case pb.Category_CATEGORY_PACKAGE:
		return "Package"
	case pb.Category_CATEGORY_SERVICE:
		return "Service"
	case pb.Category_CATEGORY_USER:
		return "User"
	case pb.Category_CATEGORY_NETWORK:
		return "Network"
	case pb.Category_CATEGORY_PROCESS:
		return "Process"
	case pb.Category_CATEGORY_AGENT_HEALTH:
		return "Agent health"
	default:
		return ""
	}
}

// actionVerb renders an action for prose. Named distinctly from the console
// helper in labels.ts so a change here cannot silently alter the timeline.
func actionVerb(a int32) string {
	switch pb.Action(a) {
	case pb.Action_ACTION_CREATED:
		return "Created"
	case pb.Action_ACTION_MODIFIED:
		return "Modified"
	case pb.Action_ACTION_DELETED:
		return "Deleted"
	case pb.Action_ACTION_RESTARTED:
		return "Restarted"
	case pb.Action_ACTION_STARTED:
		return "Started"
	case pb.Action_ACTION_STOPPED:
		return "Stopped"
	case pb.Action_ACTION_UPGRADED:
		return "Upgraded"
	case pb.Action_ACTION_THROTTLED:
		return "Throttled"
	default:
		return ""
	}
}

func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// complianceFilterValues is the closed set the reports page offers as a filter,
// echoed in the filter response so the console's dropdown cannot drift from the
// server's vocabulary.
var complianceFilterValues = []string{"approved", "unapproved", "expired", "not_required"}

// eventsCompliance annotates a page of events with their change-control verdict
// so the Reports page can filter for unauthorised production edits.
//
//	GET /api/v1/events/compliance?...
//
// It deliberately reuses the same list filters as /api/v1/events and adds the
// verdict per event, rather than growing the events endpoint: the correlation
// needs the org's whole ticket set and the ITSM settings, which is more work per
// request than the plain timeline should ever do.
func (s *Server) eventsCompliance(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	events, _, err := s.Store.ListEvents(r.Context(), s.OrgID, storage.EventFilter{
		HostID:      q.Get("host_id"),
		Actor:       q.Get("actor"),
		Search:      q.Get("search"),
		ImpactLevel: atoi(q.Get("impact_level")),
		From:        parseTime(q.Get("from")),
		To:          parseTime(q.Get("to")),
		Limit:       clamp(atoi(q.Get("limit")), 200),
		RootOnly:    true,
	})
	if err != nil {
		writeErr(w, err)
		return
	}

	annotated, enforced, err := s.annotateCompliance(r, events)
	if err != nil {
		writeErr(w, err)
		return
	}

	// Filtering in Go rather than SQL: the verdict is derived, not stored, and
	// pushing it into the query would mean persisting a compliance decision
	// that can change when a ticket is edited retroactively.
	want := storage.NormalizeComplianceStatus(q.Get("compliance"))
	out := annotateViews(annotated, want)

	writeJSON(w, http.StatusOK, map[string]any{
		"events":   out,
		"count":    len(out),
		"filters":  complianceFilterValues,
		"enforced": enforced,
	})
}

// annotateViews applies the requested verdict filter. Split out from the
// handler so the filtering rule is stated once, next to the annotation it
// filters on, rather than inline in two handlers.
func annotateViews(views []complianceEventView, want string) []complianceEventView {
	if want == "" {
		return views
	}
	out := make([]complianceEventView, 0, len(views))
	for _, v := range views {
		if v.Compliance == want {
			out = append(out, v)
		}
	}
	return out
}

// annotateCompliance attaches a change-control verdict to each event and
// reports whether enforcement is active.
//
// Shared by the timeline's `?annotate=compliance` path and the compliance
// report endpoint: the two must agree verdict-for-verdict, and the only way to
// guarantee that is to run the same code. The per-event decision is pure
// computation over a ticket set read once, so annotating a page costs two reads
// regardless of page size, and the settings read that gates it is reused for
// the response's `enforced` flag rather than repeated by the caller.
func (s *Server) annotateCompliance(r *http.Request, events []storage.Event) ([]complianceEventView, bool, error) {
	settings, err := s.Store.GetITSMSettings(r.Context(), s.OrgID)
	if err != nil {
		return nil, false, err
	}
	tickets, err := s.Store.ListChangeTickets(r.Context(), s.OrgID, "")
	if err != nil {
		return nil, false, err
	}
	enforced := settings.Enforcement != string(itsm.EnforcementOff)
	correlationTickets := toITSTickets(tickets)
	opts := itsm.Options{
		Enforcement:  itsm.Enforcement(settings.Enforcement),
		WindowGrace:  time.Duration(settings.WindowGraceMinutes) * time.Minute,
		MinLevel:     int32(settings.MinLevel),
		ExemptActors: settings.ExemptActors,
		Now:          time.Now(),
	}

	out := make([]complianceEventView, 0, len(events))
	for _, e := range events {
		verdict := itsm.Correlate(itsm.Event{
			ID:         e.ID,
			Hostname:   e.Hostname,
			PathOrKey:  e.PathOrKey,
			TargetType: e.TargetType,
			Level:      e.ImpactLevel,
			OccurredAt: e.OccurredAt,
			Summary:    e.Summary,
			Actor:      e.ActorUsername,
			Cmdline:    e.Cmdline,
			Metadata:   e.Metadata,
		}, correlationTickets, opts)
		view := complianceEventView{
			Event:            e,
			Compliance:       string(verdict.Compliance),
			ComplianceReason: verdict.Reason,
		}
		if verdict.Ticket != nil {
			view.TicketRef = verdict.Ticket.Ref
			view.TicketStatus = verdict.Ticket.Status.Label()
		}
		out = append(out, view)
	}
	return out, enforced, nil
}

// complianceEventView is one event with its change-control verdict attached.
type complianceEventView struct {
	storage.Event
	Compliance       string `json:"compliance"`
	ComplianceReason string `json:"compliance_reason,omitempty"`
	TicketRef        string `json:"ticket_ref,omitempty"`
	TicketStatus     string `json:"ticket_status,omitempty"`
}

// eventCompliance returns the change-control verdict for a single event.
//
//	GET /api/v1/events/{id}/compliance
//
// The Inspector drawer needs the verdict for the one event an operator is
// looking at, and the list endpoint cannot answer that: it pages over the
// timeline, so the event in the drawer may not be on the page it returns. The
// alternative — having the drawer pull the whole compliance feed and search it —
// would make opening an event cost a hundred events' worth of correlation.
//
// A missing event surfaces as 404 rather than an empty verdict, because
// "no ticket covers this change" and "this event does not exist" already look
// alike in the UI (both render no badge), and only one of them is a finding.
func (s *Server) eventCompliance(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "event id is required"})
		return
	}
	detail, err := s.Store.GetEvent(r.Context(), s.OrgID, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "event not found", "id": id})
			return
		}
		writeErr(w, err)
		return
	}

	settings, err := s.Store.GetITSMSettings(r.Context(), s.OrgID)
	if err != nil {
		writeErr(w, err)
		return
	}
	tickets, err := s.Store.PostMortemTickets(r.Context(), s.OrgID, detail.Hostname)
	if err != nil {
		writeErr(w, err)
		return
	}

	verdict := itsm.Correlate(itsm.Event{
		ID:         detail.ID,
		Hostname:   detail.Hostname,
		PathOrKey:  detail.PathOrKey,
		TargetType: detail.TargetType,
		Level:      detail.ImpactLevel,
		OccurredAt: detail.OccurredAt,
		Summary:    detail.Summary,
		Actor:      detail.ActorUsername,
		Cmdline:    detail.Cmdline,
		Metadata:   detail.Metadata,
	}, toITSTickets(tickets), itsm.Options{
		Enforcement:  itsm.Enforcement(settings.Enforcement),
		WindowGrace:  time.Duration(settings.WindowGraceMinutes) * time.Minute,
		MinLevel:     int32(settings.MinLevel),
		ExemptActors: settings.ExemptActors,
		Now:          time.Now(),
	})

	view := complianceEventView{
		Event:            detail.Event,
		Compliance:       string(verdict.Compliance),
		ComplianceReason: verdict.Reason,
	}
	if verdict.Ticket != nil {
		view.TicketRef = verdict.Ticket.Ref
		view.TicketStatus = verdict.Ticket.Status.Label()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"event_id": detail.ID,
		"verdict":  view,
		"enforced": verdict.Enforced,
		"filters":  complianceFilterValues,
	})
}
