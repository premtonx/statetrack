// Package postmortem renders the 1-click incident post-mortem bundle.
//
// The problem: during an outage an SRE already has all the facts, scattered
// across six tabs of the console — the diff, the actor lineage, the surrounding
// timeline, the Grafana panel, the rollback command, the audit trail. Assembling
// them into a document for management is an hour of copy-paste that happens
// after the incident, which means it happens badly or not at all.
//
// This package is the assembly, as a pure function over a Bundle. It deliberately
// does not touch the database or the network: the inputs are gathered by the API
// layer (which owns the request context and the org scope) and the output is a
// string. That makes the report format exhaustively testable, which matters
// because the artefact it produces is a compliance record — a report that
// silently omits the diff, or leaks a secret into a document that gets pasted
// into Confluence, is the failure mode worth engineering against.
package postmortem

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Window is the incident window the report covers.
//
// A post-mortem's timeline is only useful if its bounds are explicit: "all other
// mutations on that host" is unbounded without them, and a reader cannot tell a
// quiet incident from a report that was truncated.
type Window struct {
	// From and To bound the corroborating timeline. Both inclusive.
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// Label is the human-readable width ("±30m"), echoed in the report header
	// so a reader does not have to subtract timestamps to learn the span.
	Label string `json:"label"`
}

// Bundle is every input the report needs. The API layer fills it; nothing here
// is fetched by the generator itself.
type Bundle struct {
	// GeneratedAt stamps the report. Passed in rather than read from the clock
	// so a test can produce a byte-stable document.
	GeneratedAt time.Time `json:"generated_at"`
	// GeneratedBy is the operator who exported the bundle, for the footer.
	GeneratedBy string `json:"generated_by,omitempty"`
	// IncidentConsoleURL is the deep link back to the event in the console.
	IncidentConsoleURL string `json:"incident_console_url,omitempty"`

	Event    Event           `json:"event"`
	Window   Window          `json:"window"`
	Timeline []TimelineEntry `json:"timeline"`

	// Diff is the already-scrubbed unified diff, or empty when the change
	// stored hashes only. It must arrive pre-scrubbed: the scrubber runs at the
	// agent edge, and re-scrubbing here would imply the raw text was available
	// to leak.
	Diff string `json:"diff,omitempty"`
	// DiffRedacted reports that the diff above may contain redaction stubs, so
	// the report can say so rather than letting a reader assume `[REDACTED:...]`
	// was the literal file content.
	DiffRedacted bool `json:"diff_redacted"`

	// Attribution is the root-cause lineage.
	Attribution Attribution `json:"attribution"`
	// BlastRadius is the analyzer's risk assessment and remediation commands.
	BlastRadius BlastRadius `json:"blast_radius"`
	// Analysis is the engine-assisted assessment, when one was produced. Nil
	// means no analysis was attached (the caller opted out, or no gateway is
	// configured), and the report then renders only the derived plan above.
	//
	// It is a separate field from BlastRadius rather than an overwrite because
	// the two answer the same question by different means: replacing the derived
	// plan would mean a report whose rollback command changed depending on
	// whether a model happened to be reachable, which is not a compliance record
	// anyone should trust.
	Analysis *AIAnalysis `json:"analysis,omitempty"`

	// Monitoring holds the Grafana/monitoring deep links.
	Monitoring Monitoring `json:"monitoring"`

	// ControlPlane is the StateTrack administrative actions during the window.
	ControlPlane []AuditEntry `json:"control_plane"`

	// ChangeTicket is the correlated ITIL change request, when one matched.
	ChangeTicket *ChangeTicket `json:"change_ticket,omitempty"`
	// Compliance is the change-control verdict for this incident.
	Compliance string `json:"compliance,omitempty"`
	// ComplianceReason explains the verdict in one sentence, so the report says
	// *why* a change was flagged rather than only that it was.
	ComplianceReason string `json:"compliance_reason,omitempty"`
}

// Event is the incident event itself, flattened to what a report needs.
type Event struct {
	ID    string    `json:"id"`
	Host  string    `json:"host"`
	Time  time.Time `json:"time"`
	Level int32     `json:"level"`
	// LevelLabel is the rendered severity ("Level 1 · Critical").
	LevelLabel string `json:"level_label"`
	Category   string `json:"category,omitempty"`
	Action     string `json:"action,omitempty"`
	Summary    string `json:"summary"`
	TargetType string `json:"target_type"`
	PathOrKey  string `json:"path_or_key"`
	// RuleName is the matched policy rule, when one decided the verdict.
	RuleName string   `json:"rule_name,omitempty"`
	RuleTags []string `json:"rule_tags,omitempty"`
	// Classification is the analyzer's verdict string.
	Classification string `json:"classification,omitempty"`
	// Metadata is the agent's raw classification map, rendered in the appendix.
	// Sorted on output so the report is byte-stable.
	Metadata map[string]string `json:"metadata,omitempty"`
	// KubernetesContext is set for cluster resources, where "host" is a cluster
	// and the path is a namespaced resource key.
	KubernetesContext string `json:"kubernetes_context,omitempty"`
}

// TimelineEntry is one corroborating mutation inside the incident window.
type TimelineEntry struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Level     int32     `json:"level"`
	Summary   string    `json:"summary"`
	PathOrKey string    `json:"path_or_key"`
	Actor     string    `json:"actor,omitempty"`
	// Host is recorded per entry so a future correlation across a cluster's
	// nodes reads correctly; for a single-host incident it repeats the header.
	Host string `json:"host,omitempty"`
	// IsIncident marks the event the report is about, so it is visible in
	// context rather than only in the header.
	IsIncident bool `json:"is_incident"`
}

// Attribution is the root-cause lineage.
type Attribution struct {
	Actor     string `json:"actor,omitempty"`
	UID       string `json:"uid,omitempty"`
	LoginUser string `json:"login_user,omitempty"`
	RemoteIP  string `json:"remote_ip,omitempty"`
	Process   string `json:"process,omitempty"`
	PID       int32  `json:"pid,omitempty"`
	PPID      int32  `json:"ppid,omitempty"`
	Cmdline   string `json:"cmdline,omitempty"`
	// Lineage is the process tree from the root ancestor to the mutating
	// process, which is how an SSH session is told from a cron job.
	Lineage []string `json:"lineage,omitempty"`
	// Source is the attribution method: "process", "k8s-managed-fields",
	// "registry", or empty when the change was not attributable.
	Source string `json:"source,omitempty"`
}

// IsEmpty reports whether nothing was attributable, so the report can say so
// explicitly instead of printing an empty table.
func (a Attribution) IsEmpty() bool {
	return a.Actor == "" && a.Process == "" && a.RemoteIP == "" && len(a.Lineage) == 0
}

// BlastRadius is the analyzer's risk summary and the operator's next actions.
type BlastRadius struct {
	// RiskSummary is the one-paragraph "what could this break" statement.
	RiskSummary string `json:"risk_summary,omitempty"`
	// AffectedServices are the services/hosts the change can affect.
	AffectedServices []string `json:"affected_services,omitempty"`
	// RollbackCommand is the safe way to undo the change.
	RollbackCommand string `json:"rollback_command,omitempty"`
	// VerifyCommand checks whether the change is healthy.
	VerifyCommand string `json:"verify_command,omitempty"`
	// RollbackNotes explains any caveat (e.g. "requires a service reload").
	RollbackNotes string `json:"rollback_notes,omitempty"`
}

// AIAnalysis is the engine-assisted assessment attached to a report.
//
// It mirrors internal/ai.Analysis rather than embedding it because the
// dependency runs the other way: the AI gateway's deterministic engine is built
// on this package's remediation derivation, so importing it back would be a
// cycle. The API layer owns the one-line conversion, and keeping the report's
// shape here means the renderer stays a pure function.
type AIAnalysis struct {
	// Engine is the human-readable engine name the report credits, e.g.
	// "Azure OpenAI" or "Built-in Offline Heuristics".
	Engine string `json:"engine"`
	// Model is the model id that answered, when a model did.
	Model string `json:"model,omitempty"`
	// Fallback reports that the offline heuristics answered because the
	// configured provider was unreachable. The report states this plainly: a
	// reader must never mistake a heuristic for a model's judgement.
	Fallback       bool   `json:"fallback"`
	FallbackReason string `json:"fallback_reason,omitempty"`
	// RiskSummary is the engine's two-sentence impact statement.
	RiskSummary string `json:"risk_summary"`
	// BlastRadius is Low, Medium or High.
	BlastRadius string `json:"blast_radius"`
	// AffectedServices are the workloads the engine expects to be affected.
	AffectedServices    []string `json:"affected_services,omitempty"`
	RollbackCommand     string   `json:"rollback_command,omitempty"`
	VerificationCommand string   `json:"verification_command,omitempty"`
	RollbackNotes       string   `json:"rollback_notes,omitempty"`
	// Scrubbed records that the engine reasoned over content containing
	// redaction stubs, which is the zero-secret guarantee made visible.
	Scrubbed bool `json:"scrubbed"`
}

// Monitoring holds the observability deep links.
type Monitoring struct {
	// GrafanaAnnotationURL opens Grafana at the incident's annotation window.
	GrafanaAnnotationURL string `json:"grafana_annotation_url,omitempty"`
	// GrafanaHostDashboardURL opens the host's health dashboard.
	GrafanaHostDashboardURL string `json:"grafana_dashboard_url,omitempty"`
	// HostSummaryURL is the unified poller rollup for the host, which is the
	// machine-readable health snapshot.
	HostSummaryURL string `json:"host_summary_url,omitempty"`
}

// AuditEntry is one control-plane action taken during the incident window.
type AuditEntry struct {
	Time     time.Time `json:"time"`
	Actor    string    `json:"actor"`
	Role     string    `json:"role,omitempty"`
	Action   string    `json:"action"`
	Target   string    `json:"target,omitempty"`
	SourceIP string    `json:"source_ip,omitempty"`
}

// ChangeTicket is the correlated ITIL change request.
type ChangeTicket struct {
	Ref         string `json:"ref"`
	Kind        string `json:"kind,omitempty"`
	Status      string `json:"status"`
	StatusLabel string `json:"status_label,omitempty"`
	Summary     string `json:"summary,omitempty"`
	URL         string `json:"url,omitempty"`
	RequestedBy string `json:"requested_by,omitempty"`
	Authorized  bool   `json:"authorized"`
}

// redactionPlaceholder is the shape the edge scrubber leaves behind. Detecting
// it lets the report declare that the diff was scrubbed, instead of a reader
// wondering why a password field reads "[REDACTED:sha256:…]".
const redactionPlaceholder = "[REDACTED:"

// Render produces the Markdown bundle.
//
// Markdown is the delivery format because the destination is always a prose
// document: a Jira ticket, a Confluence page, a GitHub issue, a Google Doc. A
// structured format would need a converter at every one of those endpoints; a
// `.md` file pastes in with its structure intact.
func Render(b Bundle) string {
	var sb strings.Builder

	writeHeader(&sb, b)
	writeExecutiveSummary(&sb, b)
	writeChangeControl(&sb, b)
	writeAttribution(&sb, b)
	writeDiff(&sb, b)
	writeTimeline(&sb, b)
	writeBlastRadius(&sb, b)
	writeAnalysis(&sb, b)
	writeMonitoring(&sb, b)
	writeControlPlane(&sb, b)
	writeAppendix(&sb, b)

	return sb.String()
}

func writeHeader(sb *strings.Builder, b Bundle) {
	fmt.Fprintf(sb, "# Incident Post-Mortem: %s\n\n", firstNonEmpty(b.Event.Summary, b.Event.PathOrKey, "Unnamed change"))
	fmt.Fprintf(sb, "> Generated by StateTrack on %s", b.GeneratedAt.UTC().Format(time.RFC3339))
	if b.GeneratedBy != "" {
		fmt.Fprintf(sb, " by %s", b.GeneratedBy)
	}
	sb.WriteString("  \n")
	fmt.Fprintf(sb, "> Incident event `%s` · window %s\n\n", b.Event.ID, windowPhrase(b))
}

// writeExecutiveSummary answers the four questions a manager asks first: what
// broke, where, how bad, and did a rule catch it.
func writeExecutiveSummary(sb *strings.Builder, b Bundle) {
	sb.WriteString("## 1. Executive Summary\n\n")
	sb.WriteString("| Field | Value |\n| --- | --- |\n")
	row(sb, "Timestamp", b.Event.Time.UTC().Format(time.RFC3339))
	row(sb, "Affected host / cluster", b.Event.Host)
	if b.Event.KubernetesContext != "" {
		row(sb, "Kubernetes resource", b.Event.KubernetesContext)
	}
	row(sb, "Severity", b.Event.LevelLabel)
	row(sb, "Target", fmt.Sprintf("`%s` (%s)", b.Event.PathOrKey, b.Event.TargetType))
	row(sb, "Category", b.Event.Category)
	row(sb, "Action", b.Event.Action)
	row(sb, "Matched policy rule", b.Event.RuleName)
	row(sb, "Change", b.Event.Summary)
	sb.WriteString("\n")
}

// writeChangeControl states whether the change was authorised. It is placed
// before the technical detail because "was this allowed?" is the question an
// auditor opens the document to answer.
func writeChangeControl(sb *strings.Builder, b Bundle) {
	sb.WriteString("## 2. Change Control\n\n")
	if b.ChangeTicket == nil && b.Compliance == "" {
		sb.WriteString("No ITIL change ticket correlates with this change, and change-ticket enforcement is not active.\n\n")
		return
	}
	if b.Compliance != "" {
		verdict := "not evaluated"
		switch b.Compliance {
		case "approved":
			verdict = "**Authorised** — an approved change ticket covers this change."
		case "unapproved":
			verdict = "**Unauthorised** — no approved change ticket covers this change."
		case "expired":
			verdict = "**Change window expired** — a ticket covers this target but its window had closed."
		case "not_required":
			verdict = "Not required — this change is below the ticket threshold, or enforcement is off."
		}
		fmt.Fprintf(sb, "Compliance verdict: %s\n\n", verdict)
	}
	if b.ChangeTicket != nil {
		t := b.ChangeTicket
		status := t.StatusLabel
		if status == "" {
			status = t.Status
		}
		sb.WriteString("| Field | Value |\n| --- | --- |\n")
		row(sb, "Ticket", t.Ref)
		row(sb, "System", t.Kind)
		row(sb, "Status", status)
		row(sb, "Requested by", t.RequestedBy)
		row(sb, "Summary", t.Summary)
		if t.URL != "" {
			row(sb, "Link", t.URL)
		}
		sb.WriteString("\n")
	}
}

func writeAttribution(sb *strings.Builder, b Bundle) {
	sb.WriteString("## 3. Root-Cause Attribution & Lineage\n\n")
	a := b.Attribution
	if a.IsEmpty() {
		sb.WriteString("No actor could be attributed to this change. Treat the origin as unknown until")
		sb.WriteString(" it is established — an unattributed production change is itself a finding.\n\n")
		return
	}
	sb.WriteString("| Field | Value |\n| --- | --- |\n")
	row(sb, "Human actor", a.Actor)
	row(sb, "UID / SID", a.UID)
	row(sb, "Login user", a.LoginUser)
	row(sb, "Originating IP", a.RemoteIP)
	row(sb, "Process", a.Process)
	if a.PID != 0 {
		row(sb, "PID / PPID", fmt.Sprintf("%d / %d", a.PID, a.PPID))
	}
	row(sb, "Attribution source", a.Source)
	sb.WriteString("\n")
	if len(a.Lineage) > 0 {
		sb.WriteString("**Process lineage** (root → mutating process):\n\n```text\n")
		sb.WriteString(strings.Join(a.Lineage, "  →  "))
		sb.WriteString("\n```\n\n")
	}
	if a.Cmdline != "" {
		sb.WriteString("**Command line**\n\n```bash\n")
		sb.WriteString(a.Cmdline)
		sb.WriteString("\n```\n\n")
	}
}

// writeDiff renders the scrubbed diff. The fence is `diff` so GitHub, GitLab
// and most wikis syntax-highlight it, which is what makes the +/- lines legible
// in the destination document.
func writeDiff(sb *strings.Builder, b Bundle) {
	sb.WriteString("## 4. Configuration Diff (scrubbed)\n\n")
	if strings.TrimSpace(b.Diff) == "" {
		fmt.Fprintf(sb, "No text diff was recorded for this change (metadata and SHA-256 only).\n\n")
		fmt.Fprintf(sb, "- Before: `%s`\n- After: `%s`\n\n", orDash(b.Event.Metadata["hash_before"]), orDash(b.Event.Metadata["hash_after"]))
		return
	}
	if b.DiffRedacted || strings.Contains(b.Diff, redactionPlaceholder) {
		sb.WriteString("> Secret-looking values in this diff were replaced with deterministic")
		sb.WriteString(" `[REDACTED:sha256:…]` stubs **at the agent**, before the change left the host.")
		sb.WriteString(" The stubs are stable, so two edits touching the same secret can still be told apart.\n\n")
	}
	sb.WriteString("```diff\n")
	sb.WriteString(strings.TrimRight(b.Diff, "\n"))
	sb.WriteString("\n```\n\n")
}

// writeTimeline renders the corroborating window. The incident event is marked
// in place, because the most useful reading of a post-mortem timeline is
// "everything that happened around this", and a reader who has to cross-
// reference the header to find the incident loses the ordering.
func writeTimeline(sb *strings.Builder, b Bundle) {
	sb.WriteString("## 5. Correlated Timeline\n\n")
	fmt.Fprintf(sb, "All mutations on %s %s.\n\n", b.Event.Host, windowPhrase(b))
	if len(b.Timeline) == 0 {
		sb.WriteString("No other changes were recorded in this window. The change above was isolated.\n\n")
		return
	}
	sb.WriteString("| Time (UTC) | Level | Target | Event | Actor |\n| --- | --- | --- | --- | --- |\n")
	for _, e := range b.Timeline {
		marker := ""
		if e.IsIncident {
			marker = " **← incident**"
		}
		fmt.Fprintf(sb, "| %s | L%d | `%s` | %s%s | %s |\n",
			e.Time.UTC().Format("2006-01-02 15:04:05"), e.Level,
			escapePipes(e.PathOrKey), escapePipes(e.Summary), marker, escapePipes(orDash(e.Actor)))
	}
	sb.WriteString("\n")
}

func writeBlastRadius(sb *strings.Builder, b Bundle) {
	sb.WriteString("## 6. Blast Radius & Rollback Plan\n\n")
	br := b.BlastRadius
	if br.RiskSummary != "" {
		fmt.Fprintf(sb, "**Risk assessment.** %s\n\n", br.RiskSummary)
	}
	if len(br.AffectedServices) > 0 {
		sb.WriteString("**Potential blast radius**\n\n")
		for _, s := range br.AffectedServices {
			fmt.Fprintf(sb, "- %s\n", s)
		}
		sb.WriteString("\n")
	}
	if br.RollbackCommand != "" {
		sb.WriteString("**Safe rollback**\n\n```bash\n")
		sb.WriteString(br.RollbackCommand)
		sb.WriteString("\n```\n\n")
	}
	if br.VerifyCommand != "" {
		sb.WriteString("**Verification after rollback**\n\n```bash\n")
		sb.WriteString(br.VerifyCommand)
		sb.WriteString("\n```\n\n")
	}
	if br.RollbackNotes != "" {
		fmt.Fprintf(sb, "> %s\n\n", br.RollbackNotes)
	}
	if br.RollbackCommand == "" && br.RiskSummary == "" {
		sb.WriteString("No automated remediation was derived for this change. Review the diff above and ")
		sb.WriteString("restore the previous revision from the host's configuration management.\n\n")
	}
}

// writeAnalysis renders the engine-assisted assessment. It sits directly after
// the derived plan because the two are read together: the derived plan is the
// floor (always present, deterministic), and this is the model's added
// judgement, which may name a service or a caveat the heuristics could not.
func writeAnalysis(sb *strings.Builder, b Bundle) {
	if b.Analysis == nil {
		return
	}
	a := b.Analysis
	sb.WriteString("## 7. AI-Assisted Assessment\n\n")

	engine := a.Engine
	if engine == "" {
		engine = "Built-in Offline Heuristics"
	}
	fmt.Fprintf(sb, "**Engine.** %s", engine)
	if a.Model != "" {
		fmt.Fprintf(sb, " (`%s`)", a.Model)
	}
	if a.BlastRadius != "" {
		fmt.Fprintf(sb, " · **Blast radius: %s**", a.BlastRadius)
	}
	sb.WriteString("\n\n")
	// A fallback is stated explicitly and prominently. An operator handing this
	// report to management must know whether a model reasoned about the incident
	// or whether the deterministic rules did, because the two carry different
	// weight in a review.
	if a.Fallback {
		sb.WriteString("> The configured AI provider was unreachable, so the built-in offline heuristics")
		if a.FallbackReason != "" {
			fmt.Fprintf(sb, " produced this assessment (%s).", escapePipes(a.FallbackReason))
		} else {
			sb.WriteString(" produced this assessment.")
		}
		sb.WriteString("\n\n")
	}
	if a.Scrubbed {
		sb.WriteString("> This assessment reasoned only over the scrubbed diff; no secret value left the host.\n\n")
	}
	if a.RiskSummary != "" {
		fmt.Fprintf(sb, "%s\n\n", a.RiskSummary)
	}
	if len(a.AffectedServices) > 0 {
		sb.WriteString("**Expected to affect**\n\n")
		for _, s := range a.AffectedServices {
			fmt.Fprintf(sb, "- %s\n", s)
		}
		sb.WriteString("\n")
	}
	if a.RollbackCommand != "" {
		sb.WriteString("**Safe rollback (engine-suggested)**\n\n```bash\n")
		sb.WriteString(a.RollbackCommand)
		sb.WriteString("\n```\n\n")
	}
	if a.VerificationCommand != "" {
		sb.WriteString("**Verification after rollback**\n\n```bash\n")
		sb.WriteString(a.VerificationCommand)
		sb.WriteString("\n```\n\n")
	}
	if a.RollbackNotes != "" {
		fmt.Fprintf(sb, "> %s\n\n", a.RollbackNotes)
	}
}

func writeMonitoring(sb *strings.Builder, b Bundle) {
	sb.WriteString("## 8. Monitoring Correlation\n\n")
	m := b.Monitoring
	if m.GrafanaAnnotationURL == "" && m.GrafanaHostDashboardURL == "" && m.HostSummaryURL == "" {
		sb.WriteString("No monitoring endpoints are configured for this deployment.\n\n")
		return
	}
	if m.GrafanaAnnotationURL != "" {
		fmt.Fprintf(sb, "- **Grafana annotation window** — %s\n", m.GrafanaAnnotationURL)
	}
	if m.GrafanaHostDashboardURL != "" {
		fmt.Fprintf(sb, "- **Host health dashboard** — %s\n", m.GrafanaHostDashboardURL)
	}
	if m.HostSummaryURL != "" {
		fmt.Fprintf(sb, "- **Host change summary (machine-readable)** — %s\n", m.HostSummaryURL)
	}
	if b.IncidentConsoleURL != "" {
		fmt.Fprintf(sb, "- **StateTrack console** — %s\n", b.IncidentConsoleURL)
	}
	sb.WriteString("\n")
}

func writeControlPlane(sb *strings.Builder, b Bundle) {
	sb.WriteString("## 9. Control-Plane Audit Trail\n\n")
	if len(b.ControlPlane) == 0 {
		sb.WriteString("No StateTrack administrative actions were taken during this window.\n\n")
		return
	}
	sb.WriteString("Administrative actions recorded for the platform during the incident window:\n\n")
	sb.WriteString("| Time (UTC) | Actor | Role | Action | Target |\n| --- | --- | --- | --- | --- |\n")
	for _, e := range b.ControlPlane {
		fmt.Fprintf(sb, "| %s | %s | %s | `%s` | %s |\n",
			e.Time.UTC().Format("2006-01-02 15:04:05"), escapePipes(e.Actor),
			escapePipes(e.Role), e.Action, escapePipes(e.Target))
	}
	sb.WriteString("\n")
}

// writeAppendix dumps the agent's classification metadata. It is last because
// it is the raw evidence a reviewer reaches for after reading the narrative,
// and its keys are open-ended.
func writeAppendix(sb *strings.Builder, b Bundle) {
	sb.WriteString("## 10. Appendix: Agent Metadata\n\n")
	if len(b.Event.Metadata) == 0 {
		sb.WriteString("No additional agent metadata was recorded.\n\n")
		// The footer is written before returning: it is the report's closing
		// marker, and a document that ends on a section body is one an archiver
		// or a diff tool cannot tell from a truncated export.
		writeFooter(sb, b)
		return
	}
	keys := make([]string, 0, len(b.Event.Metadata))
	for k := range b.Event.Metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sb.WriteString("| Key | Value |\n| --- | --- |\n")
	for _, k := range keys {
		fmt.Fprintf(sb, "| `%s` | %s |\n", k, escapePipes(b.Event.Metadata[k]))
	}
	sb.WriteString("\n")
	writeFooter(sb, b)
}

// writeFooter closes every report. It is emitted on all paths so the document
// always ends with its provenance and generation time.
func writeFooter(sb *strings.Builder, b Bundle) {
	fmt.Fprintf(sb, "_Report generated %s._\n", b.GeneratedAt.UTC().Format(time.RFC3339))
}

/* -------------------------------------------------------------------------- */
/* JSON bundle                                                                */
/* -------------------------------------------------------------------------- */

// JSONBundle is the structured form of the same report, for ticketing systems
// and automation that should not have to parse Markdown.
type JSONBundle struct {
	Bundle
	// Format and Version make the payload self-describing, so a consumer can
	// branch on the schema instead of guessing from the field set.
	Format  string `json:"format"`
	Version int    `json:"version"`
	// Markdown is the rendered document, embedded so a single download is
	// enough for either use.
	Markdown string `json:"markdown"`
}

// SchemaVersion is the structured bundle's version.
const SchemaVersion = 1

// RenderJSON produces the structured bundle, with the Markdown document
// embedded.
func RenderJSON(b Bundle) ([]byte, error) {
	out := JSONBundle{Bundle: b, Format: "statetrack.postmortem", Version: SchemaVersion, Markdown: Render(b)}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode post-mortem bundle: %w", err)
	}
	return raw, nil
}

// Filename builds the download filename for an incident, sanitised so it is
// safe on every filesystem the console might run on (the hostname is the only
// user-influenced component, and it is restricted to a safe alphabet rather
// than escaped, because a filename with escapes in it is not helpful).
func Filename(host, eventID, ext string) string {
	safeHost := sanitize(host)
	if safeHost == "" {
		safeHost = "unknown-host"
	}
	short := eventID
	if len(short) > 8 {
		short = short[:8]
	}
	short = sanitize(short)
	if ext == "" {
		ext = "md"
	}
	return fmt.Sprintf("statetrack-postmortem-%s-%s.%s", safeHost, short, ext)
}

// sanitize reduces a value to [A-Za-z0-9._-], replacing every other run of
// characters with a single dash.
func sanitize(s string) string {
	var sb strings.Builder
	lastDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_':
			sb.WriteRune(r)
			lastDash = false
		case r == '-':
			sb.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && sb.Len() > 0 {
				sb.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(sb.String(), "-.")
}

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

// row writes one Markdown table row, substituting an em dash for a missing
// value so the table's shape is stable whether or not a field was recorded.
func row(sb *strings.Builder, label, value string) {
	fmt.Fprintf(sb, "| %s | %s |\n", escapePipes(label), escapePipes(orDash(value)))
}

// escapePipes keeps a value containing `|` from breaking the table it sits in.
// Diff blocks and command lines are fenced, so this only has to cover inline
// values (summaries, paths).
func escapePipes(s string) string {
	return strings.ReplaceAll(s, "|", `\|`)
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// windowPhrase renders the incident window for prose, falling back to a generic
// phrase when the caller did not supply a label.
func windowPhrase(b Bundle) string {
	if b.Window.Label != "" {
		return b.Window.Label
	}
	if !b.Window.From.IsZero() && !b.Window.To.IsZero() {
		return fmt.Sprintf("%s → %s UTC",
			b.Window.From.UTC().Format("15:04"), b.Window.To.UTC().Format("15:04"))
	}
	return "the surrounding window"
}
