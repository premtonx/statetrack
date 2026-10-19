package postmortem

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// baseTime is fixed so every expected string in this file is byte-stable: the
// report is a compliance artefact, and a test that depends on the wall clock
// starts failing in a different timezone rather than when something broke.
var baseTime = time.Date(2026, 3, 14, 9, 2, 11, 0, time.UTC)

// fullBundle is a maximally-populated report: every section has content, which
// is what catches "the section silently disappeared" regressions. The empty
// case is covered separately.
func fullBundle() Bundle {
	return Bundle{
		GeneratedAt:        baseTime.Add(12 * time.Minute),
		GeneratedBy:        "a.chen@example.com",
		IncidentConsoleURL: "https://statetrack.example.com/events/evt-9d2c",
		Event: Event{
			ID:                "evt-9d2c41ab",
			Host:              "prod-web-01",
			Time:              baseTime,
			Level:             1,
			LevelLabel:        "Level 1 · Critical",
			Category:          "security",
			Action:            "Modified",
			Summary:           "Modified /etc/nginx/nginx.conf",
			TargetType:        "file",
			PathOrKey:         "/etc/nginx/nginx.conf",
			RuleName:          "prod-web-config-critical",
			RuleTags:          []string{"production", "web-tier"},
			Classification:    "critical",
			Metadata:          map[string]string{"hash_after": "b1946ac9", "hash_before": "9f2b1c07", "ssh_user": "deploy"},
			KubernetesContext: "",
		},
		Window: Window{
			From:  baseTime.Add(-30 * time.Minute),
			To:    baseTime.Add(30 * time.Minute),
			Label: "±30m",
		},
		Timeline: []TimelineEntry{
			{ID: "evt-1", Time: baseTime.Add(-12 * time.Minute), Level: 3, Summary: "Rotated access log", PathOrKey: "/var/log/nginx/access.log", Actor: "logrotate", Host: "prod-web-01"},
			{ID: "evt-9d2c41ab", Time: baseTime, Level: 1, Summary: "Modified /etc/nginx/nginx.conf", PathOrKey: "/etc/nginx/nginx.conf", Actor: "deploy", Host: "prod-web-01", IsIncident: true},
			{ID: "evt-3", Time: baseTime.Add(4 * time.Minute), Level: 2, Summary: "Restarted nginx.service", PathOrKey: "nginx.service", Actor: "deploy", Host: "prod-web-01"},
		},
		Diff: "" +
			"--- a/etc/nginx/nginx.conf\n" +
			"+++ b/etc/nginx/nginx.conf\n" +
			"@@ -12,7 +12,7 @@\n" +
			"-    proxy_pass http://10.0.0.4:8080;\n" +
			"+    proxy_pass http://10.0.0.9:8080;\n" +
			"+    auth_basic_user_file [REDACTED:sha256:4f1a9c];\n",
		DiffRedacted: true,
		Attribution: Attribution{
			Actor:     "deploy",
			UID:       "1001",
			LoginUser: "a.chen",
			RemoteIP:  "203.0.113.44",
			Process:   "ssh",
			PID:       4812,
			PPID:      4801,
			Cmdline:   "ssh deploy@prod-web-01 vi /etc/nginx/nginx.conf",
			Lineage:   []string{"sshd", "bash", "sudo", "vi"},
			Source:    "process",
		},
		BlastRadius: BlastRadius{
			RiskSummary:      "Editing a web-tier configuration affects request routing and TLS termination.",
			AffectedServices: []string{"Web tier (nginx) — inbound HTTP(S) traffic"},
			RollbackCommand:  "# restore the previous revision\ncp -a '/etc/nginx/nginx.conf.orig' '/etc/nginx/nginx.conf'\nnginx -t && systemctl reload nginx",
			VerifyCommand:    "systemctl is-active nginx && curl -sS -o /dev/null -w '%{http_code}\\n' http://127.0.0.1/",
			RollbackNotes:    "nginx -t validates before it applies.",
		},
		Monitoring: Monitoring{
			GrafanaAnnotationURL:    "https://grafana.example.com/d/host?from=1&to=2",
			GrafanaHostDashboardURL: "https://grafana.example.com/d/host-health?var-host=prod-web-01",
			HostSummaryURL:          "https://grafana.example.com/api/hostsummary?host=prod-web-01",
		},
		ControlPlane: []AuditEntry{
			{Time: baseTime.Add(-3 * time.Minute), Actor: "a.chen", Role: "admin", Action: "policy.update", Target: "prod-web-config-critical", SourceIP: "203.0.113.44"},
		},
		ChangeTicket: &ChangeTicket{
			Ref:         "CHG-1042",
			Kind:        "servicenow",
			Status:      "approved",
			StatusLabel: "Approved",
			Summary:     "Raise nginx upstream timeout for checkout",
			RequestedBy: "a.chen",
			URL:         "https://snow.example.com/CHG-1042",
			Authorized:  true,
		},
		Compliance:       "approved",
		ComplianceReason: "CHG-1042 (Approved) is authorised and covers this change.",
		Analysis: &AIAnalysis{
			Engine:              "Azure OpenAI",
			Model:               "gpt-4o-deployment",
			RiskSummary:         "Reloads the TLS listener with a new upstream. A syntax error takes the site down on the next reload.",
			BlastRadius:         "High",
			AffectedServices:    []string{"Web tier (nginx) — inbound HTTP(S) traffic"},
			RollbackCommand:     "nginx -t && systemctl reload nginx",
			VerificationCommand: "curl -fsS http://127.0.0.1/healthz",
			RollbackNotes:       "Validate before reloading.",
			Scrubbed:            true,
		},
	}
}

/* -------------------------------------------------------------------------- */
/* Markdown rendering                                                         */
/* -------------------------------------------------------------------------- */

// The whole point of the bundle is that it is complete. Asserting on the ten
// section headings catches a renderer that stops emitting one, which is exactly
// the failure a reader would not notice until they needed that section.
func TestRenderEmitsEverySection(t *testing.T) {
	md := Render(fullBundle())

	sections := []string{
		"# Incident Post-Mortem:",
		"## 1. Executive Summary",
		"## 2. Change Control",
		"## 3. Root-Cause Attribution & Lineage",
		"## 4. Configuration Diff (scrubbed)",
		"## 5. Correlated Timeline",
		"## 6. Blast Radius & Rollback Plan",
		"## 7. AI-Assisted Assessment",
		"## 8. Monitoring Correlation",
		"## 9. Control-Plane Audit Trail",
		"## 10. Appendix: Agent Metadata",
	}
	for _, want := range sections {
		if !strings.Contains(md, want) {
			t.Errorf("rendered report is missing section %q", want)
		}
	}
}

// TestRenderOmitsAnalysisSectionWhenAbsent keeps the numbering honest: a report
// produced without an analysis must not have a dangling gap where section 7
// would be, because a reader counting sections would conclude one was lost.
func TestRenderOmitsAnalysisSectionWhenAbsent(t *testing.T) {
	b := fullBundle()
	b.Analysis = nil
	md := Render(b)

	if strings.Contains(md, "AI-Assisted Assessment") {
		t.Error("an absent analysis still emitted a section")
	}
	if !strings.Contains(md, "## 8. Monitoring Correlation") {
		t.Error("the monitoring section is missing when there is no analysis")
	}
}

// TestRenderAnalysisCreditsTheEngine pins the property that makes the section
// trustworthy: the reader must be able to tell a model's judgement from the
// offline heuristics, and must see that only scrubbed content was sent.
func TestRenderAnalysisCreditsTheEngine(t *testing.T) {
	md := Render(fullBundle())
	for _, want := range []string{
		"Azure OpenAI",
		"gpt-4o-deployment",
		"Blast radius: High",
		"nginx -t && systemctl reload nginx",
		"curl -fsS http://127.0.0.1/healthz",
		"no secret value left the host",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("analysis section is missing %q", want)
		}
	}
}

// TestRenderAnalysisStatesFallbackLoudly is the most important property of the
// section: a heuristic answer must never be presented as a model's judgement.
func TestRenderAnalysisStatesFallbackLoudly(t *testing.T) {
	b := fullBundle()
	b.Analysis = &AIAnalysis{
		Engine:         "Built-in Offline Heuristics",
		Fallback:       true,
		FallbackReason: "HTTP 401: invalid api key",
		RiskSummary:    "Editing a web-tier configuration affects request routing.",
		BlastRadius:    "High",
	}
	md := Render(b)

	if !strings.Contains(md, "Built-in Offline Heuristics") {
		t.Error("the engine name is missing")
	}
	if !strings.Contains(md, "was unreachable") {
		t.Error("a fallback was not declared")
	}
	if !strings.Contains(md, "invalid api key") {
		t.Error("the fallback reason was not carried into the report")
	}
}

func TestRenderExecutiveSummaryCarriesTheFacts(t *testing.T) {
	md := Render(fullBundle())

	// Each of these is a fact a manager asks for; the mapping from Bundle field
	// to report line is the contract.
	for _, want := range []string{
		"2026-03-14T09:02:11Z",           // incident timestamp, RFC3339 UTC
		"prod-web-01",                    // affected host
		"Level 1 · Critical",             // severity
		"`/etc/nginx/nginx.conf` (file)", // target
		"prod-web-config-critical",       // matched policy rule
		"Modified /etc/nginx/nginx.conf", // change summary
	} {
		if !strings.Contains(md, want) {
			t.Errorf("executive summary is missing %q", want)
		}
	}
}

func TestRenderIncludesAttributionLineage(t *testing.T) {
	md := Render(fullBundle())

	for _, want := range []string{
		"deploy",        // human actor
		"203.0.113.44",  // originating IP
		"ssh",           // process
		"4812 / 4801",   // pid / ppid
		"sshd  →  bash", // lineage is rendered as a tree, not a list
	} {
		if !strings.Contains(md, want) {
			t.Errorf("attribution section is missing %q", want)
		}
	}
}

// An unattributed production change is a finding in itself, so the report must
// say so rather than print an empty table that reads as "no problem here".
func TestRenderSaysWhenNothingWasAttributed(t *testing.T) {
	b := fullBundle()
	b.Attribution = Attribution{}

	md := Render(b)
	if !strings.Contains(md, "No actor could be attributed") {
		t.Fatal("an empty attribution must be called out, not silently omitted")
	}
	if strings.Contains(md, "| Human actor |") {
		t.Fatal("an empty attribution must not render a table of em dashes")
	}
}

// The redaction stub is not the file content; a reader who does not know that
// will assume the password really is `[REDACTED:sha256:...]`.
func TestRenderDeclaresRedaction(t *testing.T) {
	md := Render(fullBundle())
	if !strings.Contains(md, "[REDACTED:sha256:…]") {
		t.Fatal("a scrubbed diff must be labelled as scrubbed")
	}
	if !strings.Contains(md, "before the change left the host") {
		t.Fatal("the redaction notice must state where the scrubbing happened")
	}
}

// The notice must also fire when the caller did not set the flag but the diff
// visibly contains a stub: trusting the flag alone loses the disclaimer exactly
// when a caller forgot to compute it.
func TestRenderDetectsRedactionFromDiffContent(t *testing.T) {
	b := fullBundle()
	b.DiffRedacted = false
	b.Diff = "@@ -1 +1 @@\n-password = hunter2\n+password = [REDACTED:sha256:aaaa]\n"

	if md := Render(b); !strings.Contains(md, "[REDACTED:sha256:…]") {
		t.Fatal("a redaction stub in the diff body must trigger the notice")
	}
}

// A Level 3 drift event has no text diff. Printing an empty fenced block would
// imply "nothing changed"; the hashes are the evidence that something did.
func TestRenderHashesWhenNoDiffWasCaptured(t *testing.T) {
	b := fullBundle()
	b.Diff = ""
	b.DiffRedacted = false
	b.Event.Metadata = map[string]string{"hash_before": "9f2b1c07", "hash_after": "b1946ac9"}

	md := Render(b)
	if !strings.Contains(md, "metadata and SHA-256 only") {
		t.Fatal("a metadata-only change must explain why no diff is present")
	}
	for _, want := range []string{"9f2b1c07", "b1946ac9"} {
		if !strings.Contains(md, want) {
			t.Errorf("hash %q is the only available evidence and must be rendered", want)
		}
	}
	if strings.Contains(md, "```diff") {
		t.Fatal("an absent diff must not render an empty diff fence")
	}
}

// The incident row has to be identifiable inside the timeline, otherwise the
// reader cannot tell which of a dozen mutations the report is about.
func TestRenderTimelineMarksTheIncident(t *testing.T) {
	md := Render(fullBundle())

	if !strings.Contains(md, "**← incident**") {
		t.Fatal("the incident event must be marked in the timeline")
	}
	if strings.Count(md, "**← incident**") != 1 {
		t.Fatal("exactly one timeline row is the incident")
	}

	// Ordering is asserted inside the timeline section only: the incident
	// summary also appears in the H1 and the executive summary, so a
	// document-wide index would compare the wrong occurrences.
	timeline := md[strings.Index(md, "## 5. Correlated Timeline"):]
	iRotate := strings.Index(timeline, "Rotated access log")
	iIncident := strings.Index(timeline, "**← incident**")
	iRestart := strings.Index(timeline, "Restarted nginx.service")
	if !(iRotate < iIncident && iIncident < iRestart) {
		t.Fatalf("timeline is not chronological: rotate=%d incident=%d restart=%d", iRotate, iIncident, iRestart)
	}
}

// A quiet incident and a truncated report must not look the same.
func TestRenderSaysWhenTheWindowWasQuiet(t *testing.T) {
	b := fullBundle()
	b.Timeline = nil

	if md := Render(b); !strings.Contains(md, "isolated") {
		t.Fatal("an empty timeline must be stated explicitly")
	}
}

func TestRenderChangeControlVerdicts(t *testing.T) {
	cases := []struct {
		compliance string
		want       string
	}{
		{"approved", "**Authorised**"},
		{"unapproved", "**Unauthorised**"},
		{"expired", "**Change window expired**"},
		{"not_required", "Not required"},
	}
	for _, c := range cases {
		b := fullBundle()
		b.Compliance = c.compliance
		if md := Render(b); !strings.Contains(md, c.want) {
			t.Errorf("compliance %q: report is missing %q", c.compliance, c.want)
		}
	}
}

// With enforcement off and no ticket, the report must not imply a violation
// happened — an advisory deployment should not be producing "unauthorised"
// documents that reach an auditor.
func TestRenderChangeControlWithoutEnforcement(t *testing.T) {
	b := fullBundle()
	b.ChangeTicket = nil
	b.Compliance = ""

	md := Render(b)
	if !strings.Contains(md, "enforcement is not active") {
		t.Fatal("a non-enforcing deployment must be described as such")
	}
	if strings.Contains(md, "Unauthorised") {
		t.Fatal("no enforcement must never render as an unauthorised change")
	}
}

// A summary or path containing a pipe would otherwise split the Markdown table
// cell and corrupt every row after it. Only table cells need escaping — the
// prose heading legitimately echoes the raw summary — so the assertion is
// scoped to the timeline table.
func TestRenderEscapesPipesInTableCells(t *testing.T) {
	b := fullBundle()
	b.Event.Summary = `Modified nginx.conf (upstream "a|b")`
	b.Timeline[1].Summary = `Modified nginx.conf (upstream "a|b")`

	md := Render(b)
	timeline := md[strings.Index(md, "## 5. Correlated Timeline"):]
	timeline = timeline[:strings.Index(timeline, "## 6.")]

	if strings.Contains(timeline, "a|b") {
		t.Fatal("an unescaped pipe in a table cell corrupts the rest of the table")
	}
	if !strings.Contains(timeline, `a\|b`) {
		t.Fatal("escaped pipe not found in the timeline row")
	}
	// The row must still have exactly five cells: a broken escape shows up here
	// as an extra column rather than as a missing character. Escaped pipes are
	// removed first so they are not counted as cell separators.
	for _, line := range strings.Split(timeline, "\n") {
		if !strings.Contains(line, "upstream") {
			continue
		}
		if got := strings.Count(strings.ReplaceAll(line, `\|`, ""), "|"); got != 6 {
			t.Fatalf("timeline row has %d separators, want 6 for five cells: %q", got, line)
		}
	}
}

// The appendix is the raw evidence; unordered map iteration would make the
// document diff differently on every export, which defeats archiving it.
func TestRenderAppendixIsDeterministic(t *testing.T) {
	b := fullBundle()
	b.Event.Metadata = map[string]string{"z": "1", "a": "2", "m": "3", "b": "4", "y": "5"}

	first := Render(b)
	for i := 0; i < 20; i++ {
		if got := Render(b); got != first {
			t.Fatal("rendering the same bundle twice produced different documents")
		}
	}
	iA := strings.Index(first, "| `a` |")
	iB := strings.Index(first, "| `b` |")
	iM := strings.Index(first, "| `m` |")
	if !(iA < iB && iB < iM) {
		t.Fatal("appendix metadata is not sorted by key")
	}
}

func TestRenderWithMinimalBundle(t *testing.T) {
	// Nothing but the event: the report must still be a complete, valid
	// document rather than a partial one. This is the shape a hash-only drift
	// event on a freshly-enrolled host produces.
	b := Bundle{
		GeneratedAt: baseTime,
		Event: Event{
			ID: "evt-min", Host: "staging-web-01", Time: baseTime,
			Level: 3, LevelLabel: "Level 3 · Drift", Summary: "Modified redis.conf",
			TargetType: "file", PathOrKey: "/etc/redis/redis.conf",
		},
		Window: Window{From: baseTime.Add(-30 * time.Minute), To: baseTime.Add(30 * time.Minute), Label: "±30m"},
	}

	md := Render(b)
	for _, want := range []string{
		"## 1. Executive Summary",
		"## 10. Appendix: Agent Metadata",
		"No monitoring endpoints are configured",
		"No StateTrack administrative actions",
		"No additional agent metadata",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("minimal report is missing %q", want)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(md), "_Report generated 2026-03-14T09:02:11Z._") {
		t.Fatal("the report footer must always close the document")
	}
}

/* -------------------------------------------------------------------------- */
/* Structured bundle                                                          */
/* -------------------------------------------------------------------------- */

func TestRenderJSONIsStructuredAndSelfDescribing(t *testing.T) {
	b := fullBundle()
	raw, err := RenderJSON(b)
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	var got JSONBundle
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("bundle is not valid JSON: %v", err)
	}
	if got.Format != "statetrack.postmortem" {
		t.Errorf("Format = %q, want statetrack.postmortem", got.Format)
	}
	if got.Version != SchemaVersion {
		t.Errorf("Version = %d, want %d", got.Version, SchemaVersion)
	}
	// The Markdown is embedded so one download serves both audiences.
	if got.Markdown != Render(b) {
		t.Fatal("the embedded Markdown must be byte-identical to Render")
	}
	if got.ChangeTicket == nil || got.ChangeTicket.Ref != "CHG-1042" {
		t.Fatal("the correlated change ticket did not survive encoding")
	}
	if len(got.Timeline) != 3 {
		t.Errorf("timeline round-trip lost entries: got %d, want 3", len(got.Timeline))
	}
	if got.ComplianceReason == "" {
		t.Fatal("the compliance reason must be carried into the structured bundle")
	}
}

// The JSON form must not be an escape hatch that leaks what the Markdown
// redacted: the secret never reaches this package in cleartext, but the bundle
// must still record that redaction happened.
func TestRenderJSONPreservesRedactionSignal(t *testing.T) {
	raw, err := RenderJSON(fullBundle())
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	var got JSONBundle
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("bundle is not valid JSON: %v", err)
	}
	if !got.DiffRedacted {
		t.Fatal("the structured bundle must record that the diff was scrubbed")
	}
	if !strings.Contains(got.Diff, "[REDACTED:") {
		t.Fatal("the diff in the structured bundle should carry the stubs, not raw values")
	}
}

/* -------------------------------------------------------------------------- */
/* Filename                                                                   */
/* -------------------------------------------------------------------------- */

func TestFilenameIsFilesystemSafe(t *testing.T) {
	cases := []struct {
		host, eventID, ext, want string
	}{
		{"prod-web-01", "evt-9d2c41ab", "md", "statetrack-postmortem-prod-web-01-evt-9d2c.md"},
		{"prod-web-01", "evt-9d2c41ab", "json", "statetrack-postmortem-prod-web-01-evt-9d2c.json"},
		// A hostname is attacker-influenced data in a multi-tenant deployment;
		// a path separator in it must not let the download escape the intended
		// directory.
		{"../../etc/passwd", "evt-1", "md", "statetrack-postmortem-etc-passwd-evt-1.md"},
		{"prod k8s 01", "evt-2", "md", "statetrack-postmortem-prod-k8s-01-evt-2.md"},
		{"", "evt-3", "md", "statetrack-postmortem-unknown-host-evt-3.md"},
		{"prod-web-01", "evt-4", "", "statetrack-postmortem-prod-web-01-evt-4.md"},
	}
	for _, c := range cases {
		if got := Filename(c.host, c.eventID, c.ext); got != c.want {
			t.Errorf("Filename(%q, %q, %q) = %q, want %q", c.host, c.eventID, c.ext, got, c.want)
		}
	}
}

// The sanitised hostname must not contain a separator on any platform, since
// the download is written by the server's OS but named for the operator's.
func TestFilenameNeverContainsASeparator(t *testing.T) {
	for _, host := range []string{`..\..\windows\system32`, "/etc/shadow", "a/b/c", "....", "///"} {
		got := Filename(host, "evt-1", "md")
		if strings.ContainsAny(got, `/\`) {
			t.Errorf("Filename(%q) = %q contains a path separator", host, got)
		}
		if strings.Contains(got, "..") {
			t.Errorf("Filename(%q) = %q contains a traversal sequence", host, got)
		}
	}
}

/* -------------------------------------------------------------------------- */
/* Blast radius & remediation derivation                                      */
/* -------------------------------------------------------------------------- */

func TestDeriveBlastRadiusPerTargetClass(t *testing.T) {
	cases := []struct {
		name         string
		in           RemediationInput
		wantService  string // substring expected in AffectedServices[0]
		wantRollback string // substring expected in RollbackCommand
		wantVerify   string
	}{
		{
			name:         "nginx config",
			in:           RemediationInput{TargetType: "file", PathOrKey: "/etc/nginx/nginx.conf", Action: "Modified", OSFamily: "linux", DiffPresent: true},
			wantService:  "Web tier",
			wantRollback: "nginx -t && systemctl reload nginx",
			wantVerify:   "systemctl is-active nginx",
		},
		{
			name:         "apache config",
			in:           RemediationInput{TargetType: "file", PathOrKey: "/etc/apache2/apache2.conf", Action: "Modified", OSFamily: "linux", DiffPresent: true},
			wantService:  "Web tier",
			wantRollback: "apachectl configtest",
			wantVerify:   "systemctl is-active apache2",
		},
		{
			name:         "postgresql",
			in:           RemediationInput{TargetType: "file", PathOrKey: "/etc/postgresql/15/main/postgresql.conf", Action: "Modified", OSFamily: "linux", DiffPresent: true},
			wantService:  "Database server",
			wantRollback: "systemctl reload postgresql",
			wantVerify:   "pg_isready",
		},
		{
			name:         "redis",
			in:           RemediationInput{TargetType: "file", PathOrKey: "/etc/redis/redis.conf", Action: "Modified", OSFamily: "linux", DiffPresent: true},
			wantService:  "cache",
			wantRollback: "redis-cli CONFIG REWRITE",
			wantVerify:   "redis-cli ping",
		},
		{
			name:         "rabbitmq",
			in:           RemediationInput{TargetType: "file", PathOrKey: "/etc/rabbitmq/rabbitmq.conf", Action: "Modified", OSFamily: "linux", DiffPresent: true},
			wantService:  "broker",
			wantRollback: "systemctl reload rabbitmq",
			wantVerify:   "rabbitmq-diagnostics",
		},
		{
			name:         "systemd unit",
			in:           RemediationInput{TargetType: "file", PathOrKey: "/etc/systemd/system/payments.service", Action: "Modified", OSFamily: "linux", DiffPresent: true},
			wantService:  "payments",
			wantRollback: "systemctl reload payments.service",
			wantVerify:   "systemctl is-active payments.service",
		},
		{
			name:         "ssh config",
			in:           RemediationInput{TargetType: "file", PathOrKey: "/etc/ssh/sshd_config", Action: "Modified", OSFamily: "linux", DiffPresent: true},
			wantService:  "Host authentication",
			wantRollback: "systemctl reload sshd",
			wantVerify:   "sshd -T",
		},
		{
			name:         "sysctl",
			in:           RemediationInput{TargetType: "file", PathOrKey: "/etc/sysctl.conf", Action: "Modified", OSFamily: "linux", DiffPresent: true},
			wantService:  "Host kernel",
			wantRollback: "sysctl -p",
			wantVerify:   "sysctl -a",
		},
		{
			name:         "k8s configmap",
			in:           RemediationInput{TargetType: "k8s_configmap", PathOrKey: "/k8s/prod-k8s-01/payments/configmaps/app-config", Action: "Modified", OSFamily: "linux", DiffPresent: true, Cluster: "prod-k8s-01"},
			wantService:  "ConfigMap",
			wantRollback: "kubectl rollout undo",
			wantVerify:   "kubectl get configmap",
		},
		{
			name:         "k8s deployment",
			in:           RemediationInput{TargetType: "k8s_deployment", PathOrKey: "/k8s/prod-k8s-01/payments/deployments/payments-api", Action: "Modified", OSFamily: "linux", DiffPresent: true, Cluster: "prod-k8s-01"},
			wantService:  "Deployment",
			wantRollback: "kubectl rollout undo deployment/payments-api",
			wantVerify:   "kubectl rollout status",
		},
		{
			name:        "k8s ingress",
			in:          RemediationInput{TargetType: "k8s_ingress", PathOrKey: "/k8s/prod-k8s-01/payments/ingresses/checkout", Action: "Modified", OSFamily: "linux", DiffPresent: true, Cluster: "prod-k8s-01"},
			wantService: "Ingress",
			// An Ingress has no rollout history, so `rollout undo` — which does
			// not even accept Ingress — must never be offered for one.
			wantRollback: "kubectl apply -f",
			wantVerify:   "kubectl get ingress checkout",
		},
		{
			name:         "windows registry",
			in:           RemediationInput{TargetType: "registry", PathOrKey: `HKLM\Software\Company\App\LogLevel`, Action: "Modified", OSFamily: "windows", DiffPresent: true},
			wantService:  "Windows registry",
			wantRollback: "", // a value has no generic rollback; a note is the honest answer
			wantVerify:   "Get-ItemProperty",
		},
		{
			name:         "iis applicationHost",
			in:           RemediationInput{TargetType: "file", PathOrKey: `C:\Windows\System32\inetsrv\config\applicationHost.config`, Action: "Modified", OSFamily: "windows", DiffPresent: true},
			wantService:  "IIS",
			wantRollback: "Restore-WebConfiguration",
			wantVerify:   "appcmd.exe list sites",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DeriveBlastRadius(c.in)
			if got.RiskSummary == "" {
				t.Fatal("a risk summary must always be produced")
			}
			if len(got.AffectedServices) == 0 || !strings.Contains(got.AffectedServices[0], c.wantService) {
				t.Errorf("AffectedServices = %v, want one containing %q", got.AffectedServices, c.wantService)
			}
			if c.wantRollback == "" {
				if got.RollbackCommand != "" {
					t.Errorf("RollbackCommand = %q, want empty (no safe generic rollback exists)", got.RollbackCommand)
				}
				if got.RollbackNotes == "" {
					t.Error("when no rollback is offered, a note must explain the plan instead")
				}
			} else if !strings.Contains(got.RollbackCommand, c.wantRollback) {
				t.Errorf("RollbackCommand = %q, want it to contain %q", got.RollbackCommand, c.wantRollback)
			}
			if !strings.Contains(got.VerifyCommand, c.wantVerify) {
				t.Errorf("VerifyCommand = %q, want it to contain %q", got.VerifyCommand, c.wantVerify)
			}
		})
	}
}

// The platform gate is the highest-consequence rule in the derivation: telling
// an operator to run `systemctl` on a Windows host, or `Restart-Service` on a
// Linux one, wastes the most valuable minutes of the incident.
func TestDeriveBlastRadiusRespectsPlatform(t *testing.T) {
	windows := DeriveBlastRadius(RemediationInput{
		TargetType: "file", PathOrKey: "/etc/nginx/nginx.conf",
		Action: "Modified", OSFamily: "windows", DiffPresent: true,
	})
	if strings.Contains(windows.RollbackCommand, "systemctl") || strings.Contains(windows.VerifyCommand, "systemctl") {
		t.Fatalf("a Windows host must never receive a systemctl command: %q", windows.RollbackCommand)
	}

	linux := DeriveBlastRadius(RemediationInput{
		TargetType: "file", PathOrKey: "/etc/nginx/nginx.conf",
		Action: "Modified", OSFamily: "linux", DiffPresent: true,
	})
	if strings.Contains(linux.RollbackCommand, "Restart-Service") || strings.Contains(linux.VerifyCommand, "Get-Service") {
		t.Fatalf("a Linux host must never receive a PowerShell command: %q", linux.RollbackCommand)
	}
}

// Identity files are the case where the obvious advice ("reload and move on")
// is the dangerous one: a bad /etc/shadow locks out the account that would fix
// it, so the note has to say to verify in a second session.
func TestDeriveBlastRadiusWarnsOnIdentityFiles(t *testing.T) {
	for _, p := range []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers"} {
		got := DeriveBlastRadius(RemediationInput{
			TargetType: "file", PathOrKey: p,
			Action: "Modified", OSFamily: "linux", DiffPresent: true,
		})
		if !strings.Contains(got.RiskSummary, "lock out") {
			t.Errorf("%s: risk summary must warn about lockout, got %q", p, got.RiskSummary)
		}
		if !strings.Contains(got.RollbackNotes, "second session") {
			t.Errorf("%s: notes must require verification in a second session", p)
		}
		// There is no service to reload for an identity file, and inventing one
		// would be wrong advice.
		if strings.Contains(got.RollbackCommand, "systemctl") {
			t.Errorf("%s: identity files have no service to reload, got %q", p, got.RollbackCommand)
		}
	}
}

// A deleted file cannot be restored by copying the "previous revision" that no
// longer exists, so the note must redirect to the real source of truth.
func TestDeriveBlastRadiusNotesDeletions(t *testing.T) {
	got := DeriveBlastRadius(RemediationInput{
		TargetType: "file", PathOrKey: "/etc/nginx/nginx.conf",
		Action: "Deleted", OSFamily: "linux", DiffPresent: true,
	})
	if !strings.Contains(got.RollbackNotes, "configuration management") {
		t.Fatalf("a deletion must be redirected to configuration management: %q", got.RollbackNotes)
	}
}

// A restart with no diff is a forensic signal: there is nothing to roll back,
// and proposing one would send the operator down the wrong path.
func TestDeriveBlastRadiusRestartWithNoDiff(t *testing.T) {
	got := DeriveBlastRadius(RemediationInput{
		TargetType: "service", PathOrKey: "nginx.service",
		Action: "Restarted", OSFamily: "linux", DiffPresent: false,
	})
	if !strings.Contains(got.RollbackNotes, "nothing to roll back") {
		t.Fatalf("a diff-less restart must be described as forensic: %q", got.RollbackNotes)
	}
}

// An unrecognised target must produce an honest "unknown" rather than a guess:
// a plausible-looking wrong command is worse than none during an incident.
func TestDeriveBlastRadiusUnknownTargetOffersNoCommand(t *testing.T) {
	got := DeriveBlastRadius(RemediationInput{
		TargetType: "file", PathOrKey: "/opt/acme/thing.dat",
		Action: "Modified", OSFamily: "linux", DiffPresent: true,
	})
	if got.RollbackCommand != "" || got.VerifyCommand != "" {
		t.Fatalf("no command should be invented for an unknown target: %+v", got)
	}
	if !strings.Contains(got.RiskSummary, "could not be determined") {
		t.Fatalf("the risk summary must admit the blast radius is unknown: %q", got.RiskSummary)
	}
}

func TestDeriveBlastRadiusFoldsInSeverity(t *testing.T) {
	got := DeriveBlastRadius(RemediationInput{
		TargetType: "file", PathOrKey: "/etc/nginx/nginx.conf",
		Action: "Modified", LevelLabel: "Level 1 · Critical", OSFamily: "linux", DiffPresent: true,
	})
	if !strings.Contains(got.RiskSummary, "Level 1 · Critical") {
		t.Fatalf("the severity must appear in the risk sentence: %q", got.RiskSummary)
	}
}

// The rollback command is pasted into a shell by a human under pressure, so a
// path with a quote or space in it must not be able to break out of the command.
func TestDeriveBlastRadiusQuotesPaths(t *testing.T) {
	got := DeriveBlastRadius(RemediationInput{
		TargetType: "file", PathOrKey: "/etc/nginx/conf.d/site's name.conf",
		Action: "Modified", OSFamily: "linux", DiffPresent: true,
	})
	if !strings.Contains(got.RollbackCommand, `'\''`) {
		t.Fatalf("an embedded single quote must be escaped for the shell: %q", got.RollbackCommand)
	}
}

// registryParent exists because Get-ItemProperty reads properties, not values:
// pointing it at a value name errors out, which is a confusing failure in the
// one command the operator runs to confirm the rollback worked.
func TestRegistryParentStripsTheValueName(t *testing.T) {
	cases := map[string]string{
		`HKLM\Software\Company\App\LogLevel`: `HKLM\Software\Company\App`,
		`HKLM\Software`:                      `HKLM\Software`,
		`LogLevel`:                           `LogLevel`,
	}
	for in, want := range cases {
		if got := registryParent(in); got != want {
			t.Errorf("registryParent(%q) = %q, want %q", in, got, want)
		}
	}
}

// The component derivation is what selects the right command, so an unknown
// resource must yield an empty component rather than a default that would emit
// a confidently wrong rollback.
func TestServiceFromPathForUnknownTarget(t *testing.T) {
	service, component := serviceFromPath("file", "/opt/acme/thing.dat")
	if service != "" || component != "" {
		t.Fatalf("serviceFromPath on an unknown path = (%q, %q), want empty", service, component)
	}
}
