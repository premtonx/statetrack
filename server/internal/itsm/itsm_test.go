package itsm

import (
	"strings"
	"testing"
	"time"
)

// base is the reference instant every test window is built around, so the
// decision table is asserted against fixed times rather than "now".
var base = time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)

// approvedNginx is the canonical "a change was properly authorised" ticket: an
// approved, in-window change to the nginx config on one production host.
func approvedNginx() Ticket {
	return Ticket{
		ID: "t1", Kind: KindServiceNow, Ref: "CHG-1042", Status: StatusApproved,
		Hosts: []string{"prod-web-01"}, Environments: []string{"production"},
		Paths:       []string{"/etc/nginx/**"},
		WindowStart: base.Add(-2 * time.Hour), WindowEnd: base.Add(2 * time.Hour),
	}
}

// evFor builds a Level 1 production change to a path on a host.
func evFor(host, path string) Event {
	return Event{
		ID: "e1", Hostname: host, PathOrKey: path, TargetType: "file",
		Level: 1, OccurredAt: base.Add(10 * time.Minute),
		Summary: "Modified " + path,
	}
}

func strict() Options {
	return Options{Enforcement: EnforcementRequired, Now: base.Add(10 * time.Minute)}
}

func TestCorrelateApprovedTicketCoversChange(t *testing.T) {
	res := Correlate(evFor("prod-web-01", "/etc/nginx/nginx.conf"), []Ticket{approvedNginx()}, strict())
	if res.Compliance != ComplianceApproved {
		t.Fatalf("compliance = %q, want approved (reason: %s)", res.Compliance, res.Reason)
	}
	if res.Ticket == nil || res.Ticket.Ref != "CHG-1042" {
		t.Fatalf("ticket = %+v, want CHG-1042 attached", res.Ticket)
	}
	if !res.Enforced {
		t.Error("Enforced = false, want true under required enforcement")
	}
}

// The single most valuable outcome of the feature: a change citing a ticket
// that was refused. It must never be reported as approved.
func TestCorrelateRejectedReferencedTicketIsAViolation(t *testing.T) {
	rejected := approvedNginx()
	rejected.Status = StatusRejected
	ev := evFor("prod-web-01", "/etc/nginx/nginx.conf")
	ev.Metadata = map[string]string{"change_ticket": "CHG-1042"}

	res := Correlate(ev, []Ticket{rejected}, strict())
	if res.Compliance != ComplianceUnapproved {
		t.Fatalf("compliance = %q, want unapproved", res.Compliance)
	}
	if res.Ticket == nil || res.Ticket.Ref != "CHG-1042" {
		t.Fatalf("ticket = %+v, want the rejected ticket attached as evidence", res.Ticket)
	}
	if !strings.Contains(res.Reason, "rejected") {
		t.Errorf("reason = %q, want it to name the rejected status", res.Reason)
	}
}

// A reference that names a ticket the mirror does not know about is still a
// finding, and its reason must differ from "no ticket at all" so the operator
// knows which remedy applies.
func TestCorrelateUnknownReferencedTicketIsAViolation(t *testing.T) {
	ev := evFor("prod-web-01", "/etc/nginx/nginx.conf")
	ev.Metadata = map[string]string{"change_ticket": "CHG-9999"}

	res := Correlate(ev, []Ticket{approvedNginx()}, strict())
	if res.Compliance != ComplianceUnapproved {
		t.Fatalf("compliance = %q, want unapproved", res.Compliance)
	}
	if res.Ref != "CHG-9999" {
		t.Errorf("Ref = %q, want CHG-9999", res.Ref)
	}
	if !strings.Contains(res.Reason, "not a known change ticket") {
		t.Errorf("reason = %q, want it to distinguish an unknown reference", res.Reason)
	}
}

// The strongest evidence available: a human named the ticket, and it is
// authorised. Scope is not re-checked, because citing an approved ticket is a
// stronger statement than a wildcard scope record.
func TestCorrelateCitedApprovedTicketWinsOverScope(t *testing.T) {
	tickets := []Ticket{{
		ID: "t1", Kind: KindJira, Ref: "OPS-8813", Status: StatusApproved,
		Hosts:       []string{"some-other-host"},
		WindowStart: base.Add(-time.Hour), WindowEnd: base.Add(time.Hour),
	}}
	ev := evFor("prod-web-01", "/etc/nginx/nginx.conf")
	ev.Metadata = map[string]string{"ticket": "OPS-8813"}

	res := Correlate(ev, tickets, strict())
	if res.Compliance != ComplianceApproved {
		t.Fatalf("compliance = %q, want approved", res.Compliance)
	}
}

// A pending ticket is the absence of authorisation, not a weak form of it.
func TestCorrelatePendingTicketDoesNotAuthorize(t *testing.T) {
	pending := approvedNginx()
	pending.Status = StatusRequested
	res := Correlate(evFor("prod-web-01", "/etc/nginx/nginx.conf"), []Ticket{pending}, strict())
	if res.Compliance != ComplianceUnapproved {
		t.Fatalf("compliance = %q, want unapproved for a pending ticket", res.Compliance)
	}
	if !strings.Contains(res.Reason, "pending approval") {
		t.Errorf("reason = %q, want it to name the pending status", res.Reason)
	}
}

// A closed ticket is not a licence to edit production afterwards, and the
// separate verdict is what tells the operator to extend the window rather than
// open a new ticket.
func TestCorrelateClosedWindowIsExpired(t *testing.T) {
	closed := approvedNginx()
	closed.WindowStart = base.Add(-8 * time.Hour)
	closed.WindowEnd = base.Add(-6 * time.Hour)
	res := Correlate(evFor("prod-web-01", "/etc/nginx/nginx.conf"), []Ticket{closed}, strict())

	if res.Compliance != ComplianceExpired {
		t.Fatalf("compliance = %q, want expired", res.Compliance)
	}
	if !res.Compliance.IsViolation() {
		t.Error("IsViolation() = false, want true: an out-of-window change is unauthorised")
	}
}

// The grace is what stops an engineer who started four minutes early being
// flagged; without it the control trains reviewers to ignore it.
func TestCorrelateWindowGraceApplies(t *testing.T) {
	tk := approvedNginx()
	tk.WindowStart = base.Add(-time.Hour)
	tk.WindowEnd = base.Add(-time.Minute) // closed 1 minute before the change

	ev := evFor("prod-web-01", "/etc/nginx/nginx.conf")
	opts := strict()
	opts.WindowGrace = 15 * time.Minute

	if res := Correlate(ev, []Ticket{tk}, opts); res.Compliance != ComplianceApproved {
		t.Fatalf("with grace: compliance = %q, want approved", res.Compliance)
	}

	opts.WindowGrace = time.Second
	if res := Correlate(ev, []Ticket{tk}, opts); res.Compliance != ComplianceExpired {
		t.Fatalf("without grace: compliance = %q, want expired", res.Compliance)
	}
}

// A ticket scoped to a host does not authorise the same path on a different
// host. This is the multi-host fleet case, where a wildcard path is the norm.
func TestCorrelateHostScopeIsConjunctive(t *testing.T) {
	tk := approvedNginx()
	tk.Hosts = []string{"prod-web-01"}
	// Same path, different host.
	res := Correlate(evFor("prod-web-09", "/etc/nginx/nginx.conf"), []Ticket{tk}, strict())
	if res.Compliance != ComplianceUnapproved {
		t.Fatalf("compliance = %q, want unapproved for an out-of-scope host", res.Compliance)
	}
}

// And a wildcard host (empty scope) does cover every host, which is how a
// fleet-wide approved change is expressed.
func TestCorrelateFleetWideTicketCoversAnyHost(t *testing.T) {
	tk := approvedNginx()
	tk.Hosts = nil
	tk.Environments = []string{"production"}
	res := Correlate(evFor("prod-web-42", "/etc/nginx/nginx.conf"), []Ticket{tk}, strict())
	if res.Compliance != ComplianceApproved {
		t.Fatalf("compliance = %q, want approved under a fleet-wide ticket", res.Compliance)
	}
}

// A ticket for production must not authorise an edit on a staging box, which is
// the environment axis of the conjunction.
func TestCorrelateEnvironmentScopeIsConjunctive(t *testing.T) {
	tk := approvedNginx()
	tk.Environments = []string{"production"}
	res := Correlate(evFor("staging-web-01", "/etc/nginx/nginx.conf"), []Ticket{tk}, strict())
	if res.Compliance != ComplianceUnapproved {
		t.Fatalf("compliance = %q, want unapproved for a staging host", res.Compliance)
	}
}

// Level 3 staging drift must never reach an auditor's queue.
func TestCorrelateNonLevelOneIsNotRequired(t *testing.T) {
	ev := evFor("staging-web-01", "/var/www/html/index.html")
	ev.Level = 3
	res := Correlate(ev, nil, strict())
	if res.Compliance != ComplianceNotRequired {
		t.Fatalf("compliance = %q, want not_required", res.Compliance)
	}
	if res.Enforced {
		t.Error("Enforced = true, want false: a non-Level-1 change needs no ticket")
	}
}

// With enforcement off nothing is flagged; the change is still recorded.
func TestCorrelateEnforcementOffIsAdvisory(t *testing.T) {
	res := Correlate(evFor("prod-web-01", "/etc/nginx/nginx.conf"), nil,
		Options{Enforcement: EnforcementOff})
	if res.Compliance != ComplianceNotRequired {
		t.Fatalf("compliance = %q, want not_required when enforcement is off", res.Compliance)
	}
	if res.Enforced {
		t.Error("Enforced = true, want false with enforcement off")
	}
}

// A configuration-management account is the system of record, so requiring it to
// cite a ticket is circular.
func TestCorrelateExemptActorIsNotRequired(t *testing.T) {
	ev := evFor("prod-web-01", "/etc/nginx/nginx.conf")
	ev.Actor = "terraform"
	opts := strict()
	opts.ExemptActors = []string{"Terraform"}

	res := Correlate(ev, nil, opts)
	if res.Compliance != ComplianceNotRequired {
		t.Fatalf("compliance = %q, want not_required for an exempt actor", res.Compliance)
	}
	if !strings.Contains(res.Reason, "exempt") {
		t.Errorf("reason = %q, want it to say the actor is exempt", res.Reason)
	}
}

// Exemption is exact-match only: a lookalike name must not inherit it.
func TestCorrelateExemptionIsExactMatch(t *testing.T) {
	ev := evFor("prod-web-01", "/etc/nginx/nginx.conf")
	ev.Actor = "terraform-helper"
	opts := strict()
	opts.ExemptActors = []string{"terraform"}

	if res := Correlate(ev, nil, opts); res.Compliance != ComplianceUnapproved {
		t.Fatalf("compliance = %q, want unapproved: a lookalike actor must not inherit an exemption", res.Compliance)
	}
}

func TestCorrelateCustomMinLevel(t *testing.T) {
	ev := evFor("prod-web-01", "/etc/nginx/nginx.conf")
	ev.Level = 2
	opts := strict()
	opts.MinLevel = 2
	if res := Correlate(ev, nil, opts); res.Compliance != ComplianceUnapproved {
		t.Fatalf("compliance = %q, want unapproved at min_level=2", res.Compliance)
	}
	// A Level 3 change must still be exempt at min_level=2.
	ev.Level = 3
	if res := Correlate(ev, nil, opts); res.Compliance != ComplianceNotRequired {
		t.Fatalf("compliance = %q, want not_required below min_level", res.Compliance)
	}
}

// With several candidate tickets the badge should name the most specific one,
// not whichever the map iterated first.
func TestCorrelatePicksMostSpecificTicket(t *testing.T) {
	fleet := approvedNginx()
	fleet.Ref = "CHG-0001"
	fleet.Hosts = nil

	specific := approvedNginx()
	specific.Ref = "CHG-1042"
	specific.Hosts = []string{"prod-web-01", "prod-web-02"}

	res := Correlate(evFor("prod-web-01", "/etc/nginx/nginx.conf"), []Ticket{fleet, specific}, strict())
	if res.Ticket == nil {
		t.Fatal("no ticket attached")
	}
	if res.Ticket.Ref != "CHG-1042" {
		t.Fatalf("ticket = %s, want the two-host ticket CHG-1042 over the fleet-wide one", res.Ticket.Ref)
	}
}

// Selection must be order-independent, or the badge would change with map or
// row order.
func TestCorrelateSelectionIsOrderIndependent(t *testing.T) {
	a := approvedNginx()
	a.Ref = "CHG-0002"
	b := approvedNginx()
	b.Ref = "CHG-0003"
	// Identical scope: the reference breaks the tie, so the result is stable.
	first := Correlate(evFor("prod-web-01", "/etc/nginx/nginx.conf"), []Ticket{a, b}, strict())
	second := Correlate(evFor("prod-web-01", "/etc/nginx/nginx.conf"), []Ticket{b, a}, strict())
	if first.Ticket.Ref != second.Ticket.Ref {
		t.Fatalf("selection not order-independent: %s vs %s", first.Ticket.Ref, second.Ticket.Ref)
	}
}

func TestExtractRefFromMetadata(t *testing.T) {
	cases := []struct {
		key, value, want string
	}{
		{"change_ticket", "chg-1042", "CHG-1042"},
		{"change_request", "OPS-8813", "OPS-8813"},
		{"ticket", "  CHG-77  ", "CHG-77"},
		{"ticket_ref", "inc0001234", "INC0001234"},
	}
	for _, c := range cases {
		ev := Event{Metadata: map[string]string{c.key: c.value}}
		if got := ExtractRef(ev); got != c.want {
			t.Errorf("metadata %s=%q: ExtractRef = %q, want %q", c.key, c.value, got, c.want)
		}
	}
}

// The metadata field is a declaration of intent, so it outranks a token found
// in the summary.
func TestExtractRefMetadataBeatsSummary(t *testing.T) {
	ev := Event{
		Summary:  "Modified /etc/nginx/nginx.conf (ref CHG-9999)",
		Metadata: map[string]string{"change_ticket": "CHG-1042"},
	}
	if got := ExtractRef(ev); got != "CHG-1042" {
		t.Fatalf("ExtractRef = %q, want the metadata reference CHG-1042", got)
	}
}

func TestExtractRefFromFreeText(t *testing.T) {
	cases := map[string]string{
		"kubectl apply -f cm.yaml for CHG-1042": "CHG-1042",
		"deploy hotfix OPS-8813 to prod":        "OPS-8813",
		"change CHG0001234 requested":           "CHG0001234",
	}
	for text, want := range cases {
		if got := ExtractRef(Event{Summary: text}); got != want {
			t.Errorf("ExtractRef(%q) = %q, want %q", text, got, want)
		}
	}
}

// Version strings and the common config-suffix compounds look like Jira keys;
// treating them as ticket references would attach a bogus ticket to every change.
func TestExtractRefIgnoresVersionLikeTokens(t *testing.T) {
	for _, text := range []string{
		"Upgraded nginx to UTF-8 aware build",
		"Validated SHA-256 checksum",
		"Modified ISO-8859 locale settings",
	} {
		if got := ExtractRef(Event{Summary: text}); got != "" {
			t.Errorf("ExtractRef(%q) = %q, want no reference", text, got)
		}
	}
}

// A file path must not be scanned for references: "nginx-2024.log" would
// otherwise look like a Jira key.
func TestExtractRefDoesNotScanPaths(t *testing.T) {
	ev := Event{PathOrKey: "/var/log/nginx-2024.log", Summary: "Modified a log file"}
	if got := ExtractRef(ev); got != "" {
		t.Fatalf("ExtractRef = %q, want no reference from a path", got)
	}
}

func TestEnvironmentOf(t *testing.T) {
	cases := map[string]string{
		"prod-web-01":    "production",
		"production-db":  "production",
		"live-api-01":    "production",
		"staging-web-01": "staging",
		"stage-app-2":    "staging",
		"dev-box":        "development",
		"qa-runner":      "test",
		"uat-01":         "test",
		"prod-k8s-01":    "production",
		"random-host":    "unknown",
		"win-app-02":     "unknown",
		// "preprod" is its own token, so it must not inherit production's tier
		// on the "prod" substring. Reading it as production would demand change
		// tickets for a pre-production box.
		"preprod-web-01": "staging",
	}
	for host, want := range cases {
		if got := EnvironmentOf(host); got != want {
			t.Errorf("EnvironmentOf(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestNormalizeStatus(t *testing.T) {
	cases := map[string]Status{
		"Approved": StatusApproved, "APPROVED": StatusApproved, "scheduled": StatusApproved,
		"In Progress": StatusInProgress, "implement": StatusInProgress,
		"Pending Approval": StatusRequested, "awaiting_approval": StatusRequested,
		"Closed": StatusCompleted, "done": StatusCompleted,
		"Rejected": StatusRejected, "cancelled": StatusCancelled,
		"something_new": StatusUnknown, "": StatusUnknown,
	}
	for raw, want := range cases {
		if got := NormalizeStatus(raw); got != want {
			t.Errorf("NormalizeStatus(%q) = %q, want %q", raw, got, want)
		}
	}
}

// Only two statuses authorise. Asserted explicitly because widening this set is
// the single change that would silently break the control.
func TestAuthorizedStatuses(t *testing.T) {
	authorized := []Status{StatusApproved, StatusInProgress}
	notAuthorized := []Status{
		StatusDraft, StatusRequested, StatusCompleted, StatusRejected, StatusCancelled, StatusUnknown,
	}
	for _, s := range authorized {
		if !s.Authorized() {
			t.Errorf("status %q: Authorized() = false, want true", s)
		}
	}
	for _, s := range notAuthorized {
		if s.Authorized() {
			t.Errorf("status %q: Authorized() = true, want false", s)
		}
	}
}

// An unreadable upstream status must never be read as authorisation.
func TestUnknownStatusIsNotAuthorized(t *testing.T) {
	if NormalizeStatus("some_custom_servicenow_state").Authorized() {
		t.Fatal("an unmapped status must not authorise a change")
	}
}

func TestComplianceIsViolation(t *testing.T) {
	violations := []Compliance{ComplianceUnapproved, ComplianceExpired}
	for _, c := range violations {
		if !c.IsViolation() {
			t.Errorf("%q: IsViolation() = false, want true", c)
		}
	}
	for _, c := range []Compliance{ComplianceApproved, ComplianceNotRequired} {
		if c.IsViolation() {
			t.Errorf("%q: IsViolation() = true, want false", c)
		}
	}
}

func TestGlobMatching(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/etc/nginx/**", "/etc/nginx/nginx.conf", true},
		{"/etc/nginx/**", "/etc/nginx/conf.d/site.conf", true},
		{"/etc/nginx/**", "/etc/nginx", true},
		{"/etc/nginx/**", "/etc/apache2/apache2.conf", false},
		{"/etc/nginx/*.conf", "/etc/nginx/nginx.conf", true},
		// A single `*` does not cross a separator, so a nested file must not match.
		{"/etc/nginx/*.conf", "/etc/nginx/conf.d/site.conf", false},
		{"/etc/**/nginx.conf", "/etc/nginx/nginx.conf", true},
		{"/etc/nginx/nginx.conf", "/etc/nginx/nginx.conf", true},
		{"/etc/nginx/nginx.conf", "/etc/nginx/other.conf", false},
		// A `/**` suffix must sit on a segment boundary: a plain prefix test
		// would make "/etc/nginx/**" claim "/etc/nginx-backup/nginx.conf".
		{"/etc/nginx/**", "/etc/nginx-backup/nginx.conf", false},
		// Windows registry scopes use backslashes and must get identical
		// semantics; a scope that silently matched nothing reported every change
		// it was written to authorise as a compliance violation.
		{`HKLM\Software\Company\App\**`, `HKLM\Software\Company\App\LogLevel`, true},
		{`HKLM\Software\Company\App\**`, `HKLM\Software\Company\Other\LogLevel`, false},
		{`HKLM\Software\Company\App\LogLevel`, `HKLM\Software\Company\App\LogLevel`, true},
		{"ConfigMap/**", "ConfigMap/prod/app-config", true},
		{"**/*.conf", "/etc/nginx/nginx.conf", true},
		{"*.conf", "nginx.conf", true},
		{"*.conf", "/etc/nginx.conf", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.path); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

// The segment matcher must not blow up on adversarial patterns; a ticket pattern
// is data mirrored from an external system, so it is not fully trusted.
func TestGlobMatchingIsNotExponential(t *testing.T) {
	pattern := strings.Repeat("*a", 20) + "*b"
	path := strings.Repeat("a", 60)
	done := make(chan bool, 1)
	go func() {
		globMatch(pattern, path)
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("globMatch did not terminate: a ticket pattern can hang the correlation")
	}
}

func TestCoverRequiresEveryAxis(t *testing.T) {
	tk := Ticket{
		Hosts:        []string{"prod-web-01"},
		Environments: []string{"production"},
		Paths:        []string{"/etc/nginx/**"},
	}
	cases := []struct {
		host, path string
		want       bool
	}{
		{"prod-web-01", "/etc/nginx/nginx.conf", true},
		{"prod-web-02", "/etc/nginx/nginx.conf", false},
		{"prod-web-01", "/etc/redis/redis.conf", false},
		{"staging-web-01", "/etc/nginx/nginx.conf", false},
	}
	for _, c := range cases {
		if got := Covers(tk, evFor(c.host, c.path), EnvironmentOf(c.host)); got != c.want {
			t.Errorf("Covers(host=%s, path=%s) = %v, want %v", c.host, c.path, got, c.want)
		}
	}
}

// An open-ended ticket (no end) authorises indefinitely; that is what "unset"
// means, and the alternative (treating a missing bound as closed) would make
// every imported ticket that omits its window useless.
func TestOpenEndedTicketIsUnbounded(t *testing.T) {
	tk := approvedNginx()
	tk.WindowStart = time.Time{}
	tk.WindowEnd = time.Time{}
	ev := evFor("prod-web-01", "/etc/nginx/nginx.conf")
	ev.OccurredAt = base.Add(365 * 24 * time.Hour)
	if res := Correlate(ev, []Ticket{tk}, strict()); res.Compliance != ComplianceApproved {
		t.Fatalf("compliance = %q, want approved for an open-ended ticket", res.Compliance)
	}
}

// Windows registry scopes use backslashes; the matcher must compare them
// literally rather than treating `\` as an escape.
func TestRegistryPathScopeMatchesLiterally(t *testing.T) {
	tk := Ticket{
		Ref: "OPS-8813", Status: StatusApproved,
		Hosts:       []string{"win-app-02"},
		Paths:       []string{`HKLM\Software\Company\**`},
		WindowStart: base.Add(-time.Hour), WindowEnd: base.Add(time.Hour),
	}
	ev := Event{
		ID: "e1", Hostname: "win-app-02", PathOrKey: `HKLM\Software\Company\App\LogLevel`,
		TargetType: "registry", Level: 1, OccurredAt: base,
	}
	if res := Correlate(ev, []Ticket{tk}, strict()); res.Compliance != ComplianceApproved {
		t.Fatalf("compliance = %q, want approved for a registry scope (reason: %s)",
			res.Compliance, res.Reason)
	}
}

// A Kubernetes ConfigMap change on a production namespace correlates the same
// way a file change does, which is the whole point of one pipeline.
func TestKubernetesConfigMapCorrelates(t *testing.T) {
	tk := Ticket{
		Ref: "CHG-1108", Status: StatusApproved,
		Hosts:       []string{"prod-k8s-01"},
		Paths:       []string{"ConfigMap/**"},
		WindowStart: base.Add(-time.Hour), WindowEnd: base.Add(time.Hour),
	}
	ev := Event{
		ID: "e1", Hostname: "prod-k8s-01", PathOrKey: "ConfigMap/prod/app-config",
		TargetType: "k8s_configmap", Level: 1, OccurredAt: base,
	}
	if res := Correlate(ev, []Ticket{tk}, strict()); res.Compliance != ComplianceApproved {
		t.Fatalf("compliance = %q, want approved for a ConfigMap scope (reason: %s)",
			res.Compliance, res.Reason)
	}
}

func TestCoversFoldsCase(t *testing.T) {
	tk := Ticket{Hosts: []string{"PROD-WEB-01"}}
	if !Covers(tk, evFor("prod-web-01", "/etc/nginx/nginx.conf"), "production") {
		t.Fatal("host scope should match case-insensitively: a ticket imported from Jira may differ in case")
	}
}

func TestIsValidKindAndEnforcement(t *testing.T) {
	for _, k := range Kinds {
		if !IsValidKind(k) {
			t.Errorf("IsValidKind(%q) = false, want true", k)
		}
	}
	if IsValidKind("github") {
		t.Error(`IsValidKind("github") = true, want false`)
	}
	for _, e := range Enforcements {
		if !IsValidEnforcement(e) {
			t.Errorf("IsValidEnforcement(%q) = false, want true", e)
		}
	}
	if IsValidEnforcement("block") {
		t.Error(`IsValidEnforcement("block") = true, want false`)
	}
}

func TestLabelsArePresent(t *testing.T) {
	for _, s := range []Status{StatusDraft, StatusRequested, StatusApproved, StatusInProgress,
		StatusCompleted, StatusRejected, StatusCancelled, StatusUnknown} {
		if s.Label() == "" {
			t.Errorf("status %q has no label", s)
		}
	}
	for _, c := range []Compliance{ComplianceApproved, ComplianceUnapproved, ComplianceExpired, ComplianceNotRequired} {
		if c.Label() == "" {
			t.Errorf("compliance %q has no label", c)
		}
	}
	for _, e := range Enforcements {
		if e.Label() == "" {
			t.Errorf("enforcement %q has no label", e)
		}
	}
}

// A report must always carry a reason: the badge's tooltip is the only place a
// reviewer sees *why* a change was flagged.
func TestEveryVerdictHasAReason(t *testing.T) {
	cases := []struct {
		name    string
		ev      Event
		tickets []Ticket
		opts    Options
	}{
		{"approved", evFor("prod-web-01", "/etc/nginx/nginx.conf"), []Ticket{approvedNginx()}, strict()},
		{"unapproved", evFor("prod-web-01", "/etc/redis/redis.conf"), nil, strict()},
		{"not_required", func() Event { e := evFor("prod-web-01", "/x"); e.Level = 3; return e }(), nil, strict()},
	}
	for _, c := range cases {
		if res := Correlate(c.ev, c.tickets, c.opts); strings.TrimSpace(res.Reason) == "" {
			t.Errorf("%s: verdict %q has no reason", c.name, res.Compliance)
		}
	}
}
