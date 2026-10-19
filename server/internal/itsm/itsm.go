// Package itsm correlates production configuration changes against approved
// ITIL change requests.
//
// The problem it solves is a compliance one rather than a monitoring one: an
// SRE team can already see that /etc/nginx/nginx.conf changed on prod-web-01 at
// 09:02. What an auditor and a SecOps reviewer cannot see is whether that change
// was *authorised* — whether an approved change ticket (CHG-1042) covered that
// host at that time, or whether somebody edited production outside the process.
//
// Nothing here talks to Jira or ServiceNow. It is deliberately a pure function
// over a ticket set, because the environments this product targets are
// air-gapped: tickets are mirrored into the local database by a poller, entered
// by hand, or reconciled from a CSV, and the correlation itself must be
// computable from local state alone. That also makes the decision table
// exhaustively testable, which matters for the one part of the product whose
// output is a compliance verdict.
package itsm

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Kind identifies the source system a change ticket came from. It is stored and
// displayed, never used to change the matching rules: a ticket is a ticket.
type Kind string

const (
	KindJira       Kind = "jira"
	KindServiceNow Kind = "servicenow"
	// KindManual is a ticket an operator entered directly, which is what an
	// air-gapped site uses when no poller can reach the ITSM instance.
	KindManual Kind = "manual"
)

// Kinds is the closed set the console renders.
var Kinds = []Kind{KindJira, KindServiceNow, KindManual}

// IsValidKind reports whether a kind is one the console can store.
func IsValidKind(k Kind) bool {
	for _, x := range Kinds {
		if x == k {
			return true
		}
	}
	return false
}

// Status is a normalized change-ticket state.
//
// The set is deliberately small and closed. Jira and ServiceNow each have their
// own workflow vocabulary (a ServiceNow instance can have a dozen custom states),
// and mapping them onto these five is what lets the correlation decision be one
// table rather than a per-system matrix. Anything unrecognised maps to
// StatusUnknown, which is treated as *not* approved — an unreadable state must
// never be read as authorisation.
type Status string

const (
	StatusDraft      Status = "draft"
	StatusRequested  Status = "requested"
	StatusApproved   Status = "approved"
	StatusInProgress Status = "in_progress"
	StatusCompleted  Status = "completed"
	StatusRejected   Status = "rejected"
	StatusCancelled  Status = "cancelled"
	StatusUnknown    Status = "unknown"
)

// statusAliases maps the vocabulary each system actually uses onto the
// normalized set. Lower-cased on lookup so "Approved" and "APPROVED" agree.
var statusAliases = map[string]Status{
	"draft": StatusDraft, "new": StatusDraft, "open": StatusDraft,
	"requested": StatusRequested, "pending": StatusRequested, "pending_approval": StatusRequested,
	"awaiting_approval": StatusRequested, "assess": StatusRequested, "authorize": StatusRequested,
	"approved": StatusApproved, "scheduled": StatusApproved,
	"in_progress": StatusInProgress, "implement": StatusInProgress, "implementing": StatusInProgress,
	"review": StatusInProgress, "reviewing": StatusInProgress,
	"completed": StatusCompleted, "closed": StatusCompleted, "done": StatusCompleted,
	"rejected": StatusRejected, "declined": StatusRejected,
	"cancelled": StatusCancelled, "canceled": StatusCancelled, "abandoned": StatusCancelled,
}

// NormalizeStatus maps an upstream status string onto the closed set.
//
// Whitespace and hyphens are folded to underscores first, because ServiceNow and
// Jira both use human-phrased statuses ("Pending Approval", "In-Progress") and
// refusing to parse them would read a real approval as unknown — which the
// verdict treats as *not* approved, i.e. a false compliance violation.
func NormalizeStatus(raw string) Status {
	key := strings.ToLower(strings.TrimSpace(raw))
	key = strings.NewReplacer(" ", "_", "-", "_").Replace(key)
	if s, ok := statusAliases[key]; ok {
		return s
	}
	return StatusUnknown
}

// Authorized reports whether a status represents a change that has been
// through approval and may legitimately be in flight.
//
// Only two states qualify. `requested` deliberately does not: a ticket sitting
// in an approval queue is the *absence* of authorisation, and treating it as
// approved would make the whole control worthless (anyone can open a ticket).
// `completed` does not qualify either — a closed ticket may cover a change that
// has already happened, but correlating a *new* mutation to it would let a
// long-closed ticket launder a fresh production edit.
func (s Status) Authorized() bool {
	return s == StatusApproved || s == StatusInProgress
}

// StatusLabel renders a status for the console badge.
func (s Status) Label() string {
	switch s {
	case StatusDraft:
		return "Draft"
	case StatusRequested:
		return "Pending Approval"
	case StatusApproved:
		return "Approved"
	case StatusInProgress:
		return "In Progress"
	case StatusCompleted:
		return "Completed"
	case StatusRejected:
		return "Rejected"
	case StatusCancelled:
		return "Cancelled"
	default:
		return "Unknown"
	}
}

// Enforcement is the operator's chosen posture for unauthorised production
// changes. It gates *reporting*, never ingestion: a change is always recorded,
// because a monitoring product that hides a mutation it dislikes is worse than
// useless during an incident.
type Enforcement string

const (
	EnforcementOff      Enforcement = "off"
	EnforcementWarn     Enforcement = "warn"
	EnforcementRequired Enforcement = "required"
)

// Enforcements is the closed set the console offers.
var Enforcements = []Enforcement{EnforcementOff, EnforcementWarn, EnforcementRequired}

// IsValidEnforcement reports whether a posture is one the console can store.
func IsValidEnforcement(e Enforcement) bool {
	for _, x := range Enforcements {
		if x == e {
			return true
		}
	}
	return false
}

// Label renders the posture for display.
func (e Enforcement) Label() string {
	switch e {
	case EnforcementOff:
		return "Off (advisory only)"
	case EnforcementWarn:
		return "Warn (flag unapproved changes)"
	case EnforcementRequired:
		return "Required (flag and alert)"
	default:
		return string(e)
	}
}

// Compliance is the verdict attached to a mutation.
type Compliance string

const (
	// ComplianceApproved: an authorised ticket covers this change.
	ComplianceApproved Compliance = "approved"
	// ComplianceUnapproved: enforcement is active and no authorised ticket
	// covers this change. This is the auditor's filter.
	ComplianceUnapproved Compliance = "unapproved"
	// ComplianceExpired: an authorised ticket exists in scope, but its window
	// has closed. Reported separately from "unapproved" because the operator's
	// remedy is different (extend the ticket rather than raise one).
	ComplianceExpired Compliance = "expired"
	// ComplianceNotRequired: the change needs no ticket (not Level 1, or an
	// exempt actor such as the agent itself), or enforcement is off.
	ComplianceNotRequired Compliance = "not_required"
)

// Label renders a compliance verdict for the console pill.
func (c Compliance) Label() string {
	switch c {
	case ComplianceApproved:
		return "Change Approved"
	case ComplianceUnapproved:
		return "Unapproved Change"
	case ComplianceExpired:
		return "Change Window Expired"
	default:
		return "No Change Required"
	}
}

// IsViolation reports whether a verdict is one an auditor should see.
func (c Compliance) IsViolation() bool {
	return c == ComplianceUnapproved || c == ComplianceExpired
}

// Ticket is a change request mirrored into StateTrack's local database.
type Ticket struct {
	ID   string `json:"id"`
	Kind Kind   `json:"kind"`
	// Ref is the ticket key an engineer would recognise and paste into a
	// commit message: "CHG-1042", "OPS-8813".
	Ref     string `json:"ref"`
	Status  Status `json:"status"`
	Summary string `json:"summary"`
	// URL deep-links back to the ticket in its source system. Optional: an
	// air-gapped instance has nowhere to link to.
	URL string `json:"url,omitempty"`

	// ---- Scope -------------------------------------------------------------
	//
	// A ticket is matched against a mutation on three axes. Any axis left empty
	// is a wildcard, which is how "a change approved for prod-web-01's nginx
	// config" and "a change approved for the whole fleet tonight" are both
	// expressible with the same record.

	// Hosts are hostnames (not ids) so a mirrored ticket — which knows the
	// hostname an engineer typed, not StateTrack's internal UUID — matches.
	Hosts []string `json:"hosts"`
	// Environments are logical tiers ("production", "staging"). The correlation
	// derives the mutation's environment from its hostname.
	Environments []string `json:"environments"`
	// Paths are wildcard globs matched against the mutated path or key.
	Paths []string `json:"paths"`

	// ---- Window -----------------------------------------------------------
	//
	// The interval the change is authorised for. A mutation outside it is not
	// covered, which is the whole point: an approved window of 30 minutes is not
	// a licence to edit production indefinitely.

	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`

	RequestedBy string    `json:"requested_by,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

// Event is the slice of a mutation the correlation needs. It is intentionally a
// small, explicit struct rather than the storage row: the decision table below
// reads exactly these fields, and nothing else can leak into the verdict.
type Event struct {
	ID       string
	Hostname string
	// PathOrKey is the mutated file path or registry key.
	PathOrKey  string
	TargetType string
	Level      int32
	OccurredAt time.Time
	Summary    string
	// Actor is the username that made the change, matched against the
	// configured exempt-actor list.
	Actor   string
	Cmdline string
	// Metadata is the agent's classification map, scanned for an explicit
	// ticket reference.
	Metadata map[string]string
}

// Result is the correlation verdict for one event.
type Result struct {
	Compliance Compliance `json:"compliance"`
	// Ticket is the matched ticket, nil when none applies.
	Ticket *Ticket `json:"ticket,omitempty"`
	// Ref is the ticket key found in the event (however it got there), which is
	// reported even when it matched nothing — "this change claims CHG-9999,
	// which we know nothing about" is a finding in itself.
	Ref string `json:"ref,omitempty"`
	// Reason explains the verdict in one sentence, for the badge tooltip.
	Reason string `json:"reason"`
	// Enforced reports whether the verdict came from an active enforcement
	// posture, so the console can distinguish "advisory" from "actionable".
	Enforced bool `json:"enforced"`
}

// Metadata keys an agent, an integration or a commit hook may use to stamp the
// ticket reference onto a change. Scanning several is what lets a site adopt
// whichever one its existing tooling already writes.
var refMetadataKeys = []string{
	"change_ticket", "change_request", "itsm_ticket", "ticket", "ticket_ref", "chg",
}

// refPatterns recognise a ticket key in free text, in the two shapes the
// mainstream systems use: ServiceNow's CHG-number and Jira's PROJECT-number.
//
// The Jira form is anchored on a 2–10 character upper-case project key followed
// by a dash and digits. It is matched only in the summary and command line, not
// in a file path, because a path like /var/log/nginx-2024.log would otherwise
// look like a ticket reference.
var refPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bCHG\d{3,10}\b`),
	regexp.MustCompile(`\bCHG-\d{3,10}\b`),
	regexp.MustCompile(`\b[A-Z]{2,10}-\d{1,7}\b`),
}

// refIgnored are hyphenated tokens that look like a Jira key but are not:
// version strings and the common configuration-suffix compounds that appear in
// paths and summaries.
var refIgnored = map[string]bool{
	"UTF-8": true, "ISO-8859": true, "SHA-256": true, "SHA-1": true, "SHA-512": true,
	"MD-5": true, "TLS-1": true, "HTTP-2": true, "HTTP-3": true, "T-1": true,
}

// ExtractRef returns the first plausible change-ticket reference in an event.
//
// Precedence is metadata first: an explicit field is a statement of intent,
// while a substring of a shell command line is a guess. Only if no metadata
// declares one do the summary and command line get scanned.
func ExtractRef(ev Event) string {
	for _, key := range refMetadataKeys {
		for k, v := range ev.Metadata {
			if !strings.EqualFold(k, key) {
				continue
			}
			if ref := normalizeRef(v); ref != "" {
				return ref
			}
		}
	}
	for _, text := range []string{ev.Summary, ev.Cmdline} {
		if ref := matchRef(text); ref != "" {
			return ref
		}
	}
	return ""
}

// normalizeRef validates a metadata-supplied reference. A metadata value is
// trusted to *be* a reference (that is what the field means), so it only needs
// shape-checking rather than full pattern scanning.
func normalizeRef(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 64 {
		return ""
	}
	upper := strings.ToUpper(raw)
	if refIgnored[upper] {
		return ""
	}
	return upper
}

// matchRef scans free text for a ticket-shaped token.
func matchRef(text string) string {
	if text == "" {
		return ""
	}
	for _, re := range refPatterns {
		for _, m := range re.FindAllString(text, -1) {
			if refIgnored[strings.ToUpper(m)] {
				continue
			}
			return strings.ToUpper(m)
		}
	}
	return ""
}

// EnvironmentOf derives a logical tier from a hostname.
//
// A ticket's environment scope has to be matched against something, and the
// hostname is the only signal available without asking an operator to tag every
// host twice. The check is token-aware for the same reason the risk tiering is:
// a substring test would classify "preprod-web-01" as production on the "prod"
// inside "preprod", which is the opposite of what the name says.
func EnvironmentOf(hostname string) string {
	for _, tok := range tokenize(strings.ToLower(hostname)) {
		switch tok {
		case "prod", "production", "live":
			return "production"
		case "preprod", "preproduction", "stag", "stage", "staging":
			return "staging"
		case "dev", "develop", "development":
			return "development"
		case "test", "testing", "qa", "uat":
			return "test"
		}
	}
	return "unknown"
}

// tokenize splits a value into alphanumeric tokens, treating every other
// character as a boundary ("prod-web-01" -> ["prod", "web", "01"]).
func tokenize(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool {
		return !('a' <= r && r <= 'z') && !('0' <= r && r <= '9')
	})
}

// Options configures a correlation run.
type Options struct {
	Enforcement Enforcement
	// WindowGrace extends each ticket's window on both sides when matching.
	//
	// A change control process is not clock-exact: a ticket approved for
	// 09:00–09:30 is routinely executed at 08:57 by an engineer who started
	// early, and flagging that as unauthorised would train reviewers to ignore
	// the control. The grace is explicit and bounded rather than implicit for
	// exactly that reason.
	WindowGrace time.Duration
	// Now is the reference time, used only to decide whether an in-scope ticket
	// whose window has closed is reported as "expired" rather than absent.
	Now time.Time
	// MinLevel is the impact level at which a change needs a ticket. Zero means
	// the Level-1 default. Only Level 1 by default: a Level 3 hash-only drift on
	// a staging box must never be reported as a compliance violation, or the
	// audit queue becomes useless.
	MinLevel int32
	// ExemptActors are usernames whose changes never need a ticket, matched
	// case-insensitively against the event's actor. A configuration-management
	// account is the canonical case: it *is* the system of record, so requiring
	// it to cite a ticket is circular.
	ExemptActors []string
}

// DefaultWindowGrace is the default tolerance applied to a ticket's window.
const DefaultWindowGrace = 15 * time.Minute

// Correlate evaluates one event against the known tickets.
//
// The decision table, in order:
//
//  1. Enforcement off, or the mutation is not Level 1 -> not_required.
//  2. An explicit reference resolves to an authorised, in-scope ticket
//     -> approved. This is checked first because a human who named the ticket
//     is the strongest available evidence, and it also means a ticket whose
//     scope record is incomplete still works when it is cited directly.
//  3. An explicit reference resolves to a ticket that exists but is not
//     authorised (rejected, cancelled, still pending) -> unapproved, with the
//     ticket attached. This is the most valuable finding the feature produces:
//     somebody edited production citing a change that was refused.
//  4. No reference, but an authorised ticket's scope covers the mutation
//     -> approved.
//  5. Only an authorised ticket whose window has closed matches -> expired.
//  6. Otherwise -> unapproved.
func Correlate(ev Event, tickets []Ticket, opts Options) Result {
	if opts.WindowGrace <= 0 {
		opts.WindowGrace = DefaultWindowGrace
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	if opts.Enforcement == "" {
		opts.Enforcement = EnforcementOff
	}
	if opts.MinLevel <= 0 || opts.MinLevel > 4 {
		opts.MinLevel = 1
	}

	base := Result{Compliance: ComplianceNotRequired, Enforced: false}
	if ev.Level != opts.MinLevel {
		base.Reason = fmt.Sprintf(
			"Change tickets are required for Level %d critical changes only.", opts.MinLevel)
		return base
	}
	if opts.Enforcement == EnforcementOff {
		base.Reason = "Change-ticket enforcement is off; this change is recorded for advisory review only."
		return base
	}
	if isExempt(ev.Actor, opts.ExemptActors) {
		base.Reason = fmt.Sprintf("Actor %q is exempt from change-ticket correlation.", ev.Actor)
		return base
	}
	base.Enforced = true

	ref := ExtractRef(ev)
	base.Ref = ref

	// An explicit reference is resolved against the whole ticket set, not only
	// the in-scope subset: a rejected ticket that a mutation cites must be
	// reported even though nothing else about it matches.
	if ref != "" {
		if tk, ok := findRef(tickets, ref); ok {
			t := tk
			if t.Status.Authorized() {
				return Result{
					Compliance: ComplianceApproved, Ticket: &t, Ref: ref, Enforced: true,
					Reason: fmt.Sprintf("%s (%s) is authorised and covers this change.", t.Ref, t.Status.Label()),
				}
			}
			return Result{
				Compliance: ComplianceUnapproved, Ticket: &t, Ref: ref, Enforced: true,
				Reason: fmt.Sprintf("%s is %s, not approved; this change is not authorised by it.",
					t.Ref, strings.ToLower(t.Status.Label())),
			}
		}
		// Referenced but unknown to us: still a violation, and worth saying so
		// precisely, because the two remedies (fix the reference vs. raise the
		// ticket) are different.
		return Result{
			Compliance: ComplianceUnapproved, Ref: ref, Enforced: true,
			Reason: fmt.Sprintf("This change cites %s, which is not a known change ticket.", ref),
		}
	}

	env := EnvironmentOf(ev.Hostname)

	// Authorised, in-scope, in-window.
	inWindow := matching(tickets, ev, env, func(t Ticket) bool {
		return t.Status.Authorized() && withinWindow(t, ev.OccurredAt, opts.WindowGrace)
	})
	if len(inWindow) > 0 {
		best := pick(inWindow)
		return Result{
			Compliance: ComplianceApproved, Ticket: &best, Enforced: true,
			Reason: fmt.Sprintf("Covered by %s (%s), approved for %s.",
				best.Ref, best.Status.Label(), scopeSentence(best)),
		}
	}

	// An authorised ticket scoped to this host, but closed by the time the
	// change happened. Reported distinctly so the reviewer extends the window
	// rather than investigating a phantom.
	expiredScope := matching(tickets, ev, env, func(t Ticket) bool {
		return t.Status.Authorized() && !withinWindow(t, ev.OccurredAt, opts.WindowGrace)
	})
	if len(expiredScope) > 0 {
		best := pick(expiredScope)
		return Result{
			Compliance: ComplianceExpired, Ticket: &best, Enforced: true,
			Reason: fmt.Sprintf("%s covers this target but its window closed at %s.",
				best.Ref, best.WindowEnd.UTC().Format(time.RFC3339)),
		}
	}

	// In scope but never authorised (pending, rejected, cancelled).
	unauthorised := matching(tickets, ev, env, func(t Ticket) bool { return !t.Status.Authorized() })
	if len(unauthorised) > 0 {
		best := pick(unauthorised)
		return Result{
			Compliance: ComplianceUnapproved, Ticket: &best, Enforced: true,
			Reason: fmt.Sprintf("%s covers this target but is %s.",
				best.Ref, strings.ToLower(best.Status.Label())),
		}
	}

	return Result{
		Compliance: ComplianceUnapproved, Enforced: true,
		Reason: "No approved change ticket covers this host at this time.",
	}
}

// isExempt reports whether an actor is on the exemption list. Matched
// case-insensitively on the whole name: a prefix match would let an actor named
// "terraform-helper" inherit "terraform"'s exemption, which is precisely the
// kind of near-miss that makes exemptions dangerous.
func isExempt(actor string, exempt []string) bool {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return false
	}
	for _, e := range exempt {
		if strings.EqualFold(strings.TrimSpace(e), actor) {
			return true
		}
	}
	return false
}

// matching filters the ticket set by scope predicate.
//
// Scope is evaluated before the predicate so an irrelevant ticket can never
// influence the verdict, and so the predicate only has to express the *policy*
// question (authorised? in window?) rather than re-implement matching.
func matching(tickets []Ticket, ev Event, env string, want func(Ticket) bool) []Ticket {
	var out []Ticket
	for _, t := range tickets {
		if !Covers(t, ev, env) {
			continue
		}
		if want(t) {
			out = append(out, t)
		}
	}
	return out
}

// Covers reports whether a ticket's scope covers a mutation.
//
// Every axis is conjunctive: a ticket scoped to host A and path B does not cover
// host A alone, nor path B on host C. An empty axis is a wildcard.
func Covers(t Ticket, ev Event, env string) bool {
	if len(t.Hosts) > 0 && !containsFold(t.Hosts, ev.Hostname) {
		return false
	}
	if len(t.Environments) > 0 && !containsFold(t.Environments, env) {
		return false
	}
	if len(t.Paths) > 0 && !matchesAny(t.Paths, ev.PathOrKey) {
		return false
	}
	return true
}

func containsFold(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(strings.TrimSpace(v), strings.TrimSpace(want)) {
			return true
		}
	}
	return false
}

// matchesAny reports whether a glob matches a path. `**` crosses separators and
// `*` does not, matching the semantics the agent's own classifier uses, so a
// ticket scope and a policy rule pattern read the same way.
func matchesAny(patterns []string, path string) bool {
	for _, p := range patterns {
		if globMatch(p, path) {
			return true
		}
	}
	return false
}

// globMatch reports whether a glob pattern matches a path.
//
// Two separators are recognised, because a ticket scope is written by hand and
// the target is either a POSIX path ("/etc/nginx/nginx.conf") or a Windows
// registry key ("HKLM\Software\..."). Backslashes are folded onto "/" first so
// both styles get identical semantics: `**` crosses separators, `*` and `?` do
// not. Without that fold a Windows scope silently matched nothing, which
// reports every change it was meant to authorise as a violation.
//
// The previous `/**`-suffix shortcut has been removed deliberately: a plain
// string prefix test made "/etc/nginx/**" match "/etc/nginx-backup/nginx.conf".
// Segment matching requires a real separator boundary.
func globMatch(pattern, path string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if !strings.ContainsAny(pattern, "*?") {
		// A scope with no wildcards names one file, so it is compared whole
		// rather than by segment: "/etc/nginx.conf" must not accept a path that
		// merely starts the same way.
		return strings.EqualFold(pattern, path)
	}
	// A single `*` does not cross a separator, so the comparison is done
	// segment by segment rather than by translating the glob into one regexp
	// over the whole path.
	return matchSegments(
		strings.Split(foldSeparators(pattern), "/"),
		strings.Split(foldSeparators(path), "/"),
	)
}

// foldSeparators maps Windows registry separators onto the POSIX one so a single
// segment matcher serves both path styles.
func foldSeparators(p string) string {
	if !strings.Contains(p, `\`) {
		return p
	}
	return strings.ReplaceAll(p, `\`, "/")
}

func matchSegments(pat, parts []string) bool {
	if len(pat) == 0 {
		return len(parts) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(parts); i++ {
			if matchSegments(pat[1:], parts[i:]) {
				return true
			}
		}
		return false
	}
	if len(parts) == 0 || !matchSegment(pat[0], parts[0]) {
		return false
	}
	return matchSegments(pat[1:], parts[1:])
}

// matchSegment matches one path segment against one pattern segment with `?` as
// a single-character wildcard.
func matchSegment(pat, s string) bool {
	if !strings.ContainsAny(pat, "*?") {
		return pat == s
	}
	// Iterative backtracking matcher: a recursive one is exponential on inputs
	// like "*a*a*a*b", and a ticket pattern is attacker-influenced data in a
	// deployment where tickets are mirrored from an external system.
	var pi, si, star, mark int
	star = -1
	for si < len(s) {
		switch {
		case pi < len(pat) && (pat[pi] == '?' || pat[pi] == s[si]):
			pi++
			si++
		case pi < len(pat) && pat[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(pat) && pat[pi] == '*' {
		pi++
	}
	return pi == len(pat)
}

// withinWindow reports whether a time falls inside a ticket's window, allowing
// for the configured grace. An open-ended ticket (either bound zero) is treated
// as unbounded on that side.
func withinWindow(t Ticket, at time.Time, grace time.Duration) bool {
	if !t.WindowStart.IsZero() && at.Before(t.WindowStart.Add(-grace)) {
		return false
	}
	if !t.WindowEnd.IsZero() && at.After(t.WindowEnd.Add(grace)) {
		return false
	}
	return true
}

// findRef looks a ticket up by reference, case-insensitively.
func findRef(tickets []Ticket, ref string) (Ticket, bool) {
	for _, t := range tickets {
		if strings.EqualFold(strings.TrimSpace(t.Ref), ref) {
			return t, true
		}
	}
	return Ticket{}, false
}

// pick chooses the most specific ticket from a candidate set, so the badge names
// the change an engineer is most likely to recognise rather than an arbitrary
// fleet-wide one.
//
// Ordering: a narrower host scope beats a wildcard, then a newer window start
// beats an older one, then the reference breaks the tie so the result is stable
// across runs.
func pick(candidates []Ticket) Ticket {
	sorted := append([]Ticket(nil), candidates...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if len(a.Hosts) != len(b.Hosts) {
			return len(a.Hosts) > len(b.Hosts)
		}
		if !a.WindowStart.Equal(b.WindowStart) {
			return a.WindowStart.After(b.WindowStart)
		}
		return a.Ref < b.Ref
	})
	return sorted[0]
}

// scopeSentence renders a ticket's scope for a human-readable reason.
func scopeSentence(t Ticket) string {
	var parts []string
	if len(t.Hosts) == 0 {
		parts = append(parts, "the whole fleet")
	} else {
		parts = append(parts, strings.Join(t.Hosts, ", "))
	}
	if len(t.Paths) > 0 {
		parts = append(parts, strings.Join(t.Paths, ", "))
	}
	return strings.Join(parts, " · ")
}
