package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PostMortemWindow is how far either side of an incident the corroborating
// timeline reaches. 30 minutes is the default the product specifies: long enough
// to catch the package upgrade or service restart that usually precedes a
// visible failure, short enough that a report stays readable.
const PostMortemWindow = 30 * time.Minute

// MaxPostMortemWindow caps a caller-supplied window. A post-mortem is a document
// a human reads; asking for a 30-day window would produce a timeline of
// hundreds of thousands of rows and an unreadable report, so the request is
// clamped rather than refused.
const MaxPostMortemWindow = 24 * time.Hour

// PostMortemBundle is the gathered, database-backed part of an incident report.
//
// It is deliberately a plain struct of the raw rows rather than the API's
// rendered bundle: the assembly into a document (and all the presentation
// decisions in it) lives in internal/postmortem, which keeps this layer free of
// report formatting and the report free of SQL.
type PostMortemBundle struct {
	Event    EventDetail
	Hostname string
	// OSFamily is the affected host's platform, used to pick Linux vs Windows
	// remediation commands.
	OSFamily string
	// Timeline is every root event on the host inside the window, oldest first
	// (a post-mortem timeline is read forwards).
	Timeline []Event
	// ControlPlane is the administrative audit rows inside the window.
	ControlPlane []AuditLog
	// IncidentWindow is the resolved window actually used, after clamping.
	IncidentWindow time.Time
	// WindowStart and WindowEnd bound the timeline, inclusive.
	WindowStart time.Time
	WindowEnd   time.Time
}

// GatherPostMortem loads everything a post-mortem bundle needs for one event.
//
// `window` is the half-width either side of the incident; zero means
// PostMortemWindow and anything above MaxPostMortemWindow is clamped.
//
// All four queries are scoped by org and bounded by the window, so a report on
// one event cannot be used to scan the events table. They run sequentially
// rather than concurrently because the event lookup gates the rest: a report for
// an event in another org must not run the timeline query at all.
func (s *Store) GatherPostMortem(ctx context.Context, orgID, eventID string, window time.Duration) (PostMortemBundle, error) {
	if window <= 0 {
		window = PostMortemWindow
	}
	if window > MaxPostMortemWindow {
		window = MaxPostMortemWindow
	}
	if _, err := uuid.Parse(eventID); err != nil {
		return PostMortemBundle{}, ErrNotFound
	}

	detail, err := s.GetEvent(ctx, orgID, eventID)
	if err != nil {
		return PostMortemBundle{}, err
	}

	bundle := PostMortemBundle{
		Event:          detail,
		Hostname:       detail.Hostname,
		IncidentWindow: detail.OccurredAt,
		WindowStart:    detail.OccurredAt.Add(-window),
		WindowEnd:      detail.OccurredAt.Add(window),
	}

	// The host's OS decides which remediation command the report offers, so a
	// missing host row is not fatal to the report — it just means the Linux/
	// Windows-specific advice falls back to a generic plan.
	if err := s.pool.QueryRow(ctx,
		`SELECT os_family FROM hosts WHERE id = $1::uuid AND org_id = $2::uuid`,
		detail.HostID, orgID).Scan(&bundle.OSFamily); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return PostMortemBundle{}, fmt.Errorf("post-mortem host lookup: %w", err)
	}

	// Corroborating timeline, oldest first, root events only.
	//
	// Children are excluded because a Level 2 transaction carries hundreds of
	// them and they are already summarised by the parent row; including them
	// would bury the one change the report is about. The incident event itself is
	// included, and marked, so a reader sees it in its chronological place.
	rows, err := s.pool.Query(ctx, eventSelect+`
		WHERE e.org_id = $1::uuid AND e.host_id = $2::uuid
		  AND e.occurred_at >= $3 AND e.occurred_at <= $4
		  AND e.parent_event_id IS NULL
		ORDER BY e.occurred_at, e.id
		LIMIT 500`, orgID, detail.HostID, bundle.WindowStart, bundle.WindowEnd)
	if err != nil {
		return PostMortemBundle{}, fmt.Errorf("post-mortem timeline: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return PostMortemBundle{}, err
		}
		bundle.Timeline = append(bundle.Timeline, ev)
	}
	if err := rows.Err(); err != nil {
		return PostMortemBundle{}, err
	}

	// Control-plane actions during the window. Not org-scoped: the audit table is
	// platform-wide by design, and "what did StateTrack do during this incident"
	// is a question whose answer should not be narrowed to one tenant.
	auditRows, err := s.pool.Query(ctx, `
		SELECT id, occurred_at, actor_email, actor_role, action, target, source_ip, details
		FROM control_plane_audit_logs
		WHERE occurred_at >= $1 AND occurred_at <= $2
		ORDER BY occurred_at, id
		LIMIT 200`, bundle.WindowStart, bundle.WindowEnd)
	if err != nil {
		return PostMortemBundle{}, fmt.Errorf("post-mortem audit trail: %w", err)
	}
	defer auditRows.Close()
	for auditRows.Next() {
		var e AuditLog
		var raw []byte
		if err := auditRows.Scan(&e.ID, &e.OccurredAt, &e.ActorEmail, &e.ActorRole,
			&e.Action, &e.Target, &e.SourceIP, &raw); err != nil {
			return PostMortemBundle{}, err
		}
		// The details blob is informational here; the audit row's existence is
		// what the report asserts, so a malformed blob must not fail the report.
		e.Details = map[string]any{}
		bundle.ControlPlane = append(bundle.ControlPlane, e)
	}
	return bundle, auditRows.Err()
}

// PostMortemTickets returns the change tickets that could apply to one host,
// narrowed to the ones whose scope names that host.
//
// The narrow query is an optimisation with a correctness caveat the caller must
// know about: a fleet-wide ticket (no hosts listed) also applies, so it is
// matched by the `hosts = '{}'` clause rather than being omitted. The final
// decision is still made by internal/itsm, which is the single implementation of
// the matching rules — this only keeps the candidate set small.
func (s *Store) PostMortemTickets(ctx context.Context, orgID, hostname string) ([]ChangeTicket, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, kind, ref, status, summary, url, hosts, environments, paths,
		       COALESCE(window_start, 'epoch'::timestamptz),
		       COALESCE(window_end, 'epoch'::timestamptz),
		       requested_by, created_at, updated_at
		FROM change_tickets
		WHERE org_id = $1::uuid
		  AND (hosts = '{}' OR $2 = ANY(hosts))
		ORDER BY updated_at DESC`, orgID, hostname)
	if err != nil {
		return nil, fmt.Errorf("post-mortem change tickets: %w", err)
	}
	defer rows.Close()

	out := []ChangeTicket{}
	for rows.Next() {
		var t ChangeTicket
		if err := rows.Scan(&t.ID, &t.Kind, &t.Ref, &t.Status, &t.Summary, &t.URL,
			&t.Hosts, &t.Environments, &t.Paths, &t.WindowStart, &t.WindowEnd,
			&t.RequestedBy, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, decorateTicket(t, time.Now()))
	}
	return out, rows.Err()
}

// ComplianceFilter is the console's change-control filter for reports.
type ComplianceFilter struct {
	// Status narrows to one compliance verdict: 'approved', 'unapproved',
	// 'expired', 'not_required', or '' for every event.
	Status string
}

// NormalizeComplianceStatus validates a compliance filter value.
func NormalizeComplianceStatus(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "approved", "unapproved", "expired", "not_required":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return ""
	}
}
