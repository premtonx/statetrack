package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// OnlineWindow is how long after its last report a host is still considered
// online. The agent heartbeats every 15s (see agent/internal/transport), so a
// host silent for longer than this has stopped reporting. The console's "Fleet
// Health" footer (web Sidebar) uses the same 15-minute window.
const OnlineWindow = 15 * time.Minute

// ReportingStatus is the online/offline vocabulary every endpoint reports.
const (
	ReportingOnline  = "online"
	ReportingOffline = "offline"
)

// ReportingStatusAt derives a host's online/offline status from its last report.
//
// This is the single source of truth for "is this agent online" across the API:
// GET /api/v1/hosts, GET /api/v1/hosts/{host}/summary and the Prometheus
// active_agents gauge all call it, so a host cannot read online in the console
// and offline to Checkmk at the same moment.
//
// The stored hosts.status column is deliberately *not* trusted on its own. An
// agent heartbeat sets it to 'online' and nothing ever writes 'offline' (a host
// that stops reporting does not get to send a farewell batch), so the column
// alone would report a decommissioned laptop as online forever. Recency is what
// actually carries the information; the column is only a veto for a host that
// was explicitly marked offline.
func ReportingStatusAt(status string, lastSeenAt, now time.Time) string {
	if !strings.EqualFold(strings.TrimSpace(status), ReportingOnline) {
		return ReportingOffline
	}
	seen := now.Sub(lastSeenAt)
	if seen < 0 {
		// Clamp clock skew rather than letting a future timestamp read as
		// "seen in -3s" and fail the recency test.
		seen = 0
	}
	if seen <= OnlineWindow {
		return ReportingOnline
	}
	return ReportingOffline
}

// ApplyReportingStatus rewrites a host's status to the recency-derived value.
func (h *Host) ApplyReportingStatus(now time.Time) {
	h.Status = ReportingStatusAt(h.Status, h.LastSeenAt, now)
}

// HostSummaryCounts is the impact-level breakdown for a host's change window.
// The four levels partition Total: every counted change carries exactly one
// level, so l1+l2+l3+l4 == total and a poller can render a stacked graph or a
// single "changed" state without a second query.
type HostSummaryCounts struct {
	Total      int64 `json:"total"`
	L1Critical int64 `json:"l1_critical"`
	L2Grouped  int64 `json:"l2_grouped"`
	L3Drift    int64 `json:"l3_drift"`
	L4Forensic int64 `json:"l4_forensic"`
}

// HostSummaryCritical describes the newest Level 1 change on a host. It is
// deliberately self-contained: it carries the fields an alert body needs
// (target, actor, tool, matched rule) so a monitoring system never has to make
// a follow-up request to render the notification.
type HostSummaryCritical struct {
	ID         string    `json:"id"`
	OccurredAt time.Time `json:"occurred_at"`
	Target     string    `json:"target"`
	Actor      string    `json:"actor,omitempty"`
	Tool       string    `json:"tool,omitempty"`
	Summary    string    `json:"summary"`
	RuleName   string    `json:"rule_name,omitempty"`
	// DeepLink is filled in by the API layer, which owns the console base URL.
	DeepLink string `json:"deep_link,omitempty"`
}

// HostSummary is the poller-facing rollup for a single host, shaped for the
// external monitoring integrations (Checkmk, Zabbix, Icinga, Datadog).
type HostSummary struct {
	Host            string            `json:"host"`
	OS              string            `json:"os"`
	Online          bool              `json:"online"`
	LastSeenSeconds int64             `json:"last_seen_seconds"`
	Window          string            `json:"window"`
	Counts          HostSummaryCounts `json:"counts"`
	// DriftTargetsCount is the number of configuration targets in the host's
	// current-state inventory (host_current_state), i.e. how many files,
	// registry keys and packages the host is actively tracking.
	DriftTargetsCount int64 `json:"drift_targets_count"`
	// LatestCritical is the newest root Level 1 change in the window, or nil
	// when the host has had none.
	LatestCritical *HostSummaryCritical `json:"latest_critical"`
}

// HostSummary aggregates one host's change activity for a monitoring poller.
//
// `key` accepts a hostname (what Checkmk/Zabbix inventory by) or a host id /
// agent host identifier (what the console deep-links by). `from` is the window
// lower bound; the caller resolves and caps the human-readable window label.
//
// Counts cover root events only, matching the console dashboard's KPIs: an
// aggregated Level 2 transaction carries hundreds of child rows, and counting
// those would inflate "total changes" far beyond what an operator sees on the
// timeline. Three indexed queries back it — no per-level round-trips:
//
//	hosts              → unique (org_id, hostname) index
//	events             → idx_events_host_time (org_id, host_id, occurred_at DESC)
//	host_current_state → primary key (host_id, target_id), prefix scan
func (s *Store) HostSummary(ctx context.Context, orgID, key string, from time.Time) (HostSummary, error) {
	// Resolve the host. Identity is deliberately NOT a single
	// `id = $2::uuid OR hostname = $3` predicate: a malformed key would make
	// the ::uuid cast raise and turn an expected 404 into a 500. Normalizing in
	// Go first keeps a bad key a clean not-found. NormalizeHostID also maps an
	// agent's original (non-UUID) host identifier onto the stored hosts.id, so
	// that identifier resolves too.
	//
	// ORDER BY prefers a hostname match so a key that is simultaneously a valid
	// hostname and a UUID resolves to the host the operator named.
	var h Host
	normID := NormalizeHostID(key)
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, org_id::text, hostname, os_family, os_version, agent_version,
		       clock_offset_ms, forensic_until, last_seen_at, status
		FROM hosts
		WHERE org_id = $1::uuid AND (hostname = $2 OR id = $3::uuid)
		ORDER BY (hostname = $2) DESC
		LIMIT 1`, orgID, key, normID).
		Scan(&h.ID, &h.OrgID, &h.Hostname, &h.OSFamily, &h.OSVersion, &h.AgentVersion,
			&h.ClockOffsetMS, &h.ForensicUntil, &h.LastSeenAt, &h.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return HostSummary{}, ErrNotFound
	}
	if err != nil {
		return HostSummary{}, fmt.Errorf("host summary lookup: %w", err)
	}

	seen := time.Since(h.LastSeenAt)
	if seen < 0 {
		// Clamp clock skew rather than reporting a negative age.
		seen = 0
	}
	summary := HostSummary{
		Host:            h.Hostname,
		OS:              h.OSFamily,
		Online:          ReportingStatusAt(h.Status, h.LastSeenAt, time.Now()) == ReportingOnline,
		LastSeenSeconds: int64(seen.Seconds()),
	}

	// Impact-level rollup. COUNT(*) FILTER is a single grouped scan of the
	// (org_id, host_id, occurred_at DESC) index covering every level at once.
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE impact_level = 1),
		       COUNT(*) FILTER (WHERE impact_level = 2),
		       COUNT(*) FILTER (WHERE impact_level = 3),
		       COUNT(*) FILTER (WHERE impact_level = 4)
		FROM events
		WHERE org_id = $1::uuid AND host_id = $2::uuid
		  AND occurred_at >= $3 AND parent_event_id IS NULL`,
		orgID, h.ID, from).
		Scan(&summary.Counts.Total, &summary.Counts.L1Critical, &summary.Counts.L2Grouped,
			&summary.Counts.L3Drift, &summary.Counts.L4Forensic); err != nil {
		return HostSummary{}, fmt.Errorf("host summary counts: %w", err)
	}

	// Tracked configuration targets (the host's current-state inventory).
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM host_current_state WHERE host_id = $1::uuid`, h.ID).
		Scan(&summary.DriftTargetsCount); err != nil {
		return HostSummary{}, fmt.Errorf("host summary drift count: %w", err)
	}

	// Newest root Level 1 change in the window, for the alert body.
	var lc HostSummaryCritical
	err = s.pool.QueryRow(ctx, `
		SELECT e.id::text, e.occurred_at, t.path_or_key,
		       COALESCE(a.username, ''), COALESCE(p.process_name, ''),
		       e.summary, COALESCE(e.metadata->>'rule_name', '')
		FROM events e
		JOIN targets t ON t.id = e.target_id
		LEFT JOIN actors a ON a.id = e.actor_id
		LEFT JOIN processes p ON p.id = e.process_id
		WHERE e.org_id = $1::uuid AND e.host_id = $2::uuid
		  AND e.impact_level = 1 AND e.occurred_at >= $3
		  AND e.parent_event_id IS NULL
		ORDER BY e.occurred_at DESC, e.id DESC
		LIMIT 1`, orgID, h.ID, from).
		Scan(&lc.ID, &lc.OccurredAt, &lc.Target, &lc.Actor, &lc.Tool, &lc.Summary, &lc.RuleName)
	switch {
	case err == nil:
		summary.LatestCritical = &lc
	case errors.Is(err, pgx.ErrNoRows):
		// No Level 1 change in the window: leave latest_critical null.
	default:
		return HostSummary{}, fmt.Errorf("host summary latest critical: %w", err)
	}

	return summary, nil
}
