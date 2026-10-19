package storage

import (
	"context"
	"fmt"
	"time"
)

// MetricsSnapshot is the fleet state used to pre-populate the Prometheus
// gauges and counters at server startup.
type MetricsSnapshot struct {
	Hosts          []MetricsHost
	Mutations      []MetricsMutation
	StormThrottles []MetricsHostCount
	EventsReceived int64
}

// MetricsHost is one enrolled host's fleet-level dimensions.
type MetricsHost struct {
	Hostname     string
	OS           string
	Status       string
	DriftTargets int64
}

// MetricsMutation is a pre-aggregated (host, level, category, action) tally of
// root events. Aggregating in SQL rather than streaming rows keeps startup
// memory proportional to the number of distinct combinations (bounded) instead
// of the number of events (unbounded).
type MetricsMutation struct {
	Hostname string
	Level    int32
	Category int32
	Action   int32
	Count    int64
}

// MetricsHostCount is a per-host tally, used for storm throttles.
type MetricsHostCount struct {
	Hostname string
	Count    int64
}

// MetricsSnapshot reads the state needed to seed the Prometheus exporter.
//
// It issues four independent aggregate queries. They are intentionally not
// wrapped in a transaction: a snapshot taken a few milliseconds apart is
// perfectly adequate for gauge seeding, and taking a consistent snapshot would
// mean holding a transaction open across the whole events table.
func (s *Store) MetricsSnapshot(ctx context.Context, orgID string) (MetricsSnapshot, error) {
	var snap MetricsSnapshot

	// Agents and their tracked-target counts. LEFT JOIN so a host with no
	// current state still reports zero rather than vanishing from the gauge.
	// last_seen_at comes back too so the agent status can be derived with the
	// same recency rule the API and the console use (ReportingStatusAt).
	rows, err := s.pool.Query(ctx, `
		SELECT h.hostname, h.os_family, h.status, h.last_seen_at,
		       COUNT(s.target_id) FILTER (WHERE s.host_id IS NOT NULL)
		FROM hosts h
		LEFT JOIN host_current_state s ON s.host_id = h.id
		WHERE h.org_id = $1::uuid
		GROUP BY h.id, h.hostname, h.os_family, h.status, h.last_seen_at
		ORDER BY h.hostname`, orgID)
	if err != nil {
		return snap, fmt.Errorf("metrics snapshot hosts: %w", err)
	}
	defer rows.Close()
	now := time.Now()
	for rows.Next() {
		var h MetricsHost
		var lastSeen time.Time
		if err := rows.Scan(&h.Hostname, &h.OS, &h.Status, &lastSeen, &h.DriftTargets); err != nil {
			return snap, err
		}
		h.Status = ReportingStatusAt(h.Status, lastSeen, now)
		snap.Hosts = append(snap.Hosts, h)
	}
	if err := rows.Err(); err != nil {
		return snap, err
	}

	// Root-event tallies by classification. Children are excluded to match
	// the mutation counter's semantics on the live path.
	mrows, err := s.pool.Query(ctx, `
		SELECT h.hostname, e.impact_level, e.category, e.action, COUNT(*)
		FROM events e
		JOIN hosts h ON h.id = e.host_id
		WHERE e.org_id = $1::uuid AND e.parent_event_id IS NULL
		GROUP BY h.hostname, e.impact_level, e.category, e.action`, orgID)
	if err != nil {
		return snap, fmt.Errorf("metrics snapshot mutations: %w", err)
	}
	defer mrows.Close()
	for mrows.Next() {
		var m MetricsMutation
		if err := mrows.Scan(&m.Hostname, &m.Level, &m.Category, &m.Action, &m.Count); err != nil {
			return snap, err
		}
		snap.Mutations = append(snap.Mutations, m)
	}
	if err := mrows.Err(); err != nil {
		return snap, err
	}

	// Circuit-breaker activations. An agent reports a storm as a single event
	// with action=THROTTLED (8) and metadata m/count in the summary; the count
	// of such events per host is the throttle tally.
	srows, err := s.pool.Query(ctx, `
		SELECT h.hostname, COUNT(*)
		FROM events e
		JOIN hosts h ON h.id = e.host_id
		WHERE e.org_id = $1::uuid AND e.action = 8
		GROUP BY h.hostname`, orgID)
	if err != nil {
		return snap, fmt.Errorf("metrics snapshot storm throttles: %w", err)
	}
	defer srows.Close()
	for srows.Next() {
		var c MetricsHostCount
		if err := srows.Scan(&c.Hostname, &c.Count); err != nil {
			return snap, err
		}
		snap.StormThrottles = append(snap.StormThrottles, c)
	}
	if err := srows.Err(); err != nil {
		return snap, err
	}

	// Lifetime ingester throughput (children included, matching the live path).
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM events WHERE org_id = $1::uuid`, orgID).
		Scan(&snap.EventsReceived); err != nil {
		return snap, fmt.Errorf("metrics snapshot events received: %w", err)
	}

	return snap, nil
}

// HostTargetCount returns how many configuration targets the host's
// current-state inventory tracks. Used to refresh the Prometheus drift gauge
// after an ingest batch.
func (s *Store) HostTargetCount(ctx context.Context, hostID string) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM host_current_state WHERE host_id = $1::uuid`, hostID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}
