package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestLabelNormalizationIsClosed(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"level 1", NormalizeLevel(1), "L1"},
		{"level 4", NormalizeLevel(4), "L4"},
		{"level 0", NormalizeLevel(0), "unknown"},
		{"level bogus", NormalizeLevel(99), "unknown"},
		{"level negative", NormalizeLevel(-3), "unknown"},

		{"category config", NormalizeCategory(1), "config"},
		{"category network", NormalizeCategory(6), "network"},
		{"category bogus", NormalizeCategory(42), "unknown"},

		{"action throttled", NormalizeAction(8), "throttled"},
		{"action bogus", NormalizeAction(200), "unknown"},

		{"os windows", NormalizeOS("Windows"), "windows"},
		{"os linux", NormalizeOS("linux"), "linux"},
		{"os macos", NormalizeOS("macOS"), "darwin"},
		{"os bogus", NormalizeOS("plan9"), "unknown"},

		{"status online", NormalizeAgentStatus(" Online "), "online"},
		{"status stale", NormalizeAgentStatus("stale"), "offline"},

		{"provider slack", NormalizeProvider("Slack"), "slack"},
		{"provider pd", NormalizeProvider("pagerduty"), "pagerduty"},
		{"provider ms teams", NormalizeProvider("msteams"), "teams"},
		{"provider bogus", NormalizeProvider("acme-custom"), "unknown"},

		{"status 204", NormalizeDeliveryStatus(204, false), "success"},
		{"status 404", NormalizeDeliveryStatus(404, false), "client_error"},
		{"status 503", NormalizeDeliveryStatus(503, false), "server_error"},
		{"status transport error", NormalizeDeliveryStatus(200, true), "error"},
		{"status none", NormalizeDeliveryStatus(0, false), "unknown"},

		{"host empty", NormalizeHost("  "), "unknown"},
		{"host trimmed", NormalizeHost(" prod-web-01 "), "prod-web-01"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("got %q, want %q", tc.got, tc.want)
			}
		})
	}
}

// TestCardinalityIsBounded feeds the recorder a large volume of hostile input
// and asserts the number of time series stops growing. This is the regression
// test for the package's central invariant: no per-event value may reach a
// label without passing through a Normalize* helper.
func TestCardinalityIsBounded(t *testing.T) {
	r := New()

	// 5,000 distinct (level, category, action) combinations, all invalid.
	for i := 0; i < 5000; i++ {
		r.RecordMutation("prod-web-01", int32(1000+i), int32(2000+i), int32(3000+i))
	}

	if got := testutil.CollectAndCount(r.MutationsTotal); got != 1 {
		t.Fatalf("mutations_total series = %d, want 1 (invalid labels must collapse)", got)
	}

	// Unknown host values must not mint series either — but valid hostnames
	// legitimately do, so assert the bound is the fleet size plus the two
	// pre-existing buckets.
	before := testutil.CollectAndCount(r.MutationsTotal)
	for i := 0; i < 5000; i++ {
		if i%2 == 0 {
			r.RecordMutation("", 1, 1, 2) // blank hostname
		} else {
			r.RecordMutation("prod-web-01", 1, 1, 2)
		}
	}
	if got := testutil.CollectAndCount(r.MutationsTotal); got != before+2 {
		t.Fatalf("mutations_total series grew from %d to %d, want exactly one new series per host dimension",
			before, got)
	}
	if got := testutil.CollectAndCount(r.MutationsTotal); got != 3 {
		t.Fatalf("mutations_total series = %d, want 3", got)
	}
}

// TestPathActorAndPIDDoNotReachLabels is a tripwire on the metric definitions:
// if someone adds a path/actor/pid label the exposition grows without bound,
// and this test fails loudly.
func TestPathActorAndPIDDoNotReachLabels(t *testing.T) {
	r := New()
	// Simulate the worst case: an attacker-controlled path as a hostname.
	for i := 0; i < 100; i++ {
		r.SetDriftTargets("/etc/nginx/conf.d/site-"+strings.Repeat("x", i%8)+".conf", i)
	}
	// Only the 8 distinct hostname strings above are legal host dimensions;
	// the point is that the *value* is used, not interpolated into labels.
	if got := testutil.CollectAndCount(r.DriftTargets); got != 8 {
		t.Fatalf("drift_targets series = %d, want 8", got)
	}

	names := metricNames(t, r)
	for _, forbidden := range []string{"path", "actor", "pid", "event_id", "summary", "rule_name"} {
		for _, name := range names {
			if strings.Contains(name, forbidden) {
				t.Fatalf("metric %q leaks a per-event label fragment %q", name, forbidden)
			}
		}
	}
}

func TestPopulateSeedsGaugesAndCounters(t *testing.T) {
	r := New()
	r.Populate(Snapshot{
		Hosts: []HostState{
			{Hostname: "prod-web-01", OS: "linux", Status: "online", DriftTargets: 42},
			{Hostname: "prod-db-01", OS: "linux", Status: "offline", DriftTargets: 7},
			{Hostname: "win-iis-01", OS: "windows", Status: "online", DriftTargets: 3},
			{Hostname: "exotic-01", OS: "plan9", Status: "weird", DriftTargets: 1},
		},
		Mutations: []MutationCount{
			{Hostname: "prod-web-01", Level: 1, Category: 1, Action: 2, Count: 5},
			{Hostname: "prod-web-01", Level: 3, Category: 1, Action: 2, Count: 12},
			{Hostname: "prod-db-01", Level: 99, Category: 99, Action: 99, Count: 3}, // invalid → unknown
		},
		StormThrottles: []HostCount{{Hostname: "prod-web-01", Count: 4}},
		EventsReceived: 1000,
	})

	// Per-host drift gauge.
	if got := testutil.ToFloat64(r.DriftTargets.WithLabelValues("prod-web-01")); got != 42 {
		t.Fatalf("drift_targets{prod-web-01} = %v, want 42", got)
	}

	// Per-host agent gauge: one series per host, so it filters by $host.
	if got := testutil.ToFloat64(r.ActiveAgents.WithLabelValues("prod-web-01", "linux", "online")); got != 1 {
		t.Fatalf("active_agents{prod-web-01,linux,online} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(r.ActiveAgents.WithLabelValues("prod-db-01", "linux", "offline")); got != 1 {
		t.Fatalf("active_agents{prod-db-01,linux,offline} = %v, want 1", got)
	}
	// An unrecognized OS and status still collapse into the bounded vocabulary
	// rather than minting a new series per value.
	if got := testutil.ToFloat64(r.ActiveAgents.WithLabelValues("exotic-01", "unknown", "offline")); got != 1 {
		t.Fatalf("active_agents{exotic-01,unknown,offline} = %v, want 1", got)
	}
	// One series per host: the per-os rollup the alerting rule uses is a sum by.
	if got := testutil.CollectAndCount(r.ActiveAgents); got != 4 {
		t.Fatalf("active_agents series = %d, want 4 (one per host)", got)
	}

	// Counters seeded from the aggregate.
	if got := testutil.ToFloat64(r.MutationsTotal.WithLabelValues("prod-web-01", "L1", "config", "modified")); got != 5 {
		t.Fatalf("mutations_total{prod-web-01,L1} = %v, want 5", got)
	}
	if got := testutil.ToFloat64(r.MutationsTotal.WithLabelValues("prod-db-01", "unknown", "unknown", "unknown")); got != 3 {
		t.Fatalf("invalid mutation did not collapse into unknown: %v", got)
	}
	if got := testutil.ToFloat64(r.StormThrottlesTotal.WithLabelValues("prod-web-01")); got != 4 {
		t.Fatalf("storm_throttles_total{prod-web-01} = %v, want 4", got)
	}
	if got := testutil.ToFloat64(r.IngestEventsReceived); got != 1000 {
		t.Fatalf("ingest_events_received_total = %v, want 1000", got)
	}
}

// TestPopulateRepeatedIsIdempotentForGauges guards the startup path against a
// retry turning drift counts into nonsense.
func TestPopulateRepeatedIsIdempotentForGauges(t *testing.T) {
	r := New()
	snap := Snapshot{Hosts: []HostState{
		{Hostname: "prod-web-01", OS: "linux", Status: "online", DriftTargets: 42},
		{Hostname: "retired-01", OS: "linux", Status: "online", DriftTargets: 9},
	}}
	r.Populate(snap)
	// Second run omits retired-01 (it was decommissioned).
	r.Populate(Snapshot{Hosts: []HostState{
		{Hostname: "prod-web-01", OS: "linux", Status: "online", DriftTargets: 42},
	}})

	if got := testutil.ToFloat64(r.DriftTargets.WithLabelValues("prod-web-01")); got != 42 {
		t.Fatalf("drift_targets{prod-web-01} = %v, want 42 (not doubled)", got)
	}
	if got := testutil.CollectAndCount(r.DriftTargets); got != 1 {
		t.Fatalf("drift_targets series = %d, want 1 (retired host must be dropped)", got)
	}
	if got := testutil.ToFloat64(r.ActiveAgents.WithLabelValues("prod-web-01", "linux", "online")); got != 1 {
		t.Fatalf("active_agents{prod-web-01,linux,online} = %v, want 1 (not doubled)", got)
	}
}

func TestExpositionContainsEveryMetric(t *testing.T) {
	r := New()
	// Touch one label combination of each vec: Prometheus omits a vec that has
	// no series yet, and an empty scrape would not prove the metric is wired.
	r.RecordMutation("prod-web-01", 1, 1, 2)
	r.SetDriftTargets("prod-web-01", 1)
	r.ActiveAgents.WithLabelValues("prod-web-01", "linux", "online").Set(1)
	r.RecordStormThrottle("prod-web-01", 1)
	r.RecordBatchIngest(0.01, 1)
	r.RecordWebhookDelivery("slack", 200, false)

	rr := httptest.NewRecorder()
	r.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))

	body := rr.Body.String()
	for _, want := range []string{
		"statetrack_mutations_total",
		"statetrack_drift_targets",
		"statetrack_active_agents",
		"statetrack_storm_throttles_total",
		"statetrack_ingest_batch_duration_seconds_bucket",
		"statetrack_ingest_batch_duration_seconds_sum",
		"statetrack_ingest_batch_duration_seconds_count",
		"statetrack_ingest_events_received_total",
		"statetrack_webhook_deliveries_total",
		"go_goroutines",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/metrics missing %q", want)
		}
	}
	// The exposition must carry the label set the alerting rules depend on.
	for _, want := range []string{
		`statetrack_mutations_total{action="modified",category="config",host="prod-web-01",level="L1"}`,
		`statetrack_active_agents{host="prod-web-01",os="linux",status="online"}`,
		`statetrack_webhook_deliveries_total{provider="slack",status="success"}`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/metrics missing series %q", want)
		}
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content type = %q, want text/plain exposition", ct)
	}
}

func TestRecordBatchIngestObservesHistogram(t *testing.T) {
	r := New()
	r.RecordBatchIngest(0.012, 3)
	r.RecordBatchIngest(0.5, 7)

	if got := testutil.CollectAndCount(r.IngestBatchDuration); got != 1 {
		t.Fatalf("histogram series = %d, want 1", got)
	}
	if got := testutil.ToFloat64(r.IngestEventsReceived); got != 10 {
		t.Fatalf("events received = %v, want 10", got)
	}
}

func TestRecordWebhookDeliveryBuckets(t *testing.T) {
	r := New()
	r.RecordWebhookDelivery("slack", 200, false)
	r.RecordWebhookDelivery("slack", 200, false)
	r.RecordWebhookDelivery("slack", 502, false)
	r.RecordWebhookDelivery("pagerduty", 0, true)

	if got := testutil.ToFloat64(r.WebhookDeliveriesTotal.WithLabelValues("slack", "success")); got != 2 {
		t.Fatalf("slack success = %v, want 2", got)
	}
	if got := testutil.ToFloat64(r.WebhookDeliveriesTotal.WithLabelValues("slack", "server_error")); got != 1 {
		t.Fatalf("slack server_error = %v, want 1", got)
	}
	if got := testutil.ToFloat64(r.WebhookDeliveriesTotal.WithLabelValues("pagerduty", "error")); got != 1 {
		t.Fatalf("pagerduty error = %v, want 1", got)
	}
}

// TestPreseedZeroSeriesExposesBaseline pins the flag that the hub and the
// alerting rules depend on: immediately after startup, before any change has
// been ingested, /metrics must already carry a 0-valued series for every
// storm-throttle host and every (provider, status) delivery pair. Otherwise a
// "no data" scrape is indistinguishable from a broken exporter.
func TestPreseedZeroSeriesExposesBaseline(t *testing.T) {
	r := New()
	r.PreseedZeroSeries(Snapshot{
		Hosts: []HostState{
			{Hostname: "prod-web-01", OS: "linux", Status: "online"},
			{Hostname: "win-app-02", OS: "windows", Status: "online"},
		},
	})

	rr := httptest.NewRecorder()
	r.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()

	// One zero series per known host.
	for _, host := range []string{"prod-web-01", "win-app-02"} {
		want := `statetrack_storm_throttles_total{host="` + host + `"} 0`
		if !strings.Contains(body, want) {
			t.Fatalf("/metrics missing zero baseline %q\n%s", want, body)
		}
	}

	// One zero series per (provider, status) pair.
	for _, provider := range KnownProviders {
		for _, status := range KnownDeliveryStatuses {
			want := `statetrack_webhook_deliveries_total{provider="` + provider + `",status="` + status + `"} 0`
			if !strings.Contains(body, want) {
				t.Fatalf("/metrics missing zero baseline %q", want)
			}
		}
	}

	// The baseline must not fabricate a host that is not enrolled.
	if got := testutil.CollectAndCount(r.StormThrottlesTotal); got != 2 {
		t.Fatalf("storm_throttles_total series = %d, want 2", got)
	}
}

// TestPreseedDoesNotClobberRecordedCounts guards the ordering inside Populate:
// the seeded tallies must survive the zero baseline being applied afterwards.
func TestPreseedDoesNotClobberRecordedCounts(t *testing.T) {
	r := New()
	r.Populate(Snapshot{
		Hosts:          []HostState{{Hostname: "prod-web-01", OS: "linux", Status: "online"}},
		StormThrottles: []HostCount{{Hostname: "prod-web-01", Count: 4}},
	})
	if got := testutil.ToFloat64(r.StormThrottlesTotal.WithLabelValues("prod-web-01")); got != 4 {
		t.Fatalf("storm_throttles_total{prod-web-01} = %v, want 4 (baseline must not reset it)", got)
	}
}

// metricNames collects the fully-qualified names of everything exported.
func metricNames(t *testing.T, r *Registry) []string {
	t.Helper()
	families, err := r.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	names := make([]string, 0, len(families))
	for _, f := range families {
		names = append(names, f.GetName())
	}
	return names
}
