// Package metrics exposes StateTrack's Prometheus instrumentation.
//
// # Cardinality policy
//
// Every label in this package is either a **closed enumeration** (impact
// level, category, action, delivery outcome, OS family, agent status) or a
// bounded fleet dimension (the hostname, already bounded by the enrolled
// fleet). No label may carry a per-event value — a file path, actor name, PID,
// command line, rule name, event id, remote IP or search term would let a busy
// or hostile environment create one time series per event and melt the scrape
// target.
//
// Values that arrive from the wire are therefore never used as labels
// verbatim. They pass through the Normalize* helpers in this file, which map
// each input onto a fixed vocabulary and fold anything unrecognized into a
// single "unknown" bucket. That single rule is what keeps the exposition safe:
// an agent submitting a bogus impact level adds to the existing "unknown"
// series rather than minting a new one.
package metrics

import (
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Namespace prefixes every metric this package exports.
const Namespace = "statetrack"

// UnknownLabel is the bucket every unrecognized label value collapses into.
// Exported so tests (and alerting rules) can reference the exact spelling.
const UnknownLabel = "unknown"

// Registry owns the StateTrack metrics and their underlying Prometheus
// registry. It is safe for concurrent use.
type Registry struct {
	reg *prometheus.Registry

	// Fleet mutation metrics.
	MutationsTotal      *prometheus.CounterVec
	DriftTargets        *prometheus.GaugeVec
	ActiveAgents        *prometheus.GaugeVec
	StormThrottlesTotal *prometheus.CounterVec

	// Server operational SLIs.
	IngestBatchDuration    prometheus.Histogram
	IngestEventsReceived   prometheus.Counter
	WebhookDeliveriesTotal *prometheus.CounterVec
}

// Snapshot is the Postgres-derived state used to pre-populate the metrics at
// startup, so /metrics reflects seeded and already-ingested data immediately
// rather than staying empty until the next gRPC batch lands.
type Snapshot struct {
	Hosts          []HostState
	Mutations      []MutationCount
	StormThrottles []HostCount
	// EventsReceived is the lifetime count of stored events (including
	// grouped children), used to seed ingest_events_received_total.
	EventsReceived int64
}

// KnownProviders is the closed set of notification providers the exporter
// reports. Kept in sync with the integrations dispatcher's provider constants;
// an unrecognized provider folds into "unknown" (see NormalizeProvider).
var KnownProviders = []string{"slack", "teams", "pagerduty", "webhook"}

// KnownDeliveryStatuses is the closed set of delivery outcomes. Only the two
// states an operator pages on are pre-seeded ("did it get there or not"); the
// client_error/server_error split is populated on first observation.
var KnownDeliveryStatuses = []string{"success", "error"}

// PreseedZeroSeries creates a 0-valued sample for every counter dimension that
// is knowable up front.
//
// Without this, GET /metrics omits statetrack_storm_throttles_total and
// statetrack_webhook_deliveries_total entirely until the first matching event
// arrives: Prometheus only renders a CounterVec that has at least one series.
// An alertmanager rule or Grafana panel querying them would then see "no data"
// rather than "zero", which reads as a broken exporter rather than a healthy
// fleet. Seeding the baseline makes "0" the answer from the first scrape.
//
// The dimensions are bounded by construction: hosts come from the enrolled
// fleet, providers from KnownProviders, statuses from KnownDeliveryStatuses.
// This cannot introduce an unbounded label (see the package doc's cardinality
// policy).
func (r *Registry) PreseedZeroSeries(snap Snapshot) {
	for _, h := range snap.Hosts {
		// A storm counter per enrolled host. CollectAndCount counts it as a
		// real series, so it also has to exist for a host that never storms.
		r.StormThrottlesTotal.WithLabelValues(NormalizeHost(h.Hostname)).Add(0)
	}
	for _, provider := range KnownProviders {
		for _, status := range KnownDeliveryStatuses {
			r.WebhookDeliveriesTotal.WithLabelValues(
				NormalizeProvider(provider), status,
			).Add(0)
		}
	}
	// The ingest counter is a plain Counter, not a Vec: it is always rendered
	// (as 0) as soon as the collector is registered, so it needs no seeding.
}

// HostState is one enrolled host's fleet-level dimensions.
type HostState struct {
	Hostname     string
	OS           string
	Status       string
	DriftTargets int64
}

// MutationCount is a pre-aggregated (host, level, category, action) tally.
type MutationCount struct {
	Hostname                string
	Level, Category, Action int32
	Count                   int64
}

// HostCount is a per-host tally, used for storm throttles.
type HostCount struct {
	Hostname string
	Count    int64
}

// New builds the registry with every StateTrack metric registered, alongside
// the standard Go runtime and process collectors.
func New() *Registry {
	reg := prometheus.NewRegistry()
	r := &Registry{
		reg: reg,
		MutationsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "mutations_total",
			Help: "Root mutations ingested, by host and impact classification. " +
				"Grouped child events are subsumed by their parent and not counted separately.",
		}, []string{"host", "level", "category", "action"}),
		DriftTargets: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "drift_targets",
			Help:      "Configuration targets currently tracked in the host's state inventory.",
		}, []string{"host"}),
		ActiveAgents: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "active_agents",
			Help: "Enrolled agents by host, operating system and reporting status. " +
				"Carries the hostname as well as the os/status pair so a dashboard can " +
				"filter it by the same $host variable as every other fleet metric; " +
				"per-os rollups remain a sum by (os) away.",
		}, []string{"host", "os", "status"}),
		StormThrottlesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "storm_throttles_total",
			Help:      "Change-storm circuit-breaker activations reported by agents, by host.",
		}, []string{"host"}),
		IngestBatchDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      "ingest_batch_duration_seconds",
			Help:      "Server time to durably store one agent ingest batch.",
			// Tuned for this workload: a batch is a handful of upserts in one
			// transaction, so the interesting range is milliseconds, with
			// headroom to observe a slow-disk tail.
			Buckets: []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}),
		IngestEventsReceived: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "ingest_events_received_total",
			Help:      "Mutation events received from agents, including grouped children.",
		}),
		WebhookDeliveriesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "webhook_deliveries_total",
			Help:      "Outbound notification deliveries by provider and outcome.",
		}, []string{"provider", "status"}),
	}

	reg.MustRegister(
		r.MutationsTotal,
		r.DriftTargets,
		r.ActiveAgents,
		r.StormThrottlesTotal,
		r.IngestBatchDuration,
		r.IngestEventsReceived,
		r.WebhookDeliveriesTotal,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return r
}

// Handler serves the Prometheus text exposition format for /metrics.
func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

// Gatherer exposes the registry for tests and custom exposition.
func (r *Registry) Gatherer() prometheus.Gatherer { return r.reg }

// RecordMutation increments the mutation counter for one root event. Children
// are deliberately not counted: an aggregated Level 2 transaction carries
// hundreds of child rows, and counting them would report a single package
// upgrade as hundreds of mutations.
func (r *Registry) RecordMutation(host string, level, category, action int32) {
	r.MutationsTotal.WithLabelValues(
		NormalizeHost(host),
		NormalizeLevel(level),
		NormalizeCategory(category),
		NormalizeAction(action),
	).Inc()
}

// RecordEventsReceived adds to the ingester throughput counter.
func (r *Registry) RecordEventsReceived(n int) {
	if n <= 0 {
		return
	}
	r.IngestEventsReceived.Add(float64(n))
}

// RecordBatchIngest observes one batch's storage latency and throughput.
func (r *Registry) RecordBatchIngest(seconds float64, events int) {
	r.IngestBatchDuration.Observe(seconds)
	r.RecordEventsReceived(events)
}

// RecordStormThrottle counts a circuit-breaker activation on a host.
func (r *Registry) RecordStormThrottle(host string, n int) {
	if n <= 0 {
		return
	}
	r.StormThrottlesTotal.WithLabelValues(NormalizeHost(host)).Add(float64(n))
}

// RecordWebhookDelivery counts one outbound delivery attempt. `code` is the
// HTTP status, or 0 when the request never completed; `failed` is true when the
// transport itself errored, which takes precedence over the status code.
func (r *Registry) RecordWebhookDelivery(provider string, code int, failed bool) {
	r.WebhookDeliveriesTotal.WithLabelValues(
		NormalizeProvider(provider),
		NormalizeDeliveryStatus(code, failed),
	).Inc()
}

// SetDriftTargets sets the tracked-target gauge for one host.
func (r *Registry) SetDriftTargets(host string, n int) {
	r.DriftTargets.WithLabelValues(NormalizeHost(host)).Set(float64(n))
}

// Populate seeds the metrics from the current database state.
//
// Intended to be called exactly once during startup: gauges are replaced
// wholesale (so a repeated call cannot strand a stale series), but counters are
// monotonic and can only be added to, so calling this twice would double-count.
func (r *Registry) Populate(snap Snapshot) {
	// Replace, don't accumulate: a removed host or an agent that migrated OS
	// must not leave a phantom series behind.
	r.DriftTargets.Reset()
	r.ActiveAgents.Reset()

	for _, h := range snap.Hosts {
		r.SetDriftTargets(h.Hostname, int(h.DriftTargets))
		// One series per host: the hostname keeps this filterable by the same
		// $host variable as the rest of the dashboard, while os/status stay
		// available for a fleet-wide sum by (os).
		r.ActiveAgents.WithLabelValues(
			NormalizeHost(h.Hostname),
			NormalizeOS(h.OS),
			NormalizeAgentStatus(h.Status),
		).Set(1)
	}
	for _, m := range snap.Mutations {
		r.MutationsTotal.WithLabelValues(
			NormalizeHost(m.Hostname),
			NormalizeLevel(m.Level),
			NormalizeCategory(m.Category),
			NormalizeAction(m.Action),
		).Add(float64(m.Count))
	}
	for _, s := range snap.StormThrottles {
		r.RecordStormThrottle(s.Hostname, int(s.Count))
	}
	if snap.EventsReceived > 0 {
		r.IngestEventsReceived.Add(float64(snap.EventsReceived))
	}
	// After the real tallies, so a seeded count is never reset to zero.
	r.PreseedZeroSeries(snap)
}

/* -------------------------------------------------------------------------- */
/* Label normalization (the cardinality guard)                                */
/* -------------------------------------------------------------------------- */

// NormalizeHost bounds the host label. Hostnames are already bounded by the
// enrolled fleet; an empty value would otherwise produce a series with an
// empty label, which is legal but useless in a query.
func NormalizeHost(host string) string {
	if h := strings.TrimSpace(host); h != "" {
		return h
	}
	return UnknownLabel
}

// NormalizeLevel maps an impact level onto L1–L4. Anything else (including an
// agent sending a level outside the spec) collapses into one "unknown" series.
func NormalizeLevel(level int32) string {
	switch level {
	case 1:
		return "L1"
	case 2:
		return "L2"
	case 3:
		return "L3"
	case 4:
		return "L4"
	default:
		return UnknownLabel
	}
}

// NormalizeCategory maps a category id onto its fixed name.
func NormalizeCategory(category int32) string {
	switch category {
	case 1:
		return "config"
	case 2:
		return "package"
	case 3:
		return "service"
	case 4:
		return "user"
	case 5:
		return "registry"
	case 6:
		return "network"
	case 7:
		return "process"
	case 8:
		return "agent_health"
	default:
		return UnknownLabel
	}
}

// NormalizeAction maps an action id onto its fixed name.
func NormalizeAction(action int32) string {
	switch action {
	case 1:
		return "created"
	case 2:
		return "modified"
	case 3:
		return "deleted"
	case 4:
		return "restarted"
	case 5:
		return "started"
	case 6:
		return "stopped"
	case 7:
		return "upgraded"
	case 8:
		return "throttled"
	default:
		return UnknownLabel
	}
}

// NormalizeOS bounds the operating-system label to the platforms the agent
// supports.
func NormalizeOS(os string) string {
	switch strings.ToLower(strings.TrimSpace(os)) {
	case "linux":
		return "linux"
	case "windows":
		return "windows"
	case "darwin", "macos":
		return "darwin"
	default:
		return UnknownLabel
	}
}

// NormalizeAgentStatus bounds the agent status label.
func NormalizeAgentStatus(status string) string {
	if strings.EqualFold(strings.TrimSpace(status), "online") {
		return "online"
	}
	return "offline"
}

// NormalizeProvider bounds the integration provider label. Providers are
// configured rows, so an operator could otherwise introduce an arbitrary label
// value by naming a provider; only the shipped providers are reported by name.
func NormalizeProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "grafana", "grafana_annotations":
		return "grafana_annotations"
	case "slack":
		return "slack"
	case "pagerduty":
		return "pagerduty"
	case "teams", "msteams", "microsoft_teams":
		return "teams"
	case "webhook", "siem":
		return "webhook"
	default:
		return UnknownLabel
	}
}

// NormalizeDeliveryStatus folds a delivery outcome into a closed set. The raw
// HTTP status is deliberately not used: a misbehaving endpoint could return an
// endless variety of codes, and "was it a success, a client error, a server
// error, or a transport failure" is what an operator alerts on anyway.
func NormalizeDeliveryStatus(code int, failed bool) string {
	if failed {
		return "error"
	}
	switch {
	case code >= 200 && code < 300:
		return "success"
	case code >= 400 && code < 500:
		return "client_error"
	case code >= 500 && code < 600:
		return "server_error"
	default:
		return UnknownLabel
	}
}
