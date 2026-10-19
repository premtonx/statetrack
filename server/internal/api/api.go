// Package api serves the REST + WebSocket frontend API and the Grafana
// data-source endpoints.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/statetrack/statetrack/server/internal/ai"
	"github.com/statetrack/statetrack/server/internal/mcp"
	"github.com/statetrack/statetrack/server/internal/metrics"
	"github.com/statetrack/statetrack/server/internal/storage"
)

// Server holds the API dependencies.
type Server struct {
	Store *storage.Store
	Hub   *Hub
	OrgID string
	// UIBaseURL is used for Grafana annotation deep links.
	UIBaseURL string
	// Metrics exposes the Prometheus exporter. Optional: when nil the /metrics
	// route is not registered.
	Metrics *metrics.Registry
	// HTTPClient is used for outbound integration calls (Grafana connectivity
	// test, test notifications). Optional; a 10s-timeout default is used.
	HTTPClient *http.Client
	Logger     *slog.Logger

	// Version/Commit/BuildDate describe the binary, injected at link time by the
	// release build. They are reported by GET /api/v1/system so the console shows
	// the build actually running rather than a string compiled into the bundle.
	Version    string
	Commit     string
	BuildDate  string
	EmbeddedUI bool
	// StartedAt is the process start time (unix seconds) for the uptime read.
	StartedAt int64

	// signer signs and verifies console session tokens. Lazily initialized on
	// first use from STATETRACK_SESSION_SECRET (or a per-boot random key), so a
	// Server constructed directly in a test still authenticates correctly.
	signer *sessionSigner

	// ai is the analysis gateway, built lazily on first use from HTTPClient. It
	// is stateless apart from its connection pool, so one instance serves every
	// request.
	ai *ai.Gateway

	// mcp is the Model Context Protocol server, built lazily on first use. Like
	// the gateway it is stateless, so one instance serves every client.
	mcp *mcp.Server
}

// sessionSignerFor returns the server's session signer, initializing it on first
// use. Not safe to call concurrently with itself on a zero-value Server; the
// production path initializes it during Routes() before any request is served.
func (s *Server) sessionSignerFor() *sessionSigner {
	if s.signer == nil {
		s.signer = newSessionSigner(sessionSecret(s.logger().Warn))
	}
	return s.signer
}

func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// Routes builds the HTTP handler tree.
//
// The whole tree is wrapped in withIdentity so every handler can read the
// authenticated principal from its context. Authorization is then per-route:
// reads call s.readOnly, mutations go through s.mutation which both enforces
// RBAC and writes the control-plane audit row on success. Doing it per-route
// rather than as a blanket "everything except /healthz needs a session" gate is
// what lets the Grafana data-source endpoints be reachable by a scoped API key
// (or anonymously in demo mode) while the administrative endpoints are not.
func (s *Server) Routes() http.Handler {
	s.sessionSignerFor()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	// Read-only build/runtime posture for the console's System Information card.
	mux.HandleFunc("GET /api/v1/system", s.system)
	// Prometheus scrape target. Registered only when the exporter is wired so
	// the route is absent (404) rather than a nil-pointer panic.
	if s.Metrics != nil {
		mux.Handle("GET /metrics", s.Metrics.Handler())
	}

	// ---- Authentication and identity ----
	mux.HandleFunc("GET /api/v1/auth/me", s.authMe)
	mux.HandleFunc("POST /api/v1/auth/login", s.authLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", s.authLogout)
	mux.HandleFunc("POST /api/v1/auth/switch-role", s.authSwitchRole)
	mux.HandleFunc("POST /api/v1/auth/totp/setup", s.authTOTPSetup)
	mux.HandleFunc("POST /api/v1/auth/totp/verify", s.authTOTPVerify)
	mux.HandleFunc("GET /api/v1/auth/users", s.listUsers)

	// ---- Security administration: API keys, enrollment tokens, SSO, audit ----
	mux.HandleFunc("GET /api/v1/security/sso", s.ssoGet)
	mux.HandleFunc("PUT /api/v1/security/sso",
		s.mutation(storage.ActionSSOUpdated, namedTarget("sso"), s.ssoPut))
	mux.HandleFunc("GET /api/v1/security/api-keys", s.listAPIKeys)
	mux.HandleFunc("POST /api/v1/security/api-keys",
		s.mutation(storage.ActionAPIKeyCreated, namedTarget("api key"), s.createAPIKey))
	mux.HandleFunc("DELETE /api/v1/security/api-keys/{id}",
		s.mutation(storage.ActionAPIKeyRevoked, pathTarget("id"), s.revokeAPIKey))
	mux.HandleFunc("GET /api/v1/security/enrollment-tokens", s.listEnrollmentTokens)
	mux.HandleFunc("POST /api/v1/security/enrollment-tokens",
		s.mutation(storage.ActionTokenCreated, namedTarget("enrollment token"), s.createEnrollmentToken))
	mux.HandleFunc("DELETE /api/v1/security/enrollment-tokens/{id}",
		s.mutation(storage.ActionTokenRevoked, pathTarget("id"), s.revokeEnrollmentToken))
	mux.HandleFunc("GET /api/v1/security/audit-logs", s.listAuditLogs)

	// ---- Operational reads ----
	mux.HandleFunc("GET /api/v1/hosts", s.readOnly(s.listHosts))
	// Unified poller rollup for the external monitoring suite (Checkmk, Zabbix,
	// Icinga, Datadog). Registered before the /forensic route below so the
	// `{hostname}` wildcard never swallows an id-shaped path segment.
	// Reachable with a read-scoped API key: this is the endpoint a poller calls.
	mux.HandleFunc("GET /api/v1/hosts/{hostname}/summary", s.apiRead("read:summary", s.hostSummary))
	mux.HandleFunc("GET /api/v1/events", s.readOnly(s.listEvents))
	mux.HandleFunc("GET /api/v1/events/{id}", s.readOnly(s.getEvent))
	// Incident post-mortem bundle ("War Room Export"): the 1-click document an
	// SRE hands to management after an outage. Reachable with a read-scoped API
	// key so an external runbook automation can pull the bundle too. Registered
	// with a literal suffix under the {id} wildcard, so it can never shadow the
	// plain event read.
	mux.HandleFunc("GET /api/v1/events/compliance", s.readOnly(s.eventsCompliance))
	mux.HandleFunc("GET /api/v1/events/{id}/compliance", s.readOnly(s.eventCompliance))
	mux.HandleFunc("GET /api/v1/events/{id}/post-mortem", s.apiRead("read:summary", s.postMortem))
	mux.HandleFunc("GET /api/v1/drift", s.readOnly(s.drift))
	mux.HandleFunc("GET /api/v1/recommendations", s.readOnly(s.listRecommendations))

	// ---- Mutations: RBAC-enforced and audited ----
	mux.HandleFunc("POST /api/v1/recommendations/{id}/apply",
		s.mutation(storage.ActionRuleApplied, pathTarget("id"), s.applyRecommendation))
	mux.HandleFunc("POST /api/v1/recommendations/{id}/dismiss",
		s.mutation(storage.ActionRuleDismissed, pathTarget("id"), s.dismissRecommendation))
	mux.HandleFunc("POST /api/v1/recommendations/apply-all",
		s.mutation(storage.ActionRuleApplied, namedTarget("all pending recommendations"), s.applyAllRecommendations))
	mux.HandleFunc("POST /api/v1/hosts/{id}/forensic",
		s.mutation(storage.ActionForensicSet, pathTarget("id"), s.setForensic))

	// ---- Custom watched targets (the console's rule builder) ----
	//
	// A watched target is a policy rule: the same row both classifies an event
	// and tells the surgical watchers what to track, so it is pushed to agents
	// on the next batch ack. Creation and deletion are audited through the
	// mutation wrapper; the handlers add the rule's scope and level to the
	// details so the trail answers "who widened the watch scope?".
	mux.HandleFunc("GET /api/v1/rules", s.readOnly(s.watchRules))
	mux.HandleFunc("POST /api/v1/rules",
		s.mutation(storage.ActionWatchRuleCreated, bodyTarget("pattern"), s.createWatchRule))
	mux.HandleFunc("DELETE /api/v1/rules/{id}",
		s.mutation(storage.ActionWatchRuleDeleted, pathTarget("id"), s.deleteWatchRule))

	// Grafana integration: runtime-editable settings, a connectivity test, and
	// the annotation-query endpoints the dashboard datasources call.
	mux.HandleFunc("GET /api/v1/integrations/grafana", s.readOnly(s.grafanaGet))
	mux.HandleFunc("PUT /api/v1/integrations/grafana",
		s.mutation(storage.ActionIntegrationUpd, namedTarget("grafana"), s.grafanaPut))
	mux.HandleFunc("POST /api/v1/integrations/grafana/test",
		s.mutation(storage.ActionIntegrationUpd, namedTarget("grafana"), s.grafanaTest))
	mux.HandleFunc("POST /api/v1/integrations/webhooks/test",
		s.mutation(storage.ActionIntegrationUpd, namedTarget("webhook test"), s.webhookTest))
	// Outbound notification channels (Teams, Slack, PagerDuty, generic SIEM).
	// The hub reads and writes one provider at a time so a card only ever sends
	// the fields it owns, and the delivery log is exposed separately so the
	// status table can poll without re-fetching the configuration.
	mux.HandleFunc("GET /api/v1/integrations/webhooks", s.readOnly(s.webhookIntegrationsGet))
	mux.HandleFunc("PUT /api/v1/integrations/webhooks",
		s.mutation(storage.ActionIntegrationUpd, providerTarget("webhook"), s.webhookIntegrationsPut))
	mux.HandleFunc("GET /api/v1/integrations/webhooks/deliveries", s.readOnly(s.webhookDeliveriesGet))

	// ---- Pluggable AI provider gateway ----
	//
	// The analysis endpoint is a read plus a computation, not a mutation: it
	// changes nothing in the system, and gating it behind admin:write would stop
	// an on-call engineer with a read-scoped key from asking "how do I roll this
	// back?". It is guarded like the post-mortem bundle (a read-scoped API key is
	// enough) because it is the same kind of operation. The settings and test
	// endpoints *are* mutations and go through audit logging.
	mux.HandleFunc("POST /api/v1/events/{id}/analyze", s.apiRead("read:summary", s.analyzeEvent))
	mux.HandleFunc("GET /api/v1/integrations/ai", s.readOnly(s.aiGet))
	mux.HandleFunc("PUT /api/v1/integrations/ai",
		s.mutation(storage.ActionAISettingsUpdated, namedTarget("ai"), s.aiPut))
	mux.HandleFunc("POST /api/v1/integrations/ai/test",
		s.mutation(storage.ActionAISettingsUpdated, namedTarget("ai"), s.aiTest))

	// ---- Native Model Context Protocol server ----
	//
	// A JSON-RPC 2.0 endpoint over HTTP so Cursor, Claude Desktop, Windsurf and
	// Copilot can investigate outages conversationally against the same data the
	// console shows. It is a mutation-style route in the sense that it is *not*
	// an anonymous datasource read: it is guarded by the same identity middleware
	// as everything else, and the protocol layer requires the read:mcp scope.
	//
	// No audit row is written per call. A read that changes nothing would swamp
	// the trail an auditor actually filters (who changed configuration), and the
	// credential's last-used timestamp already records that the key is in use.
	mux.HandleFunc("POST /api/v1/mcp", s.mcpEndpoint)

	// ---- ITSM change-ticket correlation bridge (Jira & ServiceNow) ----
	//
	// The configuration and ticket mirror, plus the compliance verdict view of
	// the change stream. Nothing here calls the ITSM systems: the correlation is
	// computed from the local mirror, which is what makes it correct in an
	// air-gapped deployment. A sync job (or an operator) writes tickets through
	// these endpoints.
	mux.HandleFunc("GET /api/v1/integrations/itsm", s.readOnly(s.itsmGet))
	mux.HandleFunc("PUT /api/v1/integrations/itsm",
		s.mutation(storage.ActionITSMSettingsUpd, namedTarget("itsm"), s.itsmPut))
	mux.HandleFunc("POST /api/v1/integrations/itsm/sync",
		s.mutation(storage.ActionITSMTicketSynced, namedTarget("itsm sync"), s.itsmSync))
	mux.HandleFunc("GET /api/v1/change-tickets", s.readOnly(s.listChangeTickets))
	mux.HandleFunc("POST /api/v1/change-tickets",
		s.mutation(storage.ActionITSMTicketUpserted, namedTarget("change ticket"), s.upsertChangeTicket))
	mux.HandleFunc("DELETE /api/v1/change-tickets/{ref}",
		s.mutation(storage.ActionITSMTicketDeleted, pathTarget("ref"), s.deleteChangeTicket))

	// Rendered annotation markers, from the dispatch log rather than the event
	// table, so a panel only ever shows what was actually sent.
	mux.HandleFunc("GET /api/v1/grafana/annotations", s.datasource(s.grafanaAnnotations))
	// Raw root events in Grafana's table format, for panels that want the
	// change stream rather than just the markers.
	mux.HandleFunc("GET /api/v1/grafana/events", s.datasource(s.grafanaEvents))
	if s.Hub != nil {
		mux.HandleFunc("GET /api/v1/stream", s.readOnly(s.Hub.ServeWS))
	}

	return s.withIdentity(mux)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// integrationHTTPClient is the client the outbound integration endpoints
// (connectivity tests, test notifications) use. Exposed as a method so tests
// can substitute a client pointed at an httptest server.
func (s *Server) integrationHTTPClient() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.Store.ListHosts(r.Context(), s.OrgID)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": hosts})
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := storage.EventFilter{
		HostID:      q.Get("host_id"),
		Actor:       q.Get("actor"),
		Search:      q.Get("search"),
		Cursor:      q.Get("cursor"),
		ImpactLevel: atoi(q.Get("impact_level")),
		Category:    atoi(q.Get("category")),
		Limit:       atoi(q.Get("limit")),
		From:        parseTime(q.Get("from")),
		To:          parseTime(q.Get("to")),
		// Opt-in: feeds that paginate at the root level (dashboard "latest
		// changes") pass ?root_only=1 so aggregated children cannot consume the
		// page and hide other root changes.
		RootOnly: q.Get("root_only") == "1" || q.Get("root_only") == "true",
	}
	events, next, err := s.Store.ListEvents(r.Context(), s.OrgID, f)
	if err != nil {
		writeErr(w, err)
		return
	}
	// Opt-in change-control annotation, so the timeline can badge unauthorised
	// production edits inline. It is a query parameter rather than the default
	// because the correlation costs two extra reads (settings + ticket set) per
	// page, which the dashboard feed and the Grafana data source have no use
	// for. The cost is per request, not per event: the ticket set is loaded
	// once and the per-event decision is pure computation.
	if q.Get("annotate") == "compliance" {
		views, enforced, err := s.annotateCompliance(r, events)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"events":       views,
			"next_cursor":  next,
			"annotated":    "compliance",
			"enforced":     enforced,
			"annotated_at": time.Now().UTC(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "next_cursor": next})
}

func (s *Server) getEvent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ev, err := s.Store.GetEvent(r.Context(), s.OrgID, id)
	if errors.Is(err, storage.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "event not found", "id": id})
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

func (s *Server) drift(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hostA, hostB := q.Get("host_a"), q.Get("host_b")
	if hostA == "" || hostB == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host_a and host_b are required"})
		return
	}
	rows, err := s.Store.Drift(r.Context(), s.OrgID, hostA, hostB)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"drift": rows})
}

// listRecommendations returns discovered workloads, newest first. Query
// parameters: host_id (optional), status (optional; defaults to "pending").
func (s *Server) listRecommendations(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := q.Get("status")
	if status == "" {
		status = storage.RecStatusPending
	}
	if status == "all" {
		status = ""
	}
	recs, err := s.Store.ListRecommendations(r.Context(), s.OrgID, status, q.Get("host_id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	if recs == nil {
		recs = []storage.Recommendation{}
	}
	byHost := map[string]int{}
	for _, rec := range recs {
		byHost[rec.Hostname]++
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"recommendations": recs,
		"pending":         len(recs),
		"by_host":         byHost,
	})
}

// applyRecommendation approves one recommendation, generating its policy rule.
func (s *Server) applyRecommendation(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rule, err := s.Store.ApplyRecommendation(r.Context(), s.OrgID, id)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "applied", "rule": rule})
}

func (s *Server) dismissRecommendation(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Store.DismissRecommendation(r.Context(), s.OrgID, id); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "dismissed"})
}

// applyAllRecommendations approves every pending recommendation in one click,
// optionally scoped to a single host via ?host_id=.
func (s *Server) applyAllRecommendations(w http.ResponseWriter, r *http.Request) {
	hostID := r.URL.Query().Get("host_id")
	rules, err := s.Store.ApplyAllRecommendations(r.Context(), s.OrgID, hostID)
	if err != nil {
		writeErr(w, err)
		return
	}
	if rules == nil {
		rules = []storage.PolicyRuleRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "applied", "applied": len(rules), "rules": rules})
}

func (s *Server) setForensic(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d := 15 * time.Minute
	if v := r.URL.Query().Get("minutes"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			d = time.Duration(n) * time.Minute
		}
	}
	if err := s.Store.SetForensicUntil(r.Context(), s.OrgID, id, d); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host_id":           id,
		"forensic_until_ms": time.Now().Add(d).UnixMilli(),
	})
}

func (s *Server) grafanaEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	events, _, err := s.Store.ListEvents(r.Context(), s.OrgID, storage.EventFilter{
		HostID: q.Get("host"),
		From:   parseTime(q.Get("from")),
		To:     parseTime(q.Get("to")),
		Limit:  clamp(atoi(q.Get("limit")), 500),
		// Root events only (children are rendered inside their parent's card),
		// filtered in SQL so they cannot consume the limit.
		RootOnly: true,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	slog.Default().Warn("api error", "err", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func clamp(n, max int) int {
	if n <= 0 {
		return max
	}
	if n > max {
		return max
	}
	return n
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
