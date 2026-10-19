package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/statetrack/statetrack/server/internal/storage"
)

// grafanaHealthPath is the endpoint used for the connectivity test. Grafana
// exposes /api/health unauthenticated, which is exactly what a pre-flight check
// wants: it proves the URL is a Grafana instance and that the network path
// works, separately from whether the token is valid.
const grafanaHealthPath = "/api/health"

// grafanaTestTimeout bounds the connectivity test so a black-holed URL cannot
// hold the request open.
const grafanaTestTimeout = 8 * time.Second

// maxAnnotationPage caps a single annotations query page size.
const maxAnnotationPage = 500

// grafanaSettingsResponse is the GET /api/v1/integrations/grafana payload.
type grafanaSettingsResponse struct {
	storage.GrafanaSettings
	// Recent annotations, newest first, so the console renders its table from
	// one request instead of two.
	RecentAnnotations []annotationView `json:"recent_annotations"`
	// GrafanaReachable is a convenience for the header pill. It reflects the
	// last recorded test, not a live probe: the GET must stay cheap.
	GrafanaReachable bool `json:"grafana_reachable"`
}

// annotationView is the console-facing shape of an annotation log row.
type annotationView struct {
	ID           string   `json:"id"`
	EventID      string   `json:"event_id,omitempty"`
	Hostname     string   `json:"hostname"`
	ImpactLevel  string   `json:"impact_level"`
	ImpactNumber int32    `json:"impact_number"`
	Summary      string   `json:"summary"`
	Text         string   `json:"text"`
	Tags         []string `json:"tags"`
	Dashboard    string   `json:"dashboard,omitempty"`
	Status       string   `json:"status"`
	Error        string   `json:"error,omitempty"`
	Time         string   `json:"time"`
	TimeMs       int64    `json:"time_ms"`
	// DeepLink opens the diff drawer for the event this annotation describes.
	DeepLink string `json:"deep_link,omitempty"`
}

// grafanaAnnotations is the GET /api/v1/grafana/annotations payload, shaped for
// Grafana's JSON/Infinity datasource: `annotations` is the array the datasource
// maps onto markers, and the extra envelope fields make the response
// self-describing when a human opens the URL directly.
type grafanaAnnotationsResponse struct {
	Annotations []annotationView `json:"annotations"`
	Count       int              `json:"count"`
	Host        string           `json:"host,omitempty"`
	From        string           `json:"from,omitempty"`
	To          string           `json:"to,omitempty"`
	// Dashboard matches the datasource's expected top-level shape.
	StatetrackAnnotations bool `json:"statetrack"`
}

// grafana returns the current Grafana integration configuration.
//
//	GET /api/v1/integrations/grafana
func (s *Server) grafanaGet(w http.ResponseWriter, r *http.Request) {
	settings, err := s.Store.GetGrafanaSettings(r.Context(), s.OrgID)
	if err != nil {
		writeErr(w, err)
		return
	}
	recent, err := s.Store.ListAnnotations(r.Context(), s.OrgID, "", time.Time{}, time.Time{}, 20)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grafanaSettingsResponse{
		GrafanaSettings:   settings,
		RecentAnnotations: s.toAnnotationViews(recent),
		GrafanaReachable:  settings.LastTestOK,
	})
}

// grafanaPut updates the Grafana integration configuration at runtime.
//
//	PUT /api/v1/integrations/grafana
//
// The body is a partial update: omitted fields keep their current value, so the
// console can save one toggle without having to round-trip the token.
func (s *Server) grafanaPut(w http.ResponseWriter, r *http.Request) {
	current, err := s.Store.GetGrafanaSettings(r.Context(), s.OrgID)
	if err != nil {
		writeErr(w, err)
		return
	}

	var body struct {
		URL        *string   `json:"url"`
		APIToken   *string   `json:"api_token"`
		Org        *string   `json:"org"`
		PushL1     *bool     `json:"push_l1"`
		PushL2     *bool     `json:"push_l2"`
		PushL3     *bool     `json:"push_l3"`
		Template   *string   `json:"template"`
		Dashboards *[]string `json:"dashboards"`
		Enabled    *bool     `json:"enabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	next := current
	if body.URL != nil {
		target := strings.TrimSpace(*body.URL)
		if target != "" {
			// Validate now rather than at dispatch time: a bad URL saved here
			// would silently break every future annotation.
			parsed, err := url.Parse(target)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error": "url must be an absolute URL, e.g. https://grafana.example.com",
				})
				return
			}
		}
		next.URL = target
	}
	if body.APIToken != nil {
		next.APIToken = *body.APIToken
	}
	if body.Org != nil {
		next.Org = *body.Org
	}
	if body.PushL1 != nil {
		next.PushL1 = *body.PushL1
	}
	if body.PushL2 != nil {
		next.PushL2 = *body.PushL2
	}
	if body.PushL3 != nil {
		next.PushL3 = *body.PushL3
	}
	if body.Template != nil {
		next.Template = *body.Template
	}
	if body.Dashboards != nil {
		next.Dashboards = *body.Dashboards
	}
	if body.Enabled != nil {
		next.Enabled = *body.Enabled
	}

	// Changing the URL or token invalidates the previous test result: showing
	// "Reachable" for a configuration that has never been probed is exactly the
	// kind of stale green light that erodes trust in a console.
	if next.URL != current.URL || next.APIToken != current.APIToken {
		next.LastTestOK = false
		next.LastTestError = ""
		next.LastTestAt = nil
	}

	saved, err := s.Store.SaveGrafanaSettings(r.Context(), s.OrgID, next)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

// grafanaTest performs a live connectivity check against the configured Grafana
// URL and records the outcome.
//
//	POST /api/v1/integrations/grafana/test
func (s *Server) grafanaTest(w http.ResponseWriter, r *http.Request) {
	settings, err := s.Store.GetGrafanaSettings(r.Context(), s.OrgID)
	if err != nil {
		writeErr(w, err)
		return
	}
	target := strings.TrimSpace(settings.URL)
	if target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "grafana url is not configured"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), grafanaTestTimeout)
	defer cancel()

	reachable, detail, version := probeGrafana(ctx, target, settings.APIToken)
	if err := s.Store.RecordGrafanaTest(r.Context(), s.OrgID, reachable, detail); err != nil {
		s.logger().Warn("record grafana test", "err", err)
	}

	status := http.StatusOK
	if !reachable {
		// 502: the console succeeded, the upstream did not. That distinction
		// matters for an operator staring at a proxy log.
		status = http.StatusBadGateway
	}
	writeJSON(w, status, map[string]any{
		"ok":         reachable,
		"url":        target,
		"detail":     detail,
		"version":    version,
		"checked_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// probeGrafana checks the configured URL. It returns whether Grafana answered
// healthily, a human-readable detail, and the reported version when present.
func probeGrafana(ctx context.Context, baseURL, token string) (bool, string, string) {
	endpoint := strings.TrimRight(baseURL, "/") + grafanaHealthPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, "the configured URL is not a valid HTTP URL", ""
	}
	req.Header.Set("Accept", "application/json")
	// Some Grafana deployments authenticate /api/health too; send the token
	// when we have one so a proxy fronting Grafana does not reject the probe.
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: grafanaTestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return false, "could not reach Grafana: " + err.Error(), ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))

	switch {
	case resp.StatusCode == http.StatusOK:
		// A 200 with a JSON body is Grafana. A 200 with an HTML body is a login
		// page or a reverse proxy, which would accept annotation POSTs and
		// silently discard them — worth flagging rather than reporting healthy.
		var health struct {
			Database string `json:"database"`
			Version  string `json:"version"`
		}
		if err := json.Unmarshal(body, &health); err == nil && (health.Database != "" || health.Version != "") {
			return true, fmt.Sprintf("HTTP 200 · database %s · version %s", health.Database, health.Version), health.Version
		}
		return false, "HTTP 200 but the response was not Grafana's health JSON " +
			"(a login page or proxy may be intercepting)", ""
	case resp.StatusCode == http.StatusNotFound:
		return false, "HTTP 404 · /api/health not found — is this really a Grafana instance?", ""
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return false, fmt.Sprintf("HTTP %d · Grafana rejected the API token", resp.StatusCode), ""
	default:
		return false, fmt.Sprintf("HTTP %d from %s", resp.StatusCode, endpoint), ""
	}
}

// grafanaAnnotations serves the annotation query that Grafana's JSON/Infinity
// datasource calls for the $host dashboard variable.
//
//	GET /api/v1/grafana/annotations?host=prod-web-01&from=...&to=...&limit=100
//
// `from`/`to` accept either RFC3339 or epoch milliseconds (and Grafana sends
// epoch milliseconds), because the datasource passes through whatever the
// dashboard's time picker produced.
func (s *Server) grafanaAnnotations(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host := strings.TrimSpace(q.Get("host"))
	// Grafana commonly interpolates an "All" variable to a literal "$__all" or
	// a comma-joined list. Treating those as a host filter would return nothing
	// and look like data loss, so an unfiltered dashboard stays unfiltered.
	switch host {
	case "", "$__all", "All", "all":
		host = ""
	}

	from, err := parseGrafanaTime(q.Get("from"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "from: " + err.Error()})
		return
	}
	to, err := parseGrafanaTime(q.Get("to"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "to: " + err.Error()})
		return
	}

	limit := 100
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a positive integer"})
			return
		}
		limit = min(n, maxAnnotationPage)
	}

	// Annotations deliberately include failures here but exclude the synthetic
	// connectivity-test rows: a dashboard marker for a test POST would be noise
	// on every team's panels.
	entries, err := s.Store.ListAnnotations(r.Context(), s.OrgID, host, from, to, limit)
	if err != nil {
		writeErr(w, err)
		return
	}

	views := s.toAnnotationViews(entries)
	filtered := views[:0]
	for _, v := range views {
		if v.Dashboard == "connectivity-test" {
			continue
		}
		filtered = append(filtered, v)
	}

	writeJSON(w, http.StatusOK, grafanaAnnotationsResponse{
		Annotations:           filtered,
		Count:                 len(filtered),
		Host:                  host,
		From:                  q.Get("from"),
		To:                    q.Get("to"),
		StatetrackAnnotations: true,
	})
}

// toAnnotationViews maps storage rows onto the console/Grafana shape, filling
// in the deep link the API layer owns.
func (s *Server) toAnnotationViews(entries []storage.AnnotationEntry) []annotationView {
	out := make([]annotationView, 0, len(entries))
	for _, e := range entries {
		view := annotationView{
			ID:           strconv.FormatInt(e.ID, 10),
			EventID:      e.EventID,
			Hostname:     e.Hostname,
			ImpactLevel:  levelLabel(e.ImpactLevel),
			ImpactNumber: e.ImpactLevel,
			Summary:      e.Summary,
			Text:         e.Text,
			Tags:         e.Tags,
			Dashboard:    e.Dashboard,
			Status:       e.Status,
			Error:        e.Error,
			Time:         e.DispatchedAt.UTC().Format(time.RFC3339),
			TimeMs:       e.DispatchedAt.UnixMilli(),
		}
		if view.Tags == nil {
			view.Tags = []string{}
		}
		if e.EventID != "" {
			view.DeepLink = fmt.Sprintf("%s/events/%s?tab=diff",
				strings.TrimRight(s.UIBaseURL, "/"), e.EventID)
		}
		out = append(out, view)
	}
	return out
}

// levelLabel renders an impact level as the L1–L4 label the console uses.
func levelLabel(level int32) string {
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
		return "L0"
	}
}

// parseGrafanaTime accepts the several time encodings a datasource may send.
func parseGrafanaTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	// Epoch milliseconds (what Grafana's time picker sends).
	if ms, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return time.UnixMilli(ms).UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC(), nil
	}
	// Relative forms Grafana allows on the query string (e.g. now-6h).
	if strings.HasPrefix(raw, "now") {
		if d, err := parseGrafanaRelative(raw); err == nil {
			return d, nil
		}
	}
	return time.Time{}, errors.New("expected RFC3339 or epoch milliseconds")
}

// parseGrafanaRelative handles the "now" and "now-<duration>" forms.
func parseGrafanaRelative(raw string) (time.Time, error) {
	now := time.Now().UTC()
	if raw == "now" {
		return now, nil
	}
	if !strings.HasPrefix(raw, "now-") {
		return time.Time{}, errors.New("unknown relative time")
	}
	d, err := parseWindowDuration(strings.TrimPrefix(raw, "now-"))
	if err != nil {
		return time.Time{}, err
	}
	return now.Add(-d), nil
}

// decodeJSON reads a JSON body with a size cap. An unbounded body is a trivial
// denial-of-service on a settings endpoint.
func decodeJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return nil
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	// Unknown fields are ignored rather than rejected: the console and the
	// server are versioned independently, and a newer console sending an extra
	// toggle should not break an older server.
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return nil // empty body: a no-op partial update
		}
		return errors.New("invalid JSON body: " + err.Error())
	}
	return nil
}
