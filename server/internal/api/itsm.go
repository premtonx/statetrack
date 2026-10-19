// ITSM change-ticket bridge: configuration, the mirrored ticket set, and the
// compliance view of the change stream.
//
// The bridge has two halves and this file serves both:
//
//   - Configuration + the ticket mirror — under /api/v1/integrations/itsm and
//     /api/v1/change-tickets. An operator (or an external sync job) writes
//     tickets here; the correlation reads them.
//
//   - The compliance verdict per event — /api/v1/events/compliance. This is the
//     endpoint an auditor's filter and the Reports page's "unapproved changes"
//     view poll.
//
// Nothing here calls out to Jira or ServiceNow. That is the point: the
// correlation must be computable from local state, so that an air-gapped site —
// or a site whose ITSM instance is simply down during the incident — still gets
// a correct compliance verdict. A connector that fetches tickets is a separate
// concern that writes the same rows.
package api

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/statetrack/statetrack/server/internal/itsm"
	"github.com/statetrack/statetrack/server/internal/storage"
)

// Sentinel validation errors, so the POST/PUT handlers return a 400 with a
// message that says what to fix rather than a generic "invalid input".
var (
	errNotAbsoluteURL     = errors.New("url must be an absolute URL, e.g. https://acme.service-now.com")
	errConnectionNeedsURL = errors.New("cannot enable this connector without a base URL")
	errNotATime           = errors.New("expected RFC3339 (2026-10-16T09:00:00Z) or YYYY-MM-DD")
)

// itsmSettingsView is the console-facing configuration. Tokens are never
// returned: the console shows whether one is stored and leaves the field
// untouched to keep it, which is both safer and less error-prone than a masked
// value the console would have to remember not to save back.
type itsmSettingsView struct {
	storage.ITSMSettings
	JiraTokenSet       bool `json:"jira_token_set"`
	ServiceNowTokenSet bool `json:"servicenow_token_set"`
	// Enforcements and RefKinds publish the server's closed vocabularies so the
	// console's dropdowns cannot drift from what the API accepts.
	Enforcements []string `json:"enforcements"`
	Kinds        []string `json:"kinds"`
	// Modes describes each enforcement posture for the form's help text.
	Modes []enforcementHint `json:"modes"`
	// UnapprovedCount is the number of Level-1 changes in the last 24h with no
	// approved ticket, so the hub's header can show the control's real output.
	UnapprovedCount int `json:"unapproved_count"`
}

// enforcementHint is one posture's console description.
type enforcementHint struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Help  string `json:"help"`
}

// itsmEnforcementHints is the closed set of postures with their descriptions.
var itsmEnforcementHints = []enforcementHint{
	{
		Value: string(itsm.EnforcementOff),
		Label: "Off",
		Help:  "Record changes only. No compliance verdict is attached and nothing is flagged.",
	},
	{
		Value: string(itsm.EnforcementWarn),
		Label: "Warn (recommended)",
		Help:  "Attach an 'Unapproved Change' badge to Level 1 changes with no approved ticket. Nothing is blocked.",
	},
	{
		Value: string(itsm.EnforcementRequired),
		Label: "Required",
		Help:  "Flag and alert on every Level 1 change without an approved ticket. Use once your ticket mirror is populated.",
	},
}

// itsmGet returns the bridge configuration and the mirrored ticket set.
//
//	GET /api/v1/integrations/itsm
func (s *Server) itsmGet(w http.ResponseWriter, r *http.Request) {
	settings, err := s.Store.GetITSMSettings(r.Context(), s.OrgID)
	if err != nil {
		writeErr(w, err)
		return
	}
	tickets, err := s.Store.ListChangeTickets(r.Context(), s.OrgID, "")
	if err != nil {
		writeErr(w, err)
		return
	}

	view := itsmSettingsView{
		ITSMSettings:       settings,
		JiraTokenSet:       strings.TrimSpace(settings.Jira.AuthToken) != "",
		ServiceNowTokenSet: strings.TrimSpace(settings.ServiceNow.AuthToken) != "",
		Enforcements:       enforcementValues(),
		Kinds:              kindValues(),
		Modes:              itsmEnforcementHints,
	}
	// The unapproved count is computed here rather than stored: it is derived
	// state that changes whenever a ticket is edited, and persisting it would
	// mean the header could disagree with the report.
	view.UnapprovedCount = s.countUnapproved(r)

	// The token never leaves the server, even to a console that owns it.
	view.Jira.AuthToken = ""
	view.ServiceNow.AuthToken = ""

	writeJSON(w, http.StatusOK, map[string]any{
		"settings": view,
		"tickets":  tickets,
		"count":    len(tickets),
	})
}

// itsmPut updates the bridge configuration (a partial update).
//
//	PUT /api/v1/integrations/itsm
//
// Tokens are only touched when explicitly present in the body, so saving the
// enforcement mode from the console never clears a connector's credential.
func (s *Server) itsmPut(w http.ResponseWriter, r *http.Request) {
	current, err := s.Store.GetITSMSettings(r.Context(), s.OrgID)
	if err != nil {
		writeErr(w, err)
		return
	}

	var body struct {
		Jira *struct {
			URL       *string `json:"url"`
			Project   *string `json:"project"`
			AuthToken *string `json:"auth_token"`
			Username  *string `json:"username"`
			Enabled   *bool   `json:"enabled"`
		} `json:"jira"`
		ServiceNow *struct {
			URL       *string `json:"url"`
			Project   *string `json:"project"`
			AuthToken *string `json:"auth_token"`
			Username  *string `json:"username"`
			Enabled   *bool   `json:"enabled"`
		} `json:"servicenow"`
		Enforcement        *string   `json:"enforcement"`
		WindowGraceMinutes *int      `json:"window_grace_minutes"`
		MinLevel           *int      `json:"min_level"`
		ExemptActors       *[]string `json:"exempt_actors"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	next := current

	if body.Jira != nil {
		if err := applyConnectionUpdate(&next.Jira, body.Jira.URL, body.Jira.Project,
			body.Jira.AuthToken, body.Jira.Username, body.Jira.Enabled); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "jira: " + err.Error()})
			return
		}
	}
	if body.ServiceNow != nil {
		if err := applyConnectionUpdate(&next.ServiceNow, body.ServiceNow.URL, body.ServiceNow.Project,
			body.ServiceNow.AuthToken, body.ServiceNow.Username, body.ServiceNow.Enabled); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "servicenow: " + err.Error()})
			return
		}
	}
	if body.Enforcement != nil {
		mode := strings.ToLower(strings.TrimSpace(*body.Enforcement))
		if !itsm.IsValidEnforcement(itsm.Enforcement(mode)) {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "enforcement must be one of off, warn or required",
			})
			return
		}
		next.Enforcement = mode
	}
	if body.WindowGraceMinutes != nil {
		if *body.WindowGraceMinutes < 0 || *body.WindowGraceMinutes > 24*60 {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "window_grace_minutes must be between 0 and 1440",
			})
			return
		}
		next.WindowGraceMinutes = *body.WindowGraceMinutes
	}
	if body.MinLevel != nil {
		if *body.MinLevel < 1 || *body.MinLevel > 4 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "min_level must be between 1 and 4"})
			return
		}
		next.MinLevel = *body.MinLevel
	}
	if body.ExemptActors != nil {
		next.ExemptActors = normalizeScopes(*body.ExemptActors)
	}

	saved, err := s.Store.SaveITSMSettings(r.Context(), s.OrgID, next)
	if err != nil {
		writeErr(w, err)
		return
	}
	saved.Jira.AuthToken = ""
	saved.ServiceNow.AuthToken = ""
	writeJSON(w, http.StatusOK, saved)
}

// applyConnectionUpdate merges one connector's partial update, validating the
// URL so a bad value is rejected at write time rather than during a sync.
func applyConnectionUpdate(conn *storage.ITSMConnection, url_, project, token, username *string, enabled *bool) error {
	if url_ != nil {
		target := strings.TrimSpace(*url_)
		if target != "" {
			parsed, err := url.Parse(target)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				return errNotAbsoluteURL
			}
		}
		conn.URL = target
	}
	if project != nil {
		conn.Project = strings.TrimSpace(*project)
	}
	if token != nil {
		conn.AuthToken = *token
	}
	if username != nil {
		conn.Username = strings.TrimSpace(*username)
	}
	if enabled != nil {
		if *enabled && strings.TrimSpace(conn.URL) == "" {
			return errConnectionNeedsURL
		}
		conn.Enabled = *enabled
	}
	return nil
}

// itsmSync records a completed ticket sync.
//
//	POST /api/v1/integrations/itsm/sync
//
// The endpoint exists so an external sync job (or an operator who imported a CSV
// by hand) can stamp the connector's last-run result, which is what the hub's
// status pill renders. It does not fetch anything itself — see the package
// comment — and it deliberately accepts tickets in the same request so a
// connector can push and stamp in one call.
func (s *Server) itsmSync(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind     string `json:"kind"`
		Imported int    `json:"imported"`
		Error    string `json:"error"`
		Tickets  []struct {
			Ref          string   `json:"ref"`
			Status       string   `json:"status"`
			Summary      string   `json:"summary"`
			URL          string   `json:"url"`
			Hosts        []string `json:"hosts"`
			Environments []string `json:"environments"`
			Paths        []string `json:"paths"`
			WindowStart  string   `json:"window_start"`
			WindowEnd    string   `json:"window_end"`
			RequestedBy  string   `json:"requested_by"`
		} `json:"tickets"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	kind := strings.ToLower(strings.TrimSpace(body.Kind))
	if kind != string(itsm.KindJira) && kind != string(itsm.KindServiceNow) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "kind must be jira or servicenow"})
		return
	}

	imported := 0
	for _, t := range body.Tickets {
		start, err := parseOptionalTime(t.WindowStart)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "ticket " + t.Ref + ": invalid window_start",
			})
			return
		}
		end, err := parseOptionalTime(t.WindowEnd)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "ticket " + t.Ref + ": invalid window_end",
			})
			return
		}
		if _, err := s.Store.UpsertChangeTicket(r.Context(), s.OrgID, storage.ChangeTicket{
			Kind:         kind,
			Ref:          t.Ref,
			Status:       t.Status,
			Summary:      t.Summary,
			URL:          t.URL,
			Hosts:        t.Hosts,
			Environments: t.Environments,
			Paths:        t.Paths,
			WindowStart:  start,
			WindowEnd:    end,
			RequestedBy:  t.RequestedBy,
		}); err != nil {
			writeErr(w, err)
			return
		}
		imported++
	}

	count := imported
	if body.Imported > 0 {
		count = body.Imported
	}
	// A sync that reported tickets but failed to write them must not stamp a
	// green result, so the store write above runs first and any error returned.
	if err := s.Store.RecordITSMSync(r.Context(), s.OrgID, kind, count, strings.TrimSpace(body.Error)); err != nil {
		s.logger().Warn("record itsm sync", "kind", kind, "err", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "recorded", "kind": kind, "imported": imported})
}

// listChangeTickets returns the mirrored ticket set.
//
//	GET /api/v1/change-tickets?status=approved
func (s *Server) listChangeTickets(w http.ResponseWriter, r *http.Request) {
	status := storage.NormalizeComplianceStatus(r.URL.Query().Get("status"))
	tickets, err := s.Store.ListChangeTickets(r.Context(), s.OrgID, status)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tickets": tickets,
		"count":   len(tickets),
		"kinds":   kindValues(),
	})
}

// upsertChangeTicket creates or updates a mirrored ticket by hand.
//
//	POST /api/v1/change-tickets
//
// This is the air-gapped onboarding path: a site with no reachable ITSM can
// still record its change calendar, and the correlation works identically.
func (s *Server) upsertChangeTicket(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Ref          string   `json:"ref"`
		Kind         string   `json:"kind"`
		Status       string   `json:"status"`
		Summary      string   `json:"summary"`
		URL          string   `json:"url"`
		Hosts        []string `json:"hosts"`
		Environments []string `json:"environments"`
		Paths        []string `json:"paths"`
		WindowStart  string   `json:"window_start"`
		WindowEnd    string   `json:"window_end"`
		RequestedBy  string   `json:"requested_by"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ref := strings.ToUpper(strings.TrimSpace(body.Ref))
	if ref == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ref is required (e.g. CHG-1042)"})
		return
	}
	kind := strings.ToLower(strings.TrimSpace(body.Kind))
	if kind == "" {
		kind = string(itsm.KindManual)
	}
	if !itsm.IsValidKind(itsm.Kind(kind)) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "kind must be one of jira, servicenow or manual",
		})
		return
	}
	start, err := parseOptionalTime(body.WindowStart)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid window_start"})
		return
	}
	end, err := parseOptionalTime(body.WindowEnd)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid window_end"})
		return
	}

	ticket, err := s.Store.UpsertChangeTicket(r.Context(), s.OrgID, storage.ChangeTicket{
		Kind:         kind,
		Ref:          ref,
		Status:       strings.TrimSpace(body.Status),
		Summary:      strings.TrimSpace(body.Summary),
		URL:          strings.TrimSpace(body.URL),
		Hosts:        trimAll(body.Hosts),
		Environments: trimAll(body.Environments),
		Paths:        trimAll(body.Paths),
		WindowStart:  start,
		WindowEnd:    end,
		RequestedBy:  strings.TrimSpace(body.RequestedBy),
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ticket)
}

// deleteChangeTicket removes a mirrored ticket.
//
//	DELETE /api/v1/change-tickets/{ref}
func (s *Server) deleteChangeTicket(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("ref")
	if err := s.Store.DeleteChangeTicket(r.Context(), s.OrgID, ref); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "ref": strings.ToUpper(ref)})
}

// countUnapproved counts Level-1 changes in the last 24 hours with no approved
// ticket. It is the hub's headline number: it answers "is this control finding
// anything?" without the operator having to run a report.
//
// Failures return zero rather than an error: this is a summary badge, and a
// header that 500s because the ITSM settings row is unreadable would take down
// the whole integrations hub.
func (s *Server) countUnapproved(r *http.Request) int {
	settings, err := s.Store.GetITSMSettings(r.Context(), s.OrgID)
	if err != nil || settings.Enforcement == string(itsm.EnforcementOff) {
		return 0
	}
	tickets, err := s.Store.ListChangeTickets(r.Context(), s.OrgID, "")
	if err != nil {
		return 0
	}
	events, _, err := s.Store.ListEvents(r.Context(), s.OrgID, storage.EventFilter{
		ImpactLevel: 1,
		From:        time.Now().Add(-24 * time.Hour),
		Limit:       200,
		RootOnly:    true,
	})
	if err != nil {
		return 0
	}
	opts := itsm.Options{
		Enforcement:  itsm.Enforcement(settings.Enforcement),
		WindowGrace:  time.Duration(settings.WindowGraceMinutes) * time.Minute,
		MinLevel:     int32(settings.MinLevel),
		ExemptActors: settings.ExemptActors,
		Now:          time.Now(),
	}
	correlationTickets := toITSTickets(tickets)
	n := 0
	for _, e := range events {
		res := itsm.Correlate(itsm.Event{
			ID:         e.ID,
			Hostname:   e.Hostname,
			PathOrKey:  e.PathOrKey,
			TargetType: e.TargetType,
			Level:      e.ImpactLevel,
			OccurredAt: e.OccurredAt,
			Summary:    e.Summary,
			Actor:      e.ActorUsername,
			Cmdline:    e.Cmdline,
			Metadata:   e.Metadata,
		}, correlationTickets, opts)
		if res.Compliance.IsViolation() {
			n++
		}
	}
	return n
}

func enforcementValues() []string {
	out := make([]string, 0, len(itsm.Enforcements))
	for _, e := range itsm.Enforcements {
		out = append(out, string(e))
	}
	return out
}

func kindValues() []string {
	out := make([]string, 0, len(itsm.Kinds))
	for _, k := range itsm.Kinds {
		out = append(out, string(k))
	}
	return out
}

// parseOptionalTime accepts an empty string (meaning "unset"), RFC3339, or a
// date. An unset window bound is meaningful: a ticket with no end is open-ended,
// which the correlation treats as unbounded on that side.
func parseOptionalTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, errNotATime
}

// trimAll trims and drops empty entries from a list, so a form's trailing comma
// cannot produce a scope entry that matches nothing.
func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
