package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ProviderITSM is the integration_settings provider key for the change-ticket
// bridge. Distinct from the `integrations` table rows (which model outbound
// notification channels): the ITSM configuration is a set of operator knobs
// with no single endpoint, so it lives in the JSONB settings blob.
const ProviderITSM = "itsm"

// ITSMConnection is one upstream change-management system.
//
// Jira and ServiceNow are both modelled by the same struct deliberately: the
// correlation consumes normalized tickets, and the only per-system differences
// are which URL shape to fetch and which field names carry status. Keeping them
// as two instances of one type means adding a third system is a config change
// rather than a new code path.
type ITSMConnection struct {
	// URL is the base URL of the instance, e.g.
	// https://acme.atlassian.net or https://acme.service-now.com.
	URL string `json:"url"`
	// Project is Jira's project key or ServiceNow's table name
	// ("change_request"). Informational for the sync job; recorded so the
	// console can show what the connector is scoped to.
	Project string `json:"project"`
	// AuthToken is the API token / password a sync job authenticates with.
	// Never returned by the API in full.
	AuthToken string `json:"auth_token,omitempty"`
	// Username is the basic-auth user for Jira Cloud (email) or ServiceNow.
	// Empty means bearer-token authentication.
	Username string `json:"username,omitempty"`
	// Enabled gates the connector. A disabled connector's mirrored tickets stay
	// in the database: turning off a sync must not silently unapprove changes
	// that were legitimately approved.
	Enabled bool `json:"enabled"`
	// LastSyncAt / LastSyncOK / LastSyncError record the most recent sync so the
	// console shows a result that survives a reload.
	LastSyncAt    *time.Time `json:"last_sync_at,omitempty"`
	LastSyncOK    bool       `json:"last_sync_ok"`
	LastSyncError string     `json:"last_sync_error,omitempty"`
	// LastSyncCount is how many tickets the last sync imported or updated.
	LastSyncCount int `json:"last_sync_count"`
}

// ITSMSettings is the operator-editable change-ticket bridge configuration.
type ITSMSettings struct {
	Jira       ITSMConnection `json:"jira"`
	ServiceNow ITSMConnection `json:"servicenow"`
	// Enforcement is the chosen posture for unauthorised production changes:
	// 'off', 'warn' or 'required'.
	Enforcement string `json:"enforcement"`
	// WindowGraceMinutes extends each ticket's window on both sides when
	// matching. A change control process is not clock-exact, and flagging an
	// engineer who executed an approved window four minutes early would train
	// reviewers to ignore the control.
	WindowGraceMinutes int `json:"window_grace_minutes"`
	// MinLevel is the impact level above which a change needs a ticket. Only 1
	// by default: reporting every Level 3 staging drift as a compliance
	// violation makes the audit queue useless.
	MinLevel int `json:"min_level"`
	// ExemptActors are usernames whose changes never require a ticket — the
	// configuration-management account, for instance, which is itself the
	// system of record. Matched case-insensitively.
	ExemptActors []string  `json:"exempt_actors"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
}

// DefaultITSMSettings returns the configuration shown before anything is saved.
//
// Enforcement defaults to 'warn' rather than 'required': the correlation needs
// a populated ticket mirror before it can produce meaningful verdicts, and
// turning on a hard control before any tickets have synced would flag every
// production change in the fleet on the first day.
func DefaultITSMSettings() ITSMSettings {
	return ITSMSettings{
		Jira:        ITSMConnection{Project: "OPS", Enabled: false},
		ServiceNow:  ITSMConnection{Project: "change_request", Enabled: false},
		Enforcement: "warn",
		// 15 minutes matches itsm.DefaultWindowGrace.
		WindowGraceMinutes: 15,
		MinLevel:           1,
		ExemptActors:       []string{"config-management", "terraform", "state-sync"},
	}
}

// GetITSMSettings loads the org's change-ticket bridge configuration, falling
// back to the defaults when nothing has been saved.
func (s *Store) GetITSMSettings(ctx context.Context, orgID string) (ITSMSettings, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT settings FROM integration_settings
		WHERE org_id = $1::uuid AND provider = $2`, orgID, ProviderITSM).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultITSMSettings(), nil
	}
	if err != nil {
		return ITSMSettings{}, fmt.Errorf("load itsm settings: %w", err)
	}

	// Start from the defaults so a row written by an older build (or a
	// hand-edited row missing a key) still decodes into a complete struct
	// rather than silently switching enforcement off.
	settings := DefaultITSMSettings()
	if err := json.Unmarshal(raw, &settings); err != nil {
		return ITSMSettings{}, fmt.Errorf("decode itsm settings: %w", err)
	}
	if !isKnownEnforcement(settings.Enforcement) {
		settings.Enforcement = DefaultITSMSettings().Enforcement
	}
	if settings.WindowGraceMinutes < 0 {
		settings.WindowGraceMinutes = DefaultITSMSettings().WindowGraceMinutes
	}
	if settings.MinLevel < 0 || settings.MinLevel > 4 {
		settings.MinLevel = 1
	}
	if settings.ExemptActors == nil {
		settings.ExemptActors = []string{}
	}
	return settings, nil
}

// isKnownEnforcement mirrors itsm.IsValidEnforcement. Duplicated as a local
// closed set rather than imported, so the storage package does not depend on
// the correlation package's vocabulary (and vice versa).
func isKnownEnforcement(e string) bool {
	switch e {
	case "off", "warn", "required":
		return true
	default:
		return false
	}
}

// SaveITSMSettings upserts the org's ITSM configuration.
func (s *Store) SaveITSMSettings(ctx context.Context, orgID string, settings ITSMSettings) (ITSMSettings, error) {
	raw, err := json.Marshal(settings)
	if err != nil {
		return ITSMSettings{}, fmt.Errorf("encode itsm settings: %w", err)
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO integration_settings (org_id, provider, settings, updated_at)
		VALUES ($1::uuid, $2, $3, NOW())
		ON CONFLICT (org_id, provider)
		DO UPDATE SET settings = EXCLUDED.settings, updated_at = NOW()`,
		orgID, ProviderITSM, raw); err != nil {
		return ITSMSettings{}, fmt.Errorf("save itsm settings: %w", err)
	}
	settings.UpdatedAt = time.Now().UTC()
	return settings, nil
}

/* -------------------------------------------------------------------------- */
/* Change tickets                                                             */
/* -------------------------------------------------------------------------- */

// ChangeTicket is one mirrored change request.
type ChangeTicket struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Ref    string `json:"ref"`
	Status string `json:"status"`
	// StatusLabel is the normalized, human-readable status the console badges.
	// Computed on read rather than stored so a change to the mapping does not
	// need a data migration.
	StatusLabel  string    `json:"status_label"`
	Authorized   bool      `json:"authorized"`
	Summary      string    `json:"summary"`
	URL          string    `json:"url,omitempty"`
	Hosts        []string  `json:"hosts"`
	Environments []string  `json:"environments"`
	Paths        []string  `json:"paths"`
	WindowStart  time.Time `json:"window_start,omitempty"`
	WindowEnd    time.Time `json:"window_end,omitempty"`
	RequestedBy  string    `json:"requested_by,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	// Expired reports whether the ticket's window has closed as of `now`, so
	// the console can grey out a ticket that no longer authorises anything.
	Expired bool `json:"expired"`
}

// ListChangeTickets returns every mirrored ticket for the org, newest first.
// `status` filters by normalized status ("" = any).
//
// The whole set is returned rather than a page: correlation needs all of it,
// and it is bounded by the number of open change requests an organisation has
// (hundreds), not by change volume.
func (s *Store) ListChangeTickets(ctx context.Context, orgID, status string) ([]ChangeTicket, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, kind, ref, status, summary, url, hosts, environments, paths,
		       COALESCE(window_start, 'epoch'::timestamptz),
		       COALESCE(window_end, 'epoch'::timestamptz),
		       requested_by, created_at, updated_at
		FROM change_tickets
		WHERE org_id = $1::uuid AND ($2 = '' OR status = $2)
		ORDER BY updated_at DESC, ref`, orgID, status)
	if err != nil {
		return nil, fmt.Errorf("list change tickets: %w", err)
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

// GetChangeTicket returns one ticket by id or reference.
func (s *Store) GetChangeTicket(ctx context.Context, orgID, idOrRef string) (ChangeTicket, error) {
	var t ChangeTicket
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, kind, ref, status, summary, url, hosts, environments, paths,
		       COALESCE(window_start, 'epoch'::timestamptz),
		       COALESCE(window_end, 'epoch'::timestamptz),
		       requested_by, created_at, updated_at
		FROM change_tickets
		WHERE org_id = $1::uuid AND (ref = $2 OR id::text = $2)
		LIMIT 1`, orgID, idOrRef).
		Scan(&t.ID, &t.Kind, &t.Ref, &t.Status, &t.Summary, &t.URL,
			&t.Hosts, &t.Environments, &t.Paths, &t.WindowStart, &t.WindowEnd,
			&t.RequestedBy, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ChangeTicket{}, ErrNotFound
	}
	if err != nil {
		return ChangeTicket{}, fmt.Errorf("get change ticket: %w", err)
	}
	return decorateTicket(t, time.Now()), nil
}

// UpsertChangeTicket inserts or updates a mirrored ticket, keyed on its
// reference so a re-sync updates in place rather than duplicating.
//
// The reference is upper-cased before storing: 'chg-1042' typed by hand and
// 'CHG-1042' imported from ServiceNow are the same ticket, and letting both
// exist would make the correlation depend on which one a mutation happened to
// match.
func (s *Store) UpsertChangeTicket(ctx context.Context, orgID string, t ChangeTicket) (ChangeTicket, error) {
	ref := strings.ToUpper(strings.TrimSpace(t.Ref))
	if ref == "" {
		return ChangeTicket{}, errors.New("change ticket reference is required")
	}
	var windowStart, windowEnd *time.Time
	if !t.WindowStart.IsZero() {
		utc := t.WindowStart.UTC()
		windowStart = &utc
	}
	if !t.WindowEnd.IsZero() {
		utc := t.WindowEnd.UTC()
		windowEnd = &utc
	}
	kind := strings.TrimSpace(t.Kind)
	if kind == "" {
		kind = "manual"
	}

	err := s.pool.QueryRow(ctx, `
		INSERT INTO change_tickets
		    (org_id, kind, ref, status, summary, url, hosts, environments, paths,
		     window_start, window_end, requested_by, updated_at)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
		ON CONFLICT (org_id, ref) DO UPDATE SET
		    kind         = EXCLUDED.kind,
		    status       = EXCLUDED.status,
		    summary      = EXCLUDED.summary,
		    url          = EXCLUDED.url,
		    hosts        = EXCLUDED.hosts,
		    environments = EXCLUDED.environments,
		    paths        = EXCLUDED.paths,
		    window_start = EXCLUDED.window_start,
		    window_end   = EXCLUDED.window_end,
		    requested_by = EXCLUDED.requested_by,
		    updated_at   = NOW()
		RETURNING id::text, kind, ref, status, summary, url, hosts, environments, paths,
		          COALESCE(window_start, 'epoch'::timestamptz),
		          COALESCE(window_end, 'epoch'::timestamptz),
		          requested_by, created_at, updated_at`,
		orgID, kind, ref, strings.TrimSpace(t.Status), t.Summary, t.URL,
		nonNilStrings(t.Hosts), nonNilStrings(t.Environments), nonNilStrings(t.Paths),
		windowStart, windowEnd, t.RequestedBy).
		Scan(&t.ID, &t.Kind, &t.Ref, &t.Status, &t.Summary, &t.URL,
			&t.Hosts, &t.Environments, &t.Paths, &t.WindowStart, &t.WindowEnd,
			&t.RequestedBy, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return ChangeTicket{}, fmt.Errorf("upsert change ticket %s: %w", ref, err)
	}
	return decorateTicket(t, time.Now()), nil
}

// DeleteChangeTicket removes a mirrored ticket.
func (s *Store) DeleteChangeTicket(ctx context.Context, orgID, idOrRef string) error {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM change_tickets WHERE org_id = $1::uuid AND (ref = $2 OR id::text = $2)`,
		orgID, strings.ToUpper(strings.TrimSpace(idOrRef)))
	if err != nil {
		return fmt.Errorf("delete change ticket: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordITSMSync stores the outcome of a connector's last sync attempt.
//
// Best-effort by design, matching RecordGrafanaTest: a sync that succeeded must
// not be reported as failed because the status write errored.
func (s *Store) RecordITSMSync(ctx context.Context, orgID, kind string, imported int, syncErr string) error {
	settings, err := s.GetITSMSettings(ctx, orgID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	var conn *ITSMConnection
	switch kind {
	case "jira":
		conn = &settings.Jira
	case "servicenow":
		conn = &settings.ServiceNow
	default:
		return fmt.Errorf("unknown itsm connector %q", kind)
	}
	conn.LastSyncAt = &now
	conn.LastSyncOK = syncErr == ""
	conn.LastSyncError = syncErr
	conn.LastSyncCount = imported
	_, err = s.SaveITSMSettings(ctx, orgID, settings)
	return err
}

// decorateTicket fills in the derived display fields. Kept in one place so the
// console's badge and the correlation verdict can never disagree about whether
// a ticket is authorised.
func decorateTicket(t ChangeTicket, now time.Time) ChangeTicket {
	t.StatusLabel, t.Authorized = NormalizeTicketStatus(t.Status)
	if !t.WindowEnd.IsZero() && !t.WindowEnd.Equal(time.Unix(0, 0)) {
		t.Expired = now.After(t.WindowEnd)
	}
	if t.Hosts == nil {
		t.Hosts = []string{}
	}
	if t.Environments == nil {
		t.Environments = []string{}
	}
	if t.Paths == nil {
		t.Paths = []string{}
	}
	return t
}

// NormalizeTicketStatus maps an upstream status onto the closed set and reports
// whether it authorises a change.
//
// This mirrors internal/itsm's mapping. It is duplicated rather than shared
// because storage must stay free of the correlation package's policy types, and
// the alternative — a status string that means one thing to the badge and
// another to the verdict — is the failure mode this duplication prevents.
func NormalizeTicketStatus(raw string) (label string, authorized bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "draft", "new", "open":
		return "Draft", false
	case "requested", "pending", "pending_approval", "awaiting_approval", "assess", "authorize":
		return "Pending Approval", false
	case "approved", "scheduled":
		return "Approved", true
	case "in_progress", "implement", "implementing", "review", "reviewing":
		return "In Progress", true
	case "completed", "closed", "done":
		return "Completed", false
	case "rejected", "declined":
		return "Rejected", false
	case "cancelled", "canceled", "abandoned":
		return "Cancelled", false
	default:
		return "Unknown", false
	}
}

// nonNilStrings maps a nil slice onto an empty array so the TEXT[] column never
// stores NULL (which would make `hosts = '{}'` comparisons behave differently
// from a column that was explicitly written empty).
func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
