package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ProviderGrafana is the integration_settings provider key for Grafana.
const ProviderGrafana = "grafana"

// Annotation statuses.
const (
	AnnotationDelivered = "delivered"
	AnnotationFailed    = "failed"
	AnnotationSkipped   = "skipped"
)

// GrafanaSettings is the operator-editable Grafana integration configuration.
// It is persisted as JSONB so adding a toggle does not require a migration; the
// API layer validates it on write and this type is the contract both sides use.
type GrafanaSettings struct {
	URL      string `json:"url"`
	APIToken string `json:"api_token"`
	Org      string `json:"org"`
	// Level push toggles. L1 is effectively always on (it is the product's
	// promise), but it is still explicit so the console renders honestly.
	PushL1 bool `json:"push_l1"`
	PushL2 bool `json:"push_l2"`
	PushL3 bool `json:"push_l3"`
	// Template is the annotation text template, with {{summary}} {{actor}}
	// {{hostname}} {{level}} {{category}} {{path}} placeholders.
	Template string `json:"template"`
	// Dashboards are the dashboards the operator marked as receiving these
	// annotations. Informational: it records intent for the console.
	Dashboards []string `json:"dashboards"`
	// Enabled gates live dispatch without deleting the configuration.
	Enabled bool `json:"enabled"`
	// LastTestAt / LastTestOK / LastTestError record the most recent
	// connectivity test, so the console can show a result that survives a
	// reload instead of forgetting it.
	LastTestAt    *time.Time `json:"last_test_at,omitempty"`
	LastTestOK    bool       `json:"last_test_ok"`
	LastTestError string     `json:"last_test_error,omitempty"`
}

// DefaultGrafanaSettings returns the configuration used when an org has never
// saved one, so the console always renders a complete form.
func DefaultGrafanaSettings() GrafanaSettings {
	return GrafanaSettings{
		URL:      "https://grafana.internal",
		Org:      "",
		PushL1:   true,
		PushL2:   true,
		PushL3:   false,
		Template: "[StateTrack] {{summary}} · actor {{actor}} on {{hostname}} · {{level}}",
		Enabled:  true,
	}
}

// GetGrafanaSettings loads the org's Grafana settings, falling back to the
// defaults when nothing has been saved yet.
func (s *Store) GetGrafanaSettings(ctx context.Context, orgID string) (GrafanaSettings, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT settings FROM integration_settings
		WHERE org_id = $1::uuid AND provider = $2`, orgID, ProviderGrafana).Scan(&raw)
	if err == pgx.ErrNoRows {
		return DefaultGrafanaSettings(), nil
	}
	if err != nil {
		return GrafanaSettings{}, fmt.Errorf("load grafana settings: %w", err)
	}

	// Start from the defaults so a settings row written by an older build (or
	// a hand-edited row missing a key) still produces a complete struct rather
	// than silently disabling a toggle the operator never saw.
	settings := DefaultGrafanaSettings()
	if err := json.Unmarshal(raw, &settings); err != nil {
		return GrafanaSettings{}, fmt.Errorf("decode grafana settings: %w", err)
	}
	// URL and Template are load-bearing; an explicitly-null value would leave
	// the console with an empty box and the dispatcher with nothing to POST to.
	if settings.URL == "" {
		settings.URL = DefaultGrafanaSettings().URL
	}
	if settings.Template == "" {
		settings.Template = DefaultGrafanaSettings().Template
	}
	return settings, nil
}

// SaveGrafanaSettings upserts the org's Grafana settings.
func (s *Store) SaveGrafanaSettings(ctx context.Context, orgID string, settings GrafanaSettings) (GrafanaSettings, error) {
	raw, err := json.Marshal(settings)
	if err != nil {
		return GrafanaSettings{}, fmt.Errorf("encode grafana settings: %w", err)
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO integration_settings (org_id, provider, settings, updated_at)
		VALUES ($1::uuid, $2, $3, NOW())
		ON CONFLICT (org_id, provider)
		DO UPDATE SET settings = EXCLUDED.settings, updated_at = NOW()`,
		orgID, ProviderGrafana, raw); err != nil {
		return GrafanaSettings{}, fmt.Errorf("save grafana settings: %w", err)
	}
	return settings, nil
}

// RecordGrafanaTest stores the outcome of a connectivity test.
func (s *Store) RecordGrafanaTest(ctx context.Context, orgID string, ok bool, testErr string) error {
	settings, err := s.GetGrafanaSettings(ctx, orgID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	settings.LastTestAt = &now
	settings.LastTestOK = ok
	settings.LastTestError = testErr
	if _, err := s.SaveGrafanaSettings(ctx, orgID, settings); err != nil {
		return err
	}

	// Also log a synthetic annotation attempt so the Recent Annotations table
	// shows the test. Without this an operator who clicks "Test Connection"
	// sees the status pill change but nothing in the delivery history, which is
	// indistinguishable from the test not having run.
	status := AnnotationFailed
	host := "connectivity-test"
	errText := testErr
	if ok {
		status = AnnotationDelivered
		errText = ""
	}
	return s.LogAnnotation(ctx, AnnotationEntry{
		OrgID:     orgID,
		Hostname:  host,
		Summary:   "Grafana connectivity test",
		Text:      "StateTrack connectivity test against " + settings.URL,
		Tags:      []string{"statetrack", "test"},
		Dashboard: "connectivity-test",
		Status:    status,
		Error:     errText,
	})
}

// AnnotationEntry is one row of the outbound annotation log.
type AnnotationEntry struct {
	ID           int64     `json:"id"`
	OrgID        string    `json:"-"`
	EventID      string    `json:"event_id,omitempty"`
	Hostname     string    `json:"hostname"`
	ImpactLevel  int32     `json:"impact_level"`
	Summary      string    `json:"summary"`
	Text         string    `json:"text"`
	Tags         []string  `json:"tags"`
	Dashboard    string    `json:"dashboard,omitempty"`
	Status       string    `json:"status"`
	Error        string    `json:"error,omitempty"`
	DispatchedAt time.Time `json:"dispatched_at"`
}

// LogAnnotation records one outbound annotation attempt. Best-effort by
// design: a failure to log must never break ingestion or the dispatcher.
func (s *Store) LogAnnotation(ctx context.Context, e AnnotationEntry) error {
	var eventID any
	if e.EventID != "" {
		eventID = e.EventID
	}
	if e.Tags == nil {
		e.Tags = []string{}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO annotation_log
		    (org_id, event_id, hostname, impact_level, summary, text, tags, dashboard, status, error)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9, NULLIF($10, ''))`,
		e.OrgID, eventID, e.Hostname, e.ImpactLevel, e.Summary, e.Text, e.Tags, e.Dashboard, e.Status, e.Error)
	if err != nil {
		return fmt.Errorf("log annotation: %w", err)
	}
	return nil
}

// ListAnnotations returns the newest annotation log entries for the org. A
// non-empty host filters to that host (the Grafana $host variable); an empty
// host returns the whole fleet.
//
// `limit` is clamped by the caller; `from`/`to` are inclusive lower/upper
// bounds and may be zero to leave that side open.
func (s *Store) ListAnnotations(ctx context.Context, orgID, host string, from, to time.Time, limit int) ([]AnnotationEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, COALESCE(event_id::text, ''), hostname, impact_level, summary, text,
		       tags, COALESCE(dashboard, ''), status, COALESCE(error, ''), dispatched_at
		FROM annotation_log
		WHERE org_id = $1::uuid
		  AND ($2 = '' OR hostname = $2)
		  AND ($3::timestamptz IS NULL OR dispatched_at >= $3::timestamptz)
		  AND ($4::timestamptz IS NULL OR dispatched_at <= $4::timestamptz)
		ORDER BY dispatched_at DESC, id DESC
		LIMIT $5`,
		orgID, host, nullableTime(from), nullableTime(to), limit)
	if err != nil {
		return nil, fmt.Errorf("list annotations: %w", err)
	}
	defer rows.Close()

	var out []AnnotationEntry
	for rows.Next() {
		var e AnnotationEntry
		if err := rows.Scan(&e.ID, &e.EventID, &e.Hostname, &e.ImpactLevel, &e.Summary,
			&e.Text, &e.Tags, &e.Dashboard, &e.Status, &e.Error, &e.DispatchedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// nullableTime maps the zero time onto SQL NULL so a missing bound leaves that
// side of the range open rather than matching nothing.
func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	utc := t.UTC()
	return &utc
}
