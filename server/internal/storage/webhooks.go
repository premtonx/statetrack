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

// Webhook provider keys. These are the `integrations.provider` values and the
// Prometheus `provider` label, so they are stable identifiers rather than
// display names.
const (
	ProviderSlack     = "slack"
	ProviderTeams     = "teams"
	ProviderPagerDuty = "pagerduty"
	ProviderWebhook   = "webhook"
	// ProviderGrafanaAnnotations is the `integrations` table row the pusher
	// reads for annotation delivery. Distinct from grafana.go's ProviderGrafana,
	// which keys the integration_settings JSONB blob (a different table).
	ProviderGrafanaAnnotations = "grafana_annotations"
)

// WebhookProviders is the closed set the hub renders cards for, in display
// order. Kept here so the API and the store agree on what a valid provider is.
var WebhookProviders = []string{ProviderTeams, ProviderSlack, ProviderPagerDuty, ProviderWebhook}

// IsWebhookProvider reports whether a provider is one of the outbound
// notification channels (as opposed to the Grafana annotation sink).
func IsWebhookProvider(provider string) bool {
	for _, p := range WebhookProviders {
		if p == provider {
			return true
		}
	}
	return false
}

// WebhookChannel is one configured outbound notification channel.
type WebhookChannel struct {
	Provider string `json:"provider"`
	// URL is the delivery target: a Slack/Teams incoming webhook, PagerDuty's
	// Events API endpoint, or a SIEM collector.
	URL string `json:"url"`
	// Token is the HMAC signing secret (generic webhook) or the PagerDuty
	// routing key. Never returned in full by the API.
	Token string `json:"token"`
	// Label is Slack's channel name or a human note; unused by Teams/PagerDuty.
	Label string `json:"label"`
	// Severity overrides the PagerDuty severity. Empty means "derive it from the
	// impact level", which is the sensible default and what most teams want.
	Severity string `json:"severity"`
	// NotifyL1 delivers Level 1 critical changes.
	NotifyL1 bool `json:"notify_l1"`
	// NotifyStorms delivers change-storm notifications.
	NotifyStorms bool      `json:"notify_storms"`
	Enabled      bool      `json:"enabled"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
}

// DefaultWebhookChannel returns the configuration a provider has before an
// operator has saved anything, so the hub always renders a complete card.
func DefaultWebhookChannel(provider string) WebhookChannel {
	ch := WebhookChannel{
		Provider: provider,
		NotifyL1: true,
		// Storms are the "something is writing in a loop" signal, which is
		// exactly what a notification channel is for; opt out rather than in.
		NotifyStorms: true,
		Enabled:      false,
	}
	switch provider {
	case ProviderPagerDuty:
		ch.URL = "https://events.pagerduty.com/v2/enqueue"
		ch.Severity = "critical"
	case ProviderWebhook:
		ch.Label = "SIEM"
	}
	return ch
}

// ListWebhookChannels returns every configured notification channel for the
// org, including disabled ones (the hub renders a card per provider and needs
// to show the saved-but-off state).
//
// The result is padded to the full provider set: the hub shows a card for each
// provider whether or not a row exists, and doing that padding here means the
// console does not have to merge defaults into a sparse list.
func (s *Store) ListWebhookChannels(ctx context.Context, orgID string) ([]WebhookChannel, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT provider, endpoint_url, COALESCE(api_token_encrypted, ''), label, severity,
		       notify_l1, notify_storms, enabled, updated_at
		FROM integrations
		WHERE org_id = $1::uuid AND provider = ANY($2)`,
		orgID, WebhookProviders)
	if err != nil {
		return nil, fmt.Errorf("list webhook channels: %w", err)
	}
	defer rows.Close()

	found := make(map[string]WebhookChannel, len(WebhookProviders))
	for rows.Next() {
		var c WebhookChannel
		if err := rows.Scan(&c.Provider, &c.URL, &c.Token, &c.Label, &c.Severity,
			&c.NotifyL1, &c.NotifyStorms, &c.Enabled, &c.UpdatedAt); err != nil {
			return nil, err
		}
		found[c.Provider] = c
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]WebhookChannel, 0, len(WebhookProviders))
	for _, p := range WebhookProviders {
		if c, ok := found[p]; ok {
			out = append(out, c)
			continue
		}
		out = append(out, DefaultWebhookChannel(p))
	}
	return out, nil
}

// GetWebhookChannel returns one provider's channel, falling back to its
// defaults when nothing has been saved.
func (s *Store) GetWebhookChannel(ctx context.Context, orgID, provider string) (WebhookChannel, error) {
	var c WebhookChannel
	err := s.pool.QueryRow(ctx, `
		SELECT provider, endpoint_url, COALESCE(api_token_encrypted, ''), label, severity,
		       notify_l1, notify_storms, enabled, updated_at
		FROM integrations
		WHERE org_id = $1::uuid AND provider = $2`, orgID, provider).
		Scan(&c.Provider, &c.URL, &c.Token, &c.Label, &c.Severity,
			&c.NotifyL1, &c.NotifyStorms, &c.Enabled, &c.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return DefaultWebhookChannel(provider), nil
		}
		return WebhookChannel{}, fmt.Errorf("get webhook channel: %w", err)
	}
	return c, nil
}

// SaveWebhookChannel upserts one provider's configuration.
//
// min_impact_level is derived rather than taken from the caller: notify_l1 and
// notify_storms are what the UI expresses, and the pusher's existing dispatch
// rule reads min_impact_level. Writing 1 when L1 is on and 4 when it is off
// (Level 4 is the least severe, so it matches everything) keeps the pusher
// unchanged while giving the console the toggles it needs.
func (s *Store) SaveWebhookChannel(ctx context.Context, orgID string, c WebhookChannel) (WebhookChannel, error) {
	minLevel := 4
	if c.NotifyL1 {
		minLevel = 1
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO integrations
		    (org_id, provider, endpoint_url, api_token_encrypted, min_impact_level, enabled,
		     label, severity, notify_l1, notify_storms, updated_at)
		VALUES ($1::uuid, $2, $3, NULLIF($4, ''), $5, $6, $7, $8, $9, $10, NOW())
		ON CONFLICT (org_id, provider) DO UPDATE SET
		    endpoint_url        = EXCLUDED.endpoint_url,
		    api_token_encrypted = EXCLUDED.api_token_encrypted,
		    min_impact_level    = EXCLUDED.min_impact_level,
		    enabled             = EXCLUDED.enabled,
		    label               = EXCLUDED.label,
		    severity            = EXCLUDED.severity,
		    notify_l1           = EXCLUDED.notify_l1,
		    notify_storms       = EXCLUDED.notify_storms,
		    updated_at          = NOW()
		RETURNING provider, endpoint_url, COALESCE(api_token_encrypted, ''), label, severity,
		          notify_l1, notify_storms, enabled, updated_at`,
		orgID, c.Provider, c.URL, c.Token, minLevel, c.Enabled,
		c.Label, c.Severity, c.NotifyL1, c.NotifyStorms).
		Scan(&c.Provider, &c.URL, &c.Token, &c.Label, &c.Severity,
			&c.NotifyL1, &c.NotifyStorms, &c.Enabled, &c.UpdatedAt)
	if err != nil {
		return WebhookChannel{}, fmt.Errorf("save webhook channel: %w", err)
	}
	return c, nil
}

// DeleteWebhookChannel removes a channel, so "disable and clear" can leave the
// table tidy rather than accumulating empty rows.
func (s *Store) DeleteWebhookChannel(ctx context.Context, orgID, provider string) error {
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM integrations WHERE org_id = $1::uuid AND provider = $2`, orgID, provider); err != nil {
		return fmt.Errorf("delete webhook channel: %w", err)
	}
	return nil
}

// WebhookDelivery is one row of the outbound delivery log.
type WebhookDelivery struct {
	ID         int64     `json:"id"`
	Provider   string    `json:"provider"`
	Endpoint   string    `json:"endpoint,omitempty"`
	EventID    string    `json:"event_id,omitempty"`
	StatusCode int       `json:"status_code"`
	LatencyMs  int       `json:"latency_ms"`
	Success    bool      `json:"success"`
	Attempts   int       `json:"attempts"`
	Sample     bool      `json:"sample"`
	Error      string    `json:"error,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// LogWebhookDelivery records one delivery attempt so the hub's status log is
// backed by real sends rather than a hardcoded list.
//
// Best-effort by design: a failure to log must never affect delivery, so
// callers may ignore the error (and the handler does).
func (s *Store) LogWebhookDelivery(ctx context.Context, orgID string, d WebhookDelivery) error {
	var eventID any
	if d.EventID != "" {
		eventID = d.EventID
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO webhook_deliveries
		    (org_id, provider, endpoint_url, event_id, status_code, latency_ms, success, attempts, sample, error)
		VALUES ($1::uuid, $2, $3, $4::uuid, $5, $6, $7, $8, $9, NULLIF($10, ''))`,
		orgID, d.Provider, d.Endpoint, eventID,
		d.StatusCode, d.LatencyMs, d.Success, d.Attempts, d.Sample, d.Error)
	if err != nil {
		return fmt.Errorf("log webhook delivery: %w", err)
	}
	return nil
}

// ListWebhookDeliveries returns the newest delivery rows for the org, newest
// first. An empty provider returns every channel.
func (s *Store) ListWebhookDeliveries(ctx context.Context, orgID, provider string, limit int) ([]WebhookDelivery, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, provider, endpoint_url, COALESCE(event_id::text, ''), status_code,
		       latency_ms, success, attempts, sample, COALESCE(error, ''), created_at
		FROM webhook_deliveries
		WHERE org_id = $1::uuid AND ($2 = '' OR provider = $2)
		ORDER BY created_at DESC, id DESC
		LIMIT $3`, orgID, provider, limit)
	if err != nil {
		return nil, fmt.Errorf("list webhook deliveries: %w", err)
	}
	defer rows.Close()

	out := make([]WebhookDelivery, 0, limit)
	for rows.Next() {
		var d WebhookDelivery
		if err := rows.Scan(&d.ID, &d.Provider, &d.Endpoint, &d.EventID, &d.StatusCode,
			&d.LatencyMs, &d.Success, &d.Attempts, &d.Sample, &d.Error, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// MarshalWebhookChannel exposes the channel as JSON for callers that want to
// store the rendered settings (used by tests and the seed path).
func MarshalWebhookChannel(c WebhookChannel) ([]byte, error) {
	return json.Marshal(c)
}

// TrimToken shortens a secret for display so the console can show "ends in
// …abcd" without ever receiving the whole value.
func TrimToken(token string) string {
	token = strings.TrimSpace(token)
	if len(token) <= 4 {
		return token
	}
	return "…" + token[len(token)-4:]
}
