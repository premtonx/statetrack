package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/statetrack/statetrack/server/internal/ai"
)

// ProviderAI is the integration_settings provider key for the AI analysis
// gateway.
//
// It is a distinct key rather than folded into ProviderITSM or ProviderGrafana
// because the three are configured by different roles and read by different
// code paths; one shared blob would mean saving the AI provider also rewrote
// the Grafana template, and an audit reviewer could no longer tell which
// endpoint changed.
const ProviderAI = "ai"

// GetAISettings loads the org's AI gateway configuration, falling back to the
// defaults when nothing has been saved.
//
// The stored JSON is decoded onto top of DefaultSettings() rather than a zero
// value, so a row written by an earlier build (or hand-edited in the database)
// yields a usable configuration instead of a zero timeout that fails every
// call. It is then passed through ai.NormalizeSettings, which clamps the
// numeric knobs and rejects an unknown provider — the same normalization the
// gateway applies, so what the console reads back is what will actually run.
func (s *Store) GetAISettings(ctx context.Context, orgID string) (ai.Settings, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT settings FROM integration_settings
		WHERE org_id = $1::uuid AND provider = $2`, orgID, ProviderAI).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return ai.DefaultSettings(), nil
	}
	if err != nil {
		return ai.Settings{}, fmt.Errorf("load ai settings: %w", err)
	}

	settings := ai.DefaultSettings()
	if err := json.Unmarshal(raw, &settings); err != nil {
		return ai.Settings{}, fmt.Errorf("decode ai settings: %w", err)
	}
	return ai.NormalizeSettings(settings), nil
}

// SaveAISettings upserts the org's AI gateway configuration.
//
// The value is normalized before it is written, not only on read: an operator
// who saves a negative timeout should not see the console echo it back and then
// have the gateway silently use a different number. What is stored is what runs.
func (s *Store) SaveAISettings(ctx context.Context, orgID string, settings ai.Settings) (ai.Settings, error) {
	settings = ai.NormalizeSettings(settings)
	raw, err := json.Marshal(settings)
	if err != nil {
		return ai.Settings{}, fmt.Errorf("encode ai settings: %w", err)
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO integration_settings (org_id, provider, settings, updated_at)
		VALUES ($1::uuid, $2, $3, NOW())
		ON CONFLICT (org_id, provider)
		DO UPDATE SET settings = EXCLUDED.settings, updated_at = NOW()`,
		orgID, ProviderAI, raw); err != nil {
		return ai.Settings{}, fmt.Errorf("save ai settings: %w", err)
	}
	settings.UpdatedAt = time.Now().UTC()
	return settings, nil
}

// RecordAITest stores the outcome of a connectivity test so the console shows a
// result that survives a reload.
//
// The test writes only the three LastTest* fields onto the *stored* row rather
// than saving the settings the test ran against: a Test must never silently
// commit an unsaved form. An operator who probes a candidate endpoint and then
// navigates away has changed nothing, which is what "Test" implies.
func (s *Store) RecordAITest(ctx context.Context, orgID string, ok bool, testErr string) error {
	settings, err := s.GetAISettings(ctx, orgID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	settings.LastTestAt = &now
	settings.LastTestOK = ok
	settings.LastTestError = testErr
	_, err = s.SaveAISettings(ctx, orgID, settings)
	return err
}
