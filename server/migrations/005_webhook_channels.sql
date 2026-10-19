-- Outbound notification channel configuration and the delivery audit log.
--
-- The `integrations` table (001_init.sql) already models one row per channel:
-- provider, endpoint_url, token and min_impact_level. This migration adds the
-- per-provider knobs the Integrations hub exposes, and the delivery log that
-- backs its "Recent Webhook Deliveries" table.
--
-- Why columns rather than the JSONB blob used by integration_settings: the
-- pusher reads these on every notification and filters on `enabled`, so they
-- are query predicates rather than opaque operator input. JSONB would push that
-- filtering into Go and make "which channels are live?" unqueryable in SQL.

-- Slack's channel label, PagerDuty's severity override. Both optional and
-- provider-specific, but a single TEXT is enough to carry either.
ALTER TABLE integrations
    ADD COLUMN IF NOT EXISTS label TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS notify_l1 BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS notify_storms BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- The hub saves by provider ("save my Teams card"), so (org, provider) has to
-- be unique for the upsert to be well-defined. A partial index would not do:
-- two rows for one provider would mean two deliveries per change.
CREATE UNIQUE INDEX IF NOT EXISTS idx_integrations_org_provider
    ON integrations (org_id, provider);

-- One row per delivery attempt, so the hub can show whether a channel actually
-- works rather than only whether it is configured. Retention is the same as the
-- rest of the operational tables: pruned by the partition maintainer's window,
-- not here.
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id           BIGSERIAL PRIMARY KEY,
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider     TEXT NOT NULL,
    -- The target is recorded so "which URL is failing?" is answerable; the HMAC
    -- secret is not, because the log is readable by anyone with console access.
    endpoint_url TEXT NOT NULL DEFAULT '',
    event_id     UUID,
    status_code  INT NOT NULL DEFAULT 0,
    latency_ms   INT NOT NULL DEFAULT 0,
    success      BOOLEAN NOT NULL DEFAULT FALSE,
    attempts     INT NOT NULL DEFAULT 0,
    -- Marks a row produced by the "Send Test" buttons, so a scheduled canary is
    -- distinguishable from a real change notification.
    sample       BOOLEAN NOT NULL DEFAULT FALSE,
    error        TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The hub reads the newest N per org; the descending index keeps that a bounded
-- index scan. The provider index backs the per-card "last delivery" badge.
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_org_time
    ON webhook_deliveries (org_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_org_provider_time
    ON webhook_deliveries (org_id, provider, created_at DESC);
