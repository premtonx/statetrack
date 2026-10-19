-- Runtime-editable integration settings and the outbound annotation log.
--
-- Two separate concerns:
--
--   integration_settings  — the operator-editable knobs the console renders
--                           (Grafana URL, level push toggles, annotation
--                           template). Kept as JSONB rather than columns so a
--                           new provider or a new toggle does not need a
--                           migration; the API layer owns the shape and
--                           validates it on write.
--
--   annotation_log        — what was actually dispatched, so the console's
--                           "Recent Annotations" table reflects real sends
--                           instead of a hardcoded list, and so an operator can
--                           tell "Grafana is down" from "nothing happened".

CREATE TABLE IF NOT EXISTS integration_settings (
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider   TEXT NOT NULL,
    settings   JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, provider)
);

-- Outbound annotation attempts. One row per delivery, so the table doubles as
-- the delivery audit trail: an operator can distinguish "Grafana rejected it"
-- from "the event never triggered an annotation".
CREATE TABLE IF NOT EXISTS annotation_log (
    id          BIGSERIAL PRIMARY KEY,
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    event_id    UUID,
    hostname    TEXT NOT NULL,
    impact_level SMALLINT NOT NULL,
    summary     TEXT NOT NULL,
    text        TEXT NOT NULL,
    tags        TEXT[] NOT NULL DEFAULT '{}',
    dashboard   TEXT,
    status      TEXT NOT NULL,           -- 'delivered' | 'failed' | 'skipped'
    error       TEXT,
    dispatched_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The console reads the newest N per org; the descending index makes that a
-- bounded index scan rather than a sort over the whole log.
CREATE INDEX IF NOT EXISTS idx_annotation_log_org_time
    ON annotation_log (org_id, dispatched_at DESC);

-- The Grafana annotations query filters by $host over a time range.
CREATE INDEX IF NOT EXISTS idx_annotation_log_host_time
    ON annotation_log (org_id, hostname, dispatched_at DESC);
