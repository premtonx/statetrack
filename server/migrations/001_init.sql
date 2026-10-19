CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE hosts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    os_family TEXT NOT NULL, -- 'linux' | 'windows'
    os_version TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    clock_offset_ms BIGINT NOT NULL DEFAULT 0,
    forensic_until TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'online',
    UNIQUE(org_id, hostname)
);

-- Dictionary Table 1: Deduplicated Target Paths / Registry Keys / Package Names
CREATE TABLE targets (
    id BIGSERIAL PRIMARY KEY,
    org_id UUID NOT NULL,
    target_type TEXT NOT NULL,
    path_or_key TEXT NOT NULL,
    UNIQUE(org_id, target_type, path_or_key)
);

-- Dictionary Table 2: Deduplicated Actors
CREATE TABLE actors (
    id BIGSERIAL PRIMARY KEY,
    org_id UUID NOT NULL,
    username TEXT NOT NULL,
    uid_or_sid TEXT NOT NULL,
    login_uid TEXT NOT NULL DEFAULT '',
    UNIQUE(org_id, username, uid_or_sid, login_uid)
);

-- Dictionary Table 3: Deduplicated Processes
CREATE TABLE processes (
    id BIGSERIAL PRIMARY KEY,
    org_id UUID NOT NULL,
    process_name TEXT NOT NULL,
    cmdline_hash TEXT NOT NULL,
    cmdline_sample TEXT NOT NULL,
    UNIQUE(org_id, process_name, cmdline_hash)
);

-- Main Partitioned Events Table (Compact ~90-byte core row)
CREATE TABLE events (
    id UUID NOT NULL,
    org_id UUID NOT NULL,
    host_id UUID NOT NULL,
    parent_event_id UUID,
    occurred_at TIMESTAMPTZ NOT NULL, -- Normalized for clock offset
    impact_level SMALLINT NOT NULL,   -- 1, 2, 3, or 4
    category SMALLINT NOT NULL,
    action SMALLINT NOT NULL,
    target_id BIGINT NOT NULL REFERENCES targets(id),
    actor_id BIGINT REFERENCES actors(id),
    process_id BIGINT REFERENCES processes(id),
    pid INTEGER,
    ppid INTEGER,
    process_lineage TEXT[],
    remote_ip TEXT,
    hash_before TEXT,
    hash_after TEXT,
    version_before TEXT,
    version_after TEXT,
    child_count INTEGER NOT NULL DEFAULT 0,
    summary TEXT NOT NULL,
    inline_diff TEXT,                 -- Populated if diff <= 2048 bytes
    s3_blob_key TEXT,                 -- Populated if diff > 2048 bytes (s3://.../sha256.zst)
    metadata JSONB,
    PRIMARY KEY (occurred_at, id)
) PARTITION BY RANGE (occurred_at);

-- Create initial monthly partitions. Later months are created by the server's
-- partition maintainer (server/internal/storage).
CREATE TABLE events_2026_10 PARTITION OF events
    FOR VALUES FROM ('2026-10-01 00:00:00+00') TO ('2026-11-01 00:00:00+00');
CREATE TABLE events_2026_11 PARTITION OF events
    FOR VALUES FROM ('2026-11-01 00:00:00+00') TO ('2026-12-01 00:00:00+00');

CREATE INDEX idx_events_host_time ON events (org_id, host_id, occurred_at DESC);
CREATE INDEX idx_events_parent ON events (parent_event_id) WHERE parent_event_id IS NOT NULL;
CREATE INDEX idx_events_level_cat ON events (org_id, impact_level, category, occurred_at DESC);

-- Host State Inventory (For Instant Cross-Node Drift Matrix)
CREATE TABLE host_current_state (
    host_id UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    target_id BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    current_hash TEXT NOT NULL,
    current_version TEXT,
    updated_at TIMESTAMPTZ NOT NULL,
    last_event_id UUID NOT NULL,
    PRIMARY KEY (host_id, target_id)
);

-- Integrations Table (Grafana, Slack, PagerDuty, Webhooks)
CREATE TABLE integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider TEXT NOT NULL, -- 'grafana_annotations' | 'slack' | 'webhook'
    endpoint_url TEXT NOT NULL,
    api_token_encrypted TEXT,
    min_impact_level SMALLINT NOT NULL DEFAULT 2,
    enabled BOOLEAN NOT NULL DEFAULT TRUE
);
