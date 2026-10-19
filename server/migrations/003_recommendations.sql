-- Smart auto-discovery & granular policy overrides (asset tiering).
--
-- host_recommendations holds the workloads each agent auto-discovered on its
-- host. The console surfaces pending rows as onboarding recommendations; an
-- accepted recommendation is materialized into a host_policy_rules row that is
-- pushed down to the agent over gRPC.
--
-- The unique key is (host_id, workload_type, name, config_path) so a heartbeat
-- that re-reports the same workload updates the existing row instead of
-- creating duplicate recommendations.

CREATE TABLE host_recommendations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    host_id UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    workload_type TEXT NOT NULL,
    name TEXT NOT NULL,
    config_path TEXT NOT NULL,
    suggested_level SMALLINT NOT NULL DEFAULT 3,
    suggested_diff BOOLEAN NOT NULL DEFAULT TRUE,
    reason TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'applied' | 'dismissed'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at TIMESTAMPTZ,
    UNIQUE (host_id, workload_type, name, config_path)
);

CREATE INDEX idx_host_recommendations_pending
    ON host_recommendations (org_id, status, updated_at DESC);
CREATE INDEX idx_host_recommendations_host
    ON host_recommendations (host_id, status);

-- host_policy_rules is the host's active granular policy set. It is the source
-- of truth for what the server pushes to the agent on every batch ack.
CREATE TABLE host_policy_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    host_id UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    pattern TEXT NOT NULL DEFAULT '',
    level SMALLINT NOT NULL DEFAULT 3,
    diff BOOLEAN NOT NULL DEFAULT TRUE,
    tags TEXT[] NOT NULL DEFAULT '{}',
    source_recommendation_id UUID REFERENCES host_recommendations(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (host_id, name)
);

CREATE INDEX idx_host_policy_rules_host ON host_policy_rules (host_id);
