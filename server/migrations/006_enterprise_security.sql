-- Enterprise security, identity, RBAC and the control-plane audit trail.
--
-- Four concerns, all serving one enterprise requirement: a CISO must be able to
-- answer "who can change what, and who changed it?" from the database alone.
--
--   users                    -- console identities and their role
--   api_keys                 -- scoped machine credentials (Checkmk, Zabbix, CI)
--   enrollment_tokens        -- the bootstrap secret an agent installs with
--   control_plane_audit_logs -- append-only record of every administrative change
--
-- Secrets are never stored in a form that can be replayed: passwords are
-- PBKDF2-HMAC-SHA256, and API keys / enrollment tokens are single-round SHA-256
-- of a high-entropy random value. A hash-only column means a database dump does
-- not hand an attacker working credentials. The console-facing secret is shown
-- exactly once, at creation, and is unrecoverable afterwards.
--
-- These tables are org-scoped like every other table so a future multi-tenant
-- deployment does not need a data migration, but the role model is global:
-- `users.role` is the grant, and `control_plane_audit_logs` is deliberately
-- org-less because a control-plane action (SSO change, key revocation) is an
-- act on the platform, not on one tenant's data.

CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email         TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL DEFAULT '',
    -- RBAC grant. 'admin' is full access, 'operator' is SRE write access,
    -- 'policy_admin' owns policy/tuning, 'auditor' is strictly read-only and is
    -- enforced by middleware rather than only hidden in the UI.
    role          TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'policy_admin', 'auditor')),
    password_hash TEXT,
    totp_secret   TEXT,
    totp_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
    auth_provider TEXT NOT NULL DEFAULT 'local' CHECK (auth_provider IN ('local', 'oidc')),
    -- Recorded so "who is actually using this account?" is answerable, and a
    -- dormant admin account is visible rather than assumed active.
    last_login_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_org_role ON users (org_id, role);

-- Scoped machine credentials. The key itself (`st_live_...`) is only ever
-- returned by the create endpoint; `key_hash` is what authenticates a request.
CREATE TABLE IF NOT EXISTS api_keys (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    -- Display-only prefix, so an operator can identify a key in the UI and in
    -- logs ("which key is being used?") without holding the secret.
    key_prefix   TEXT NOT NULL,
    key_hash     TEXT NOT NULL UNIQUE,
    role         TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'policy_admin', 'auditor')),
    -- Fine-grained scopes such as 'read:summary' or 'admin:write'. A key with
    -- read scopes can only ever be used for reads even if its role would allow
    -- writes, so a monitoring poller's key cannot be turned into a write path.
    scopes       TEXT[] NOT NULL DEFAULT '{}',
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys (org_id, created_at DESC);
-- Authentication looks a key up by hash on every request, so this index is the
-- difference between an O(1) probe and a sequential scan of every key.
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys (key_hash);

-- Agent enrollment. A token is a bearer secret that lets a host join the fleet,
-- so it is capped (`max_uses`) and time-boxed (`expires_at`) by default.
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    token_prefix TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    -- NULL means unlimited; the console defaults to a finite cap because an
    -- unbounded enrollment token is a fleet-takeover primitive.
    max_uses    INT,
    uses_count  INT NOT NULL DEFAULT 0,
    expires_at  TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_org
    ON enrollment_tokens (org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_hash ON enrollment_tokens (token_hash);

-- Immutable administrative audit trail. Append-only by convention and by
-- grant: the application only ever INSERTs, and the console only reads.
--
-- Deliberately NOT org-scoped: a control-plane action is an act on the
-- platform, and an auditor reviewing "who changed SSO?" wants one timeline
-- rather than a per-tenant slice.
CREATE TABLE IF NOT EXISTS control_plane_audit_logs (
    id          BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_email TEXT NOT NULL,
    actor_role  TEXT NOT NULL,
    -- Dotted verb.noun, e.g. 'rule.applied', 'integration.updated',
    -- 'apikey.created', 'agent.revoked', 'auth.login', 'auth.2fa_enabled'.
    action      TEXT NOT NULL,
    target      TEXT NOT NULL DEFAULT '',
    source_ip   TEXT NOT NULL DEFAULT '',
    -- Free-form structured context. JSONB rather than columns because the
    -- detail differs per action and an audit row must never block a write by
    -- lacking a column.
    details     JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- The console and any SIEM shipper read newest-first; the descending index
-- keeps "show me the last 200 control-plane changes" a bounded index scan.
CREATE INDEX IF NOT EXISTS idx_control_plane_audit_time
    ON control_plane_audit_logs (occurred_at DESC, id DESC);
-- "What has this actor done?" is the other question an auditor asks first.
CREATE INDEX IF NOT EXISTS idx_control_plane_audit_actor
    ON control_plane_audit_logs (actor_email, occurred_at DESC);
-- ...and "who touched the GitHub SSO config?" is the third.
CREATE INDEX IF NOT EXISTS idx_control_plane_audit_action
    ON control_plane_audit_logs (action, occurred_at DESC);

