-- ITSM change-ticket correlation: the compliance half of the product.
--
-- The question this table answers is not "what changed?" (the events table
-- already does that) but "was this change *authorised*?". An enterprise with an
-- ITIL change process has Jira or ServiceNow holding the approvals; StateTrack
-- holds the mutations. This table is the join between them.
--
-- Why a local mirror rather than a live API call on every change:
--
--   * The product's target deployments are air-gapped. A production network may
--     have no route to the ITSM instance at all, and a compliance control that
--     silently degrades when a SaaS endpoint is unreachable is worse than no
--     control — it produces "unapproved" verdicts for correctly-approved changes.
--   * Correlating at ingest time would put an external HTTP call on the agent's
--     write path. An outage at Jira would then become data loss in StateTrack.
--   * The correlation becomes a pure function over local state, which is what
--     makes the decision table exhaustively testable.
--
-- Tickets arrive by whichever route the site has: a scheduled sync job, an
-- inbound webhook from Jira/ServiceNow, a CSV import, or an operator typing one
-- in by hand. All four write the same rows.
--
-- Scope (`hosts` / `environments` / `paths`) is three arrays rather than a
-- normalized child table because a ticket is read as a whole and is never
-- joined on: matching happens in Go (internal/itsm), and the arrays are exactly
-- the shape that correlation rule consumes. An empty array is a wildcard.
--
-- Window (`window_start` / `window_end`) is load-bearing, not informational: an
-- approved 30-minute maintenance window is not a permanent licence to edit
-- production, so a mutation outside it does not correlate.
CREATE TABLE IF NOT EXISTS change_tickets (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- Source system, so the console can show a Jira vs ServiceNow vs
    -- hand-entered badge. Never changes the matching rules.
    kind          TEXT NOT NULL CHECK (kind IN ('jira', 'servicenow', 'manual')),
    -- The reference an engineer recognises and pastes into a commit message:
    -- 'CHG-1042' (ServiceNow) or 'OPS-8813' (Jira).
    ref           TEXT NOT NULL,
    -- Normalized status ('approved', 'in_progress', 'rejected', …). Stored
    -- post-normalization so the correlation never has to know that ServiceNow
    -- calls an approval "authorize" and Jira calls it "In Progress".
    status        TEXT NOT NULL DEFAULT 'unknown',
    summary       TEXT NOT NULL DEFAULT '',
    -- Deep link back to the ticket. Optional: an air-gapped mirror has nowhere
    -- to link to, and a fabricated URL is worse than no URL.
    url           TEXT NOT NULL DEFAULT '',
    hosts         TEXT[] NOT NULL DEFAULT '{}',
    environments  TEXT[] NOT NULL DEFAULT '{}',
    paths         TEXT[] NOT NULL DEFAULT '{}',
    window_start  TIMESTAMPTZ,
    window_end    TIMESTAMPTZ,
    requested_by  TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- A reference is unique per org: two rows claiming CHG-1042 would make the
    -- correlation result depend on row order, which is exactly the kind of
    -- non-determinism a compliance verdict cannot have.
    UNIQUE (org_id, ref)
);

-- Correlation loads the whole ticket set for an org (it is small: hundreds of
-- rows, not millions), so this index serves the only access path there is.
CREATE INDEX IF NOT EXISTS idx_change_tickets_org ON change_tickets (org_id, updated_at DESC);

-- The console's compliance view ("show me every unauthorised production edit")
-- filters by status and orders newest-first.
CREATE INDEX IF NOT EXISTS idx_change_tickets_org_status
    ON change_tickets (org_id, status, updated_at DESC);

-- --------------------------------------------------------------------------- --
-- Seed: a realistic change-control state on first boot.
--
-- Three tickets exercise the three verdicts the badge can produce:
--   CHG-1042  approved + in window        -> "CHG-1042 · Approved"
--   CHG-1108  pending (never approved)    -> "Unapproved Change"
--   OPS-8813  approved, scoped elsewhere  -> no match (fleet-wide coverage)
--
-- The windows are relative to NOW() so the demo does not rot: an approved
-- window that closed last month would make every seeded change read as
-- "unapproved", which is the right behaviour but a poor first impression.
-- --------------------------------------------------------------------------- --

INSERT INTO change_tickets
    (org_id, kind, ref, status, summary, url, hosts, environments, paths,
     window_start, window_end, requested_by)
SELECT o.id, 'servicenow', 'CHG-1042', 'approved',
       'Rotate nginx upstream pool and reload web tier',
       'https://acme.service-now.com/change_request.do?sys_id=chg1042',
       ARRAY['prod-web-01', 'prod-web-02'], ARRAY['production'],
       ARRAY['/etc/nginx/**'],
       NOW() - INTERVAL '2 hours', NOW() + INTERVAL '6 hours', 'sarah@statetrack.io'
FROM organizations o WHERE o.name = 'default'
ON CONFLICT (org_id, ref) DO NOTHING;

INSERT INTO change_tickets
    (org_id, kind, ref, status, summary, url, hosts, environments, paths,
     window_start, window_end, requested_by)
SELECT o.id, 'jira', 'OPS-8813', 'approved',
       'Emergency SQL Server log level reduction',
       'https://acme.atlassian.net/browse/OPS-8813',
       ARRAY[]::TEXT[], ARRAY['production'],
       ARRAY['HKLM\\Software\\Company\\App\\**'],
       NOW() - INTERVAL '1 hour', NOW() + INTERVAL '3 hours', 'pk@statetrack.io'
FROM organizations o WHERE o.name = 'default'
ON CONFLICT (org_id, ref) DO NOTHING;

INSERT INTO change_tickets
    (org_id, kind, ref, status, summary, url, hosts, environments, paths,
     window_start, window_end, requested_by)
SELECT o.id, 'servicenow', 'CHG-1108', 'requested',
       'Kubernetes prod namespace config rollout (awaiting CAB approval)',
       'https://acme.service-now.com/change_request.do?sys_id=chg1108',
       ARRAY['prod-k8s-01'], ARRAY['production'],
       ARRAY['ConfigMap/**', 'Secret/**'],
       NOW() - INTERVAL '30 minutes', NOW() + INTERVAL '4 hours', 'sarah@statetrack.io'
FROM organizations o WHERE o.name = 'default'
ON CONFLICT (org_id, ref) DO NOTHING;
