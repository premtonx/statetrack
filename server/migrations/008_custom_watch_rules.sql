-- Custom watched targets authored in the console.
--
-- A watched target is a policy rule: the same row both classifies an event and
-- tells the surgical watchers *what* to track. The console's rule builder is
-- therefore a UI over host_policy_rules rather than a second, parallel
-- configuration store — a rule that is not pushed to the agent would be a
-- button that does nothing.
--
-- Two changes make fleet-wide targets expressible:
--
--   * host_id becomes nullable. NULL means "every host in the organisation",
--     which is what the builder's "All Hosts" option has to mean. Fanning the
--     rule out to the hosts that exist at creation time would silently skip
--     every host enrolled afterwards.
--
--   * created_by records the authoring identity. The control-plane audit log
--     already records the action; this column keeps "who owns this rule?" on
--     the row itself, so the list view can show it without joining the trail.

ALTER TABLE host_policy_rules ALTER COLUMN host_id DROP NOT NULL;

ALTER TABLE host_policy_rules ADD COLUMN IF NOT EXISTS created_by TEXT NOT NULL DEFAULT '';

-- A per-host rule name is unique per host (the existing constraint). Fleet-wide
-- rows all have a NULL host_id, and Postgres treats NULLs as distinct in a
-- UNIQUE constraint, so the fleet scope needs its own partial index or the same
-- target could be created twice.
CREATE UNIQUE INDEX IF NOT EXISTS idx_host_policy_rules_fleet_name
    ON host_policy_rules (org_id, name)
    WHERE host_id IS NULL;

-- The list view filters by scope and target type, and the push path reads every
-- fleet-wide row on each batch ack.
CREATE INDEX IF NOT EXISTS idx_host_policy_rules_org_type
    ON host_policy_rules (org_id, target_type);
