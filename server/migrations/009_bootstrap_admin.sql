-- Bootstrap identity seeding.
--
-- The schema itself lives in 006_enterprise_security.sql. This file exists so a
-- first boot creates a *usable* console (one administrator) without inventing a
-- demo fleet, demo audit history or demo credentials.
--
-- Why this is a migration rather than application code: the server needs a
-- password hash produced by its own KDF (PBKDF2-HMAC-SHA256, 210k rounds), and
-- SQL cannot compute that. The placeholder below is therefore a one-time marker
-- row that the server replaces on boot with a real hash — see
-- `api.EnsureBootstrapAdmin`. The marker is a random-looking, clearly invalid
-- hash so it can never authenticate: VerifyPassword rejects it structurally.
--
-- The account is created only when the whole users table is empty. An operator
-- who deletes the bootstrap admin has made a deliberate choice, and a migration
-- that resurrected it on the next restart would be a security hole rather than a
-- convenience.

INSERT INTO users (org_id, email, name, role, password_hash, auth_provider)
SELECT o.id, 'admin@localhost', 'Administrator', 'admin', 'bootstrap-pending', 'local'
FROM organizations o WHERE o.name = 'default'
  AND NOT EXISTS (SELECT 1 FROM users)
ON CONFLICT (email) DO NOTHING;
