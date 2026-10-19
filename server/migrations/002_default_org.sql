-- Default organization + uniqueness so the server can resolve its org
-- idempotently without races.
ALTER TABLE organizations ADD CONSTRAINT organizations_name_key UNIQUE (name);

INSERT INTO organizations (name) VALUES ('default') ON CONFLICT (name) DO NOTHING;
