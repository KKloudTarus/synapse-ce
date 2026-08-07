-- +goose Up
-- Certificate identity for fleet agents (#408): a SHA-256 certificate fingerprint (the agent's
-- cryptographic identity issued from the control-plane CA via a CSR) plus revocation attribution.
-- Also widens the agent state set to include 'stale' (last-seen-based, computed by fleet coverage).
ALTER TABLE fleet_agents ADD COLUMN fingerprint TEXT NOT NULL DEFAULT '';
ALTER TABLE fleet_agents ADD COLUMN revoked_at TIMESTAMPTZ;
ALTER TABLE fleet_agents ADD COLUMN revoked_by TEXT NOT NULL DEFAULT '';
ALTER TABLE fleet_agents ADD COLUMN revoke_reason TEXT NOT NULL DEFAULT '';

ALTER TABLE fleet_agents DROP CONSTRAINT fleet_agents_state_check;
ALTER TABLE fleet_agents ADD CONSTRAINT fleet_agents_state_check CHECK (state IN ('active', 'stale', 'revoked'));

-- Fingerprint auth resolves the agent by (tenant, fingerprint); a partial index skips agents with
-- no certificate issued yet. Tenant is read from the verified certificate's subject, so this stays
-- an RLS-scoped lookup.
CREATE INDEX idx_fleet_agents_fingerprint ON fleet_agents (tenant_id, fingerprint) WHERE fingerprint <> '';

-- +goose Down
DROP INDEX idx_fleet_agents_fingerprint;
ALTER TABLE fleet_agents DROP CONSTRAINT fleet_agents_state_check;
ALTER TABLE fleet_agents ADD CONSTRAINT fleet_agents_state_check CHECK (state IN ('active', 'revoked'));
ALTER TABLE fleet_agents DROP COLUMN revoke_reason;
ALTER TABLE fleet_agents DROP COLUMN revoked_by;
ALTER TABLE fleet_agents DROP COLUMN revoked_at;
ALTER TABLE fleet_agents DROP COLUMN fingerprint;
