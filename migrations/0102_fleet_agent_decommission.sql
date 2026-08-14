-- +goose Up
-- Clean-uninstall decommission for fleet agents (#412, AC 11): a terminal, self-reported state distinct
-- from operator 'revoked' and from last-seen 'stale', so the control plane shows an orderly removal
-- rather than letting a removed agent decay into stale. decommissioned_at is the self-reported time
-- (nullable; no attributed actor — the agent reports its own decommission over its authenticated
-- credential during uninstall).
ALTER TABLE fleet_agents ADD COLUMN decommissioned_at TIMESTAMPTZ;

ALTER TABLE fleet_agents DROP CONSTRAINT fleet_agents_state_check;
ALTER TABLE fleet_agents ADD CONSTRAINT fleet_agents_state_check CHECK (state IN ('active', 'stale', 'revoked', 'decommissioned'));

-- +goose Down
ALTER TABLE fleet_agents DROP CONSTRAINT fleet_agents_state_check;
ALTER TABLE fleet_agents ADD CONSTRAINT fleet_agents_state_check CHECK (state IN ('active', 'stale', 'revoked'));
ALTER TABLE fleet_agents DROP COLUMN decommissioned_at;
