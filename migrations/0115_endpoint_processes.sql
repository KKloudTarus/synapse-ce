-- +goose Up
-- Phase B / B5 (#667 tail): the per-host process snapshot projection — "what is running on this host right
-- now" — the running side of running-vs-installed exposure (X5 #634). It is a MUTABLE projection (a
-- re-observation upserts a process in place, flipping running=false when it exits), so no append-only
-- trigger; one row per (tenant, asset, entity). asset_id is the HOST/fleet asset the process runs on.
CREATE TABLE endpoint_processes (
    tenant_id    TEXT NOT NULL,
    asset_id     TEXT NOT NULL,
    entity_id    TEXT NOT NULL,
    pid          INT NOT NULL CHECK (pid >= 0),
    comm         TEXT NOT NULL DEFAULT '',
    path         TEXT NOT NULL DEFAULT '',
    running      BOOLEAN NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, asset_id, entity_id),
    -- composite FK to the host asset (fleet_assets has UNIQUE (tenant_id, id) from migration 0058).
    FOREIGN KEY (tenant_id, asset_id) REFERENCES fleet_assets (tenant_id, id) ON DELETE CASCADE
);
-- Running processes are queried per asset; index that path (entity_id COLLATE "C" so the SQL order matches
-- the memory twin's Go bytewise ordering).
CREATE INDEX idx_endpoint_processes_running
    ON endpoint_processes (tenant_id, asset_id, entity_id COLLATE "C")
    WHERE running = true;
CALL synapse_enable_tenant_rls('endpoint_processes');

-- +goose Down
DROP TABLE endpoint_processes;
