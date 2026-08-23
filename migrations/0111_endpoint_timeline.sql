-- +goose Up
-- Phase B / B7 (#669): the durable, per-asset endpoint State Timeline — the append-only, event-time
-- ordered log of endpoint transitions (process/network/file/privilege) that Phase C correlation and
-- retro-hunt read after the raw telemetry that produced them has expired. It holds projected transitions,
-- not raw events (that is the columnar telemetry store) nor delivery bookkeeping (the transport store).
CREATE TABLE endpoint_timeline (
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    asset_id    TEXT NOT NULL,
    event_id    TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    entity_kind TEXT NOT NULL CHECK (entity_kind IN ('process','network','file','identity','container')),
    entity_id   TEXT NOT NULL,
    kind        TEXT NOT NULL,
    summary     TEXT NOT NULL,
    -- One envelope projects to at most one transition, so (tenant, asset, event_id) is the idempotency
    -- key: a re-delivered or replayed envelope is a no-op insert.
    PRIMARY KEY (tenant_id, asset_id, event_id),
    FOREIGN KEY (tenant_id, asset_id) REFERENCES fleet_assets(tenant_id, id)
);
-- Event-time reads for a window on one asset (the retro-hunt access pattern); event_id makes the order
-- total and matches the in-memory (OccurredAt, EventID) tiebreak. event_id is ordered with COLLATE "C"
-- (bytewise) so the SQL order is identical to the Go bytewise tiebreak regardless of the DB's default
-- collation — the same house convention migrations 0047/0052/0054/0107 use for id tiebreaks.
CREATE INDEX idx_endpoint_timeline_window
    ON endpoint_timeline (tenant_id, asset_id, occurred_at, event_id COLLATE "C");
-- Pivot from one entity to its transitions.
CREATE INDEX idx_endpoint_timeline_entity
    ON endpoint_timeline (tenant_id, asset_id, entity_id, occurred_at);
CALL synapse_enable_tenant_rls('endpoint_timeline');

-- The State Timeline is a chain-of-custody substrate Phase C reads: append-only (golden rule 6), matching
-- the evidence/audit tables. synapse_forbid_mutation is defined in migration 0033.
CREATE TRIGGER endpoint_timeline_append_only
    BEFORE UPDATE OR DELETE ON endpoint_timeline
    FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER endpoint_timeline_no_truncate
    BEFORE TRUNCATE ON endpoint_timeline
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

-- +goose Down
DROP TRIGGER IF EXISTS endpoint_timeline_no_truncate ON endpoint_timeline;
DROP TRIGGER IF EXISTS endpoint_timeline_append_only ON endpoint_timeline;
DROP TABLE endpoint_timeline;
