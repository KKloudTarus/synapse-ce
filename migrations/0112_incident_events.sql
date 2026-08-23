-- +goose Up
-- Phase C / C7 (#681): the event-sourced incident log. It is the source of truth for an incident (the
-- projection is folded from it by incident.Project) and is APPEND-ONLY (golden rule 6), like the evidence
-- and audit ledgers. One row per event; (tenant, incident, seq) is the position, and its uniqueness is
-- what gives optimistic-concurrency appends (two writers cannot both claim the next position).
CREATE TABLE incident_events (
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    incident_id TEXT NOT NULL,
    seq         INT NOT NULL CHECK (seq >= 1),
    kind        TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    actor       TEXT NOT NULL,
    -- asset_id is set on the Created event (the incident's asset), empty otherwise, so incidents can be
    -- listed by asset without folding every log.
    asset_id TEXT NOT NULL DEFAULT '',
    -- payload is the full incident.IncidentEvent as JSON; it is the authoritative event content that
    -- incident.Project folds. The columns above are for ordering, integrity, and querying.
    payload JSONB NOT NULL,
    PRIMARY KEY (tenant_id, incident_id, seq)
);
-- incident_id is ordered COLLATE "C" (bytewise) so the SQL list order matches the memory twin's Go
-- bytewise ordering regardless of the DB's default collation (house convention; see migration 0111).
CREATE INDEX idx_incident_events_by_asset
    ON incident_events (tenant_id, asset_id, incident_id COLLATE "C")
    WHERE asset_id <> '';
CALL synapse_enable_tenant_rls('incident_events');

-- Append-only: the incident log is chain-of-custody; reject UPDATE/DELETE/TRUNCATE like evidence/audit.
-- synapse_forbid_mutation is defined in migration 0033.
CREATE TRIGGER incident_events_append_only
    BEFORE UPDATE OR DELETE ON incident_events
    FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER incident_events_no_truncate
    BEFORE TRUNCATE ON incident_events
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

-- +goose Down
DROP TRIGGER IF EXISTS incident_events_no_truncate ON incident_events;
DROP TRIGGER IF EXISTS incident_events_append_only ON incident_events;
DROP TABLE incident_events;
