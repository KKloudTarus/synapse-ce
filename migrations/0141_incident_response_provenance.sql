-- +goose Up
-- Incident response recovery links and endpoint source provenance for independent verification.
ALTER TABLE endpoint_timeline
    ADD COLUMN source_agent_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN source_agent_session_id TEXT NOT NULL DEFAULT '';
CREATE INDEX endpoint_timeline_source_idx
    ON endpoint_timeline (tenant_id, asset_id, source_agent_id, source_agent_session_id, occurred_at, event_id)
    WHERE source_agent_id <> '' AND source_agent_session_id <> '';

CREATE TABLE incident_response_links (
    tenant_id          TEXT NOT NULL REFERENCES tenants(id),
    incident_id        TEXT NOT NULL,
    action_id          TEXT NOT NULL,
    source_request_seq INT NOT NULL CHECK (source_request_seq >= 1),
    requested_at       TIMESTAMPTZ NOT NULL,
    verified_at        TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, incident_id, action_id),
    UNIQUE (tenant_id, incident_id, source_request_seq),
    FOREIGN KEY (tenant_id, incident_id, source_request_seq)
        REFERENCES incident_events(tenant_id, incident_id, seq) ON DELETE RESTRICT
);
CREATE INDEX idx_incident_response_links_pending
    ON incident_response_links (tenant_id, incident_id COLLATE "C", action_id COLLATE "C")
    WHERE verified_at IS NULL;
CALL synapse_enable_tenant_rls('incident_response_links');

-- Immutable canonical merge proof for #676. Source and target intentionally have no mutable incident table
-- foreign key: incident identity is an append-only event stream.
CREATE TABLE incident_merge_edges (
    tenant_id        TEXT NOT NULL REFERENCES tenants(id),
    source_incident_id TEXT NOT NULL,
    canonical_incident_id TEXT NOT NULL,
    bridge_key       TEXT NOT NULL,
    source_event_seq INT NOT NULL CHECK (source_event_seq >= 1),
    actor            TEXT NOT NULL,
    merged_at        TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, source_incident_id),
    UNIQUE (tenant_id, source_incident_id, source_event_seq),
    FOREIGN KEY (tenant_id, source_incident_id, source_event_seq)
        REFERENCES incident_events(tenant_id, incident_id, seq) ON DELETE RESTRICT,
    CHECK (source_incident_id <> canonical_incident_id)
);
CREATE INDEX idx_incident_merge_edges_target
    ON incident_merge_edges (tenant_id, canonical_incident_id COLLATE "C");
CALL synapse_enable_tenant_rls('incident_merge_edges');
CREATE TRIGGER incident_merge_edges_immutable
    BEFORE UPDATE OR DELETE ON incident_merge_edges
    FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER incident_merge_edges_no_truncate
    BEFORE TRUNCATE ON incident_merge_edges
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

-- +goose Down
DROP TRIGGER IF EXISTS incident_merge_edges_no_truncate ON incident_merge_edges;
DROP TRIGGER IF EXISTS incident_merge_edges_immutable ON incident_merge_edges;
DROP TABLE incident_merge_edges;
DROP TABLE incident_response_links;
DROP INDEX endpoint_timeline_source_idx;
ALTER TABLE endpoint_timeline
    DROP COLUMN source_agent_session_id,
    DROP COLUMN source_agent_id;
