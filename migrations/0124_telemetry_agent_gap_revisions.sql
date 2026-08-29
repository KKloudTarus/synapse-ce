-- +goose Up
-- Preserve every authenticated signed agent-origin gap snapshot. The existing
-- telemetry_agent_gaps table remains the mutable latest/coalesced projection;
-- this table is the immutable accepted-input ledger used for restart audit.
CREATE TABLE telemetry_agent_gap_revisions (
    tenant_id                 TEXT NOT NULL REFERENCES tenants(id),
    signed_content_digest     TEXT NOT NULL,
    gap_id                    TEXT NOT NULL,
    revision                  BIGINT NOT NULL CHECK (revision > 0),
    authenticated_agent_id    TEXT NOT NULL,
    agent_id                  TEXT NOT NULL,
    host_id                   TEXT NOT NULL,
    agent_session_id          TEXT NOT NULL CHECK (btrim(agent_session_id) <> ''),
    asset_id                  TEXT NOT NULL,
    stream_id                 TEXT NOT NULL,
    priority                  INT NOT NULL CHECK (priority BETWEEN 0 AND 3),
    epoch                     BIGINT NOT NULL CHECK (epoch >= 1),
    known_sequence            BOOLEAN NOT NULL,
    from_sequence             BIGINT,
    to_sequence               BIGINT,
    count                     BIGINT NOT NULL CHECK (count >= 1),
    reason                    TEXT NOT NULL CHECK (reason IN ('quota_eviction','quota_backpressure','corrupt_frame','torn_write','io_failure','unsynced_tail','state_recovery')),
    from_at                   TIMESTAMPTZ NOT NULL,
    to_at                     TIMESTAMPTZ NOT NULL CHECK (to_at >= from_at),
    from_at_unix_nano         BIGINT NOT NULL,
    to_at_unix_nano           BIGINT NOT NULL CHECK (to_at_unix_nano >= from_at_unix_nano),
    protocol_version          INT NOT NULL CHECK (protocol_version >= 1),
    key_id                    TEXT NOT NULL CHECK (btrim(key_id) <> ''),
    signature                 TEXT NOT NULL CHECK (btrim(signature) <> ''),
    received_at               TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, signed_content_digest),
    UNIQUE (tenant_id, gap_id, revision),
    CONSTRAINT telemetry_agent_gap_revision_projection_fk
        FOREIGN KEY (tenant_id, gap_id) REFERENCES telemetry_agent_gaps(tenant_id, gap_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, agent_id) REFERENCES fleet_agents(tenant_id, id),
    FOREIGN KEY (tenant_id, asset_id) REFERENCES fleet_assets(tenant_id, id),
    CONSTRAINT telemetry_agent_gap_revisions_digest_sha256
        CHECK (signed_content_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT telemetry_agent_gap_revisions_authenticated_agent
        CHECK (authenticated_agent_id = agent_id),
    CONSTRAINT telemetry_agent_gap_revisions_authenticated_host
        CHECK (host_id = authenticated_agent_id),
    CONSTRAINT telemetry_agent_gap_revisions_sequence_shape CHECK (
        (known_sequence AND from_sequence IS NOT NULL AND from_sequence >= 1 AND to_sequence IS NOT NULL AND to_sequence >= from_sequence AND count = to_sequence - from_sequence + 1)
        OR
        (NOT known_sequence AND from_sequence IS NULL AND to_sequence IS NULL)
    )
);
CREATE INDEX idx_telemetry_agent_gap_revisions_gap
    ON telemetry_agent_gap_revisions (tenant_id, gap_id, received_at);
CREATE INDEX idx_telemetry_agent_gap_revisions_coverage
    ON telemetry_agent_gap_revisions (tenant_id, asset_id, priority, from_at, to_at);
CREATE INDEX idx_telemetry_agent_gap_revisions_stream
    ON telemetry_agent_gap_revisions (tenant_id, agent_id, stream_id, epoch, received_at);
CALL synapse_enable_tenant_rls('telemetry_agent_gap_revisions');

CREATE TRIGGER telemetry_agent_gap_revisions_append_only
    BEFORE UPDATE OR DELETE ON telemetry_agent_gap_revisions
    FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER telemetry_agent_gap_revisions_no_truncate
    BEFORE TRUNCATE ON telemetry_agent_gap_revisions
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();


-- +goose Down
-- Signed gap history is custody evidence and must not be silently discarded.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM telemetry_agent_gap_revisions) THEN
        RAISE EXCEPTION 'cannot roll back 0124: telemetry agent gap revision history exists';
    END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS telemetry_agent_gap_revisions_no_truncate ON telemetry_agent_gap_revisions;
DROP TRIGGER IF EXISTS telemetry_agent_gap_revisions_append_only ON telemetry_agent_gap_revisions;
DROP TABLE telemetry_agent_gap_revisions;
