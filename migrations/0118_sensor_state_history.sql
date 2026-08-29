-- +goose Up
-- Signed P0 sensor-state and coverage observations. These are append-only facts:
-- a retry may prove the same report again, but cannot revise an accepted observation.
CREATE TABLE sensor_state_history (
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    report_id       TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    asset_id        TEXT NOT NULL,
    host_id         TEXT NOT NULL,
    record_kind     TEXT NOT NULL CHECK (record_kind IN ('coverage', 'sensor_state')),
    observed_at     TIMESTAMPTZ NOT NULL,
    recorded_at     TIMESTAMPTZ NOT NULL,
    schema_version  INT NOT NULL CHECK (schema_version >= 1),
    payload_digest         TEXT NOT NULL,
    signed_content_digest  TEXT NOT NULL,
    states                 JSONB NOT NULL,
    PRIMARY KEY (tenant_id, report_id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES fleet_agents(tenant_id, id),
    FOREIGN KEY (tenant_id, asset_id) REFERENCES fleet_assets(tenant_id, id)
);
CREATE INDEX idx_sensor_state_history_asset_time
    ON sensor_state_history (tenant_id, asset_id, observed_at, report_id);
CREATE INDEX idx_sensor_state_history_agent_time
    ON sensor_state_history (tenant_id, agent_id, observed_at, report_id);
CALL synapse_enable_tenant_rls('sensor_state_history');

-- The history is a fact log. Application code only inserts; this trigger also rejects accidental
-- UPDATE/DELETE/TRUNCATE through a future repository path.
CREATE TRIGGER sensor_state_history_append_only
    BEFORE UPDATE OR DELETE ON sensor_state_history
    FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER sensor_state_history_no_truncate
    BEFORE TRUNCATE ON sensor_state_history
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

-- +goose Down
-- Accepted state observations are evidence of coverage limits; do not erase them.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM sensor_state_history) THEN
        RAISE EXCEPTION 'cannot roll back 0118: sensor-state history exists';
    END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS sensor_state_history_no_truncate ON sensor_state_history;
DROP TRIGGER IF EXISTS sensor_state_history_append_only ON sensor_state_history;
DROP TABLE sensor_state_history;
