-- +goose Up
CREATE TABLE advisory_evaluation_checkpoints (
    tenant_id         TEXT NOT NULL REFERENCES tenants(id),
    advisory_id       TEXT NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    evaluated_revision BIGINT NOT NULL CHECK (evaluated_revision > 0),
    evaluated_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, advisory_id)
);
CREATE INDEX idx_advisory_evaluation_lag
    ON advisory_evaluation_checkpoints(tenant_id, evaluated_revision, evaluated_at, advisory_id);
CALL synapse_enable_tenant_rls('advisory_evaluation_checkpoints');

-- +goose Down
DROP TABLE IF EXISTS advisory_evaluation_checkpoints;
