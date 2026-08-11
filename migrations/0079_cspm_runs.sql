-- +goose Up
-- Durable, tenant-scoped CSPM lifecycle. Provider credentials remain vault references in the queue only;
-- this table stores normalized counts, coverage and evidence identity, never credential material.
CREATE TABLE cspm_runs (
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    id              TEXT NOT NULL,
    engagement_id   TEXT NOT NULL,
    actor            TEXT NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('queued','running','succeeded','partial','failed','cancelled')),
    complete         BOOLEAN NOT NULL DEFAULT FALSE,
    assets           INTEGER NOT NULL DEFAULT 0 CHECK (assets >= 0),
    findings         INTEGER NOT NULL DEFAULT 0 CHECK (findings >= 0),
    coverage         JSONB NOT NULL DEFAULT '[]'::jsonb,
    error_code       TEXT NOT NULL DEFAULT '',
    evidence_refs    JSONB NOT NULL DEFAULT '[]'::jsonb,
    started_at       TIMESTAMPTZ NOT NULL,
    finished_at      TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagements(tenant_id, id) ON DELETE CASCADE,
    CHECK ((status IN ('succeeded','partial','failed','cancelled')) = (finished_at IS NOT NULL))
);

CREATE INDEX idx_cspm_runs_engagement ON cspm_runs(tenant_id, engagement_id, started_at DESC);
CALL synapse_enable_tenant_rls('cspm_runs');

-- +goose Down
DROP TABLE cspm_runs;
