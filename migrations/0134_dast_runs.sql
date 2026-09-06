-- +goose Up
-- Durable, tenant-scoped DAST verification-run lifecycle. A probe used to execute synchronously in the
-- API request; it now runs as a lease-executed job, so this table tracks its status and secret-free
-- outcome (the verdict class, the observed HTTP status, and the sealed-evidence id). It never stores the
-- probe body, any request/response content, or a credential.
CREATE TABLE dast_runs (
    tenant_id     TEXT NOT NULL REFERENCES tenants(id),
    id            TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    action_id     TEXT NOT NULL,
    actor         TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('queued','running','succeeded','failed')),
    verdict       TEXT NOT NULL DEFAULT '',
    http_status   INTEGER NOT NULL DEFAULT 0 CHECK (http_status >= 0),
    evidence_id   TEXT NOT NULL DEFAULT '',
    error_code    TEXT NOT NULL DEFAULT '',
    started_at    TIMESTAMPTZ NOT NULL,
    finished_at   TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagements(tenant_id, id) ON DELETE CASCADE,
    -- The terminal states carry a finish time; the in-flight states do not.
    CHECK ((status IN ('succeeded','failed')) = (finished_at IS NOT NULL))
);

CREATE INDEX idx_dast_runs_engagement ON dast_runs(tenant_id, engagement_id, started_at DESC);
CALL synapse_enable_tenant_rls('dast_runs');

-- +goose Down
DROP TABLE dast_runs;
