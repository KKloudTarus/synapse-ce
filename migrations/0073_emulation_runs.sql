-- +goose Up
-- Adversary-emulation runs and their per-technique coverage (issue #421). This is the offensive half of
-- the purple ledger #426 consumes. Tenant-scoped and RLS-enforced like every engagement-owned table.
CREATE TABLE emulation_runs (
    tenant_id     TEXT NOT NULL REFERENCES tenants(id),
    id            TEXT NOT NULL,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    target        TEXT NOT NULL,
    actor         TEXT NOT NULL,
    started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, id)
);

CREATE TABLE emulation_coverage (
    tenant_id          TEXT NOT NULL REFERENCES tenants(id),
    run_id             TEXT NOT NULL,
    technique_id       TEXT NOT NULL,
    taxonomy_ref       TEXT NOT NULL,
    executed           BOOLEAN NOT NULL,
    expected_detection TEXT NOT NULL,
    actual_detection   TEXT,  -- NULL until the #422 detection engine populates it
    gap                BOOLEAN NOT NULL,
    PRIMARY KEY (tenant_id, run_id, technique_id),
    -- The coverage row belongs to a run in the SAME tenant; a composite FK makes a cross-tenant row
    -- unstorable, matching the exploitation and asset tables.
    FOREIGN KEY (tenant_id, run_id) REFERENCES emulation_runs(tenant_id, id) ON DELETE CASCADE,
    -- The gap definition is enforced in the database as well as the domain: an EXECUTED technique whose
    -- actual detection does not equal its expected one is a gap; a non-executed technique is not. A row
    -- that recorded a gap inconsistent with its executed/detection fields cannot be stored.
    CONSTRAINT emulation_coverage_gap_matches_evidence CHECK (
        gap = (executed AND (actual_detection IS DISTINCT FROM expected_detection))
    )
);

CREATE INDEX idx_emulation_coverage_run ON emulation_coverage(tenant_id, run_id, technique_id);

CALL synapse_enable_tenant_rls('emulation_runs');
CALL synapse_enable_tenant_rls('emulation_coverage');

-- +goose Down
DROP TABLE emulation_coverage;
DROP TABLE emulation_runs;
