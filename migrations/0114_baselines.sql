-- +goose Up
-- Phase D / D5 (#738): the behavioral-baseline projection. Unlike the append-only evidence/incident
-- ledgers, a baseline is a MUTABLE projection — a re-observation upserts it in place — so this table has
-- no append-only trigger; integrity comes from the domain (baseline.NewBaselineFrom validates the
-- accumulators on every load) and the usecase (which audits every lifecycle transition). One row per
-- (tenant, group); the group is a peer-group or entity id, optionally seasonally keyed by the usecase.
CREATE TABLE baselines (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id),
    group_id   TEXT NOT NULL,
    state      TEXT NOT NULL,
    -- summaries is the []baseline.FeatureSummary vector (per-feature count/sum/sumSq/min/max) as JSON; it
    -- is the authoritative accumulator content the domain rehydrates. Deterministic integer values only.
    summaries  JSONB NOT NULL,
    -- drift-tracker per-baseline progress (config score/threshold is service policy, not stored here).
    drift_run  INT NOT NULL DEFAULT 0 CHECK (drift_run >= 0),
    drifted    BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, group_id)
);
CALL synapse_enable_tenant_rls('baselines');

-- +goose Down
DROP TABLE baselines;
