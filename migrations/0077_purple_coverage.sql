-- +goose Up
-- Purple-team coverage ledger (issue #426). Each row is one emulated technique's resolved coverage for a
-- run: the join of the offensive half (what the technique executed and EXPECTED to be detected, #421) with
-- the defensive half (what actually fired, #422/#423). Keyed (run_id, technique_id) so a re-computation of
-- a run replaces its rows in place and coverage across runs is a trend. Tenant-scoped and RLS-enforced.
CREATE TABLE purple_coverage (
    tenant_id         TEXT NOT NULL REFERENCES tenants(id),
    run_id            TEXT NOT NULL,
    technique_id      TEXT NOT NULL,
    engagement_id     TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    asset_id          TEXT NOT NULL DEFAULT '',
    -- The public taxonomy reference is NOT NULL and non-empty: coverage is expressed against a taxonomy a
    -- customer and an auditor already understand, mirroring the domain's construction-time refusal.
    taxonomy_ref      TEXT NOT NULL CHECK (taxonomy_ref <> ''),
    expected          TEXT NOT NULL DEFAULT '',
    actual            JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- The verdict set is closed. out_of_reach/unknown are honest non-measurements; only 'gap' is an
    -- actionable coverage hole — so a non-executed technique can never be stored as a gap.
    verdict           TEXT NOT NULL CHECK (verdict IN ('out_of_reach', 'unknown', 'covered', 'gap')),
    computed_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, run_id, technique_id)
);

CREATE INDEX idx_purple_coverage_engagement ON purple_coverage (tenant_id, engagement_id, computed_at);

CALL synapse_enable_tenant_rls('purple_coverage');

-- +goose Down
DROP TABLE purple_coverage;
