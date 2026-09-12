-- +goose Up
-- Persist detection-accuracy regression runs over the golden corpus (EPIC #860 D8.6) so the console
-- can show a precision/recall/false-positive trend over time. This is deployment-global engine data
-- (the golden corpus is fixed and self-contained), so the table carries NO tenant_id and no RLS,
-- matching the advisories table. The overall confusion-matrix summary lives in explicit columns for
-- querying; the per-ecosystem group breakdown rides in a jsonb column. Additive, so every existing
-- deployment is valid and older binaries that do not write it keep working (phased-safe).
CREATE TABLE accuracy_runs (
    id                TEXT PRIMARY KEY,
    ran_at            TIMESTAMPTZ NOT NULL,
    corpus_version    TEXT NOT NULL,
    schema_version    TEXT NOT NULL DEFAULT '',
    cases             INTEGER NOT NULL DEFAULT 0,
    overall_tp        BIGINT NOT NULL DEFAULT 0,
    overall_fp        BIGINT NOT NULL DEFAULT 0,
    overall_fn        BIGINT NOT NULL DEFAULT 0,
    overall_precision DOUBLE PRECISION NOT NULL DEFAULT 0,
    overall_recall    DOUBLE PRECISION NOT NULL DEFAULT 0,
    overall_f1        DOUBLE PRECISION NOT NULL DEFAULT 0,
    overall_fdr       DOUBLE PRECISION NOT NULL DEFAULT 0,
    overall_fnr       DOUBLE PRECISION NOT NULL DEFAULT 0,
    groups            JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX accuracy_runs_ran_at_idx ON accuracy_runs (ran_at DESC);

-- +goose Down
DROP TABLE accuracy_runs;
