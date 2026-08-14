-- +goose Up
-- Persist sealed verifier provenance with each judgment score transition.
ALTER TABLE judgments
    ADD COLUMN verified_by TEXT NOT NULL DEFAULT '',
    ADD COLUMN verdict_rationale TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE judgments
    DROP COLUMN IF EXISTS verdict_rationale,
    DROP COLUMN IF EXISTS verified_by;
