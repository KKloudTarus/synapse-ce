-- +goose Up
-- Persist the complete provenance required before a reachability negative may
-- suppress a finding. NULL is intentionally the legacy/no-authority state.
ALTER TABLE judgments
    ADD COLUMN suppression_provenance JSONB;

-- +goose Down
ALTER TABLE judgments
    DROP COLUMN IF EXISTS suppression_provenance;
