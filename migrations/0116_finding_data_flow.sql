-- +goose Up
-- Python Tier-2 semantic taint: retain the bounded, source-only source-to-sink witness after a judgment
-- is confirmed and projected to a finding. Domain validation caps the trace at 64 canonical relative
-- positions and excludes source text, parser output, value ids, secrets, and local workspace paths.
ALTER TABLE findings ADD COLUMN data_flow JSONB;

-- +goose Down
ALTER TABLE findings DROP COLUMN data_flow;
