-- +goose Up
-- Finding Kind discriminator (Phase 2, E0.3): how a finding was produced
-- (sca|recon|exploitation|manual). Existing rows are SCA findings, so default to
-- 'sca' (backward compatible). Drives promotion gating – exploitation/AI findings
-- must clear the evidence bar before promotion (golden rule 5).
ALTER TABLE findings ADD COLUMN kind TEXT NOT NULL DEFAULT 'sca';

-- +goose Down
ALTER TABLE findings DROP COLUMN kind;
