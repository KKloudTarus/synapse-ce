-- +goose Up
-- E5 recon: live reconnaissance is gated behind an explicit per-engagement flag
-- (ADR-0009 §4 – lab-only until the Phase-3 sandbox + egress allowlist exist).
-- Default false: existing engagements cannot run live recon until opted in.
ALTER TABLE engagements ADD COLUMN live_recon BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down
ALTER TABLE engagements DROP COLUMN live_recon;
