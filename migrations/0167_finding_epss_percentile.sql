-- +goose Up
-- Persist the EPSS percentile (the EPSS score's rank among all scored CVEs, 0..1) on each finding
-- (EPIC #860 D1.3), so the triage rank carried offline from the synced advisory corpus survives to the
-- server report/API alongside the existing kev and public_exploit signals. Additive with a default, so
-- every existing row is valid and older binaries that do not write it keep working (phased-safe).
ALTER TABLE findings ADD COLUMN epss_percentile DOUBLE PRECISION NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE findings DROP COLUMN epss_percentile;
