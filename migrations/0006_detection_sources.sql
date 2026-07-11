-- +goose Up
-- Multi-source detection (Phase 1.6): which detectors found each vulnerability,
-- the confidence derived from how many agree, and each source's original data.
-- Backward compatible – existing rows keep the defaults (treated as OSV / medium).
ALTER TABLE vulnerabilities ADD COLUMN sources         TEXT NOT NULL DEFAULT '';
ALTER TABLE vulnerabilities ADD COLUMN confidence      TEXT NOT NULL DEFAULT 'medium';
ALTER TABLE vulnerabilities ADD COLUMN source_metadata JSONB;
ALTER TABLE sboms           ADD COLUMN grype_database_version TEXT;

-- +goose Down
ALTER TABLE sboms           DROP COLUMN grype_database_version;
ALTER TABLE vulnerabilities DROP COLUMN source_metadata;
ALTER TABLE vulnerabilities DROP COLUMN confidence;
ALTER TABLE vulnerabilities DROP COLUMN sources;
