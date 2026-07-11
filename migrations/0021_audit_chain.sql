-- +goose Up
-- Phase 2.5 (WS3, golden rule 6): make the audit log tamper-evident, like evidence.
-- Each new row's hash covers its content AND the previous row's hash. Columns are
-- nullable so rows written before this migration stay valid; they are reported as
-- "unchained" (legacy) at verification time, and the chain is enforced from the first
-- row written after the feature ships. No backfill – inventing hashes for past rows
-- would fake a guarantee those rows never had.
ALTER TABLE audit_log ADD COLUMN hash          TEXT;
ALTER TABLE audit_log ADD COLUMN previous_hash TEXT;

-- +goose Down
ALTER TABLE audit_log DROP COLUMN previous_hash;
ALTER TABLE audit_log DROP COLUMN hash;
