-- +goose NO TRANSACTION
-- +goose Up
-- A failed concurrent build can leave an invalid index behind. Drop it
-- before retrying instead of treating IF NOT EXISTS as proof of validity.
DROP INDEX CONCURRENTLY IF EXISTS siem_audit_v2_keyset_idx;
CREATE INDEX CONCURRENTLY siem_audit_v2_keyset_idx
    ON audit_log (tenant_id, id)
    WHERE hash_version = 2 AND hash IS NOT NULL;

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS siem_audit_v2_keyset_idx;
