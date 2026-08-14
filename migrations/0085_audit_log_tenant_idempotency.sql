-- +goose Up
-- Legacy rows retain the global v1 chain (hash_version = 1). New v2 rows bind
-- tenant_id into the canonical hash and form an independent chain per tenant.
ALTER TABLE audit_log
    ADD COLUMN idempotency_key TEXT,
    ADD COLUMN hash_version INTEGER NOT NULL DEFAULT 1;

ALTER TABLE audit_log
    ADD CONSTRAINT audit_log_hash_version_check CHECK (hash_version IN (1, 2));

CREATE UNIQUE INDEX audit_log_tenant_action_idempotency_key_uniq
    ON audit_log (tenant_id, action, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- The v1 chain has one global parent per hash. V2 chains have one parent per
-- tenant; retaining the old global index would reject every second tenant root.
DROP INDEX audit_chain_link_uniq;
CREATE UNIQUE INDEX audit_chain_link_v1_uniq
    ON audit_log (previous_hash)
    WHERE previous_hash IS NOT NULL AND hash_version = 1;
CREATE UNIQUE INDEX audit_chain_link_v2_uniq
    ON audit_log (tenant_id, previous_hash)
    WHERE previous_hash IS NOT NULL AND hash_version = 2;

CREATE INDEX audit_log_tenant_chain_head_idx
    ON audit_log (tenant_id, hash_version, id DESC)
    WHERE hash IS NOT NULL;

-- +goose Down
-- V2 chains are tenant-local. The v1 fork guard is global, so any v2 history
-- can make the original constraint invalid. Refuse rollback rather than leave
-- a mixed schema or silently weaken the fork guarantee.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM audit_log
        WHERE hash_version = 2
    ) THEN
        RAISE EXCEPTION 'cannot roll back audit_log tenant chains after tenant genesis rows exist';
    END IF;
END
$$;
-- +goose StatementEnd

DROP INDEX IF EXISTS audit_log_tenant_chain_head_idx;
DROP INDEX IF EXISTS audit_chain_link_v2_uniq;
DROP INDEX IF EXISTS audit_chain_link_v1_uniq;
CREATE UNIQUE INDEX audit_chain_link_uniq ON audit_log (previous_hash) WHERE previous_hash IS NOT NULL;
DROP INDEX IF EXISTS audit_log_tenant_action_idempotency_key_uniq;
ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_hash_version_check;
ALTER TABLE audit_log DROP COLUMN IF EXISTS hash_version;
ALTER TABLE audit_log DROP COLUMN IF EXISTS idempotency_key;