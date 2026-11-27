-- +goose Up
-- Contract release for credentials (#1687). 0277 gave every row its tenant and v0.3.0 reads and writes
-- the vault only inside a bound tenant, so this release can enforce it: forced row-level security, and
-- tenant_id NOT NULL.
--
-- A row 0277 could not attribute has no engagement left to own it: its engagement was deleted before
-- 0277 ran, and the vault resolves a secret only through its engagement. Nothing can read such a
-- secret, so it is deleted rather than kept as unattributed ciphertext. A NULL-tenant row whose
-- engagement still exists would mean the 0277 trigger was bypassed; the migration refuses to guess
-- its tenant and stops.
SET LOCAL lock_timeout = '5s';

-- +goose StatementBegin
DO $$
DECLARE
    v_attributable BIGINT;
BEGIN
    SELECT count(*) INTO v_attributable
      FROM credentials c
      JOIN scan_run_engagement_tenants b ON b.engagement_id = c.engagement_id
     WHERE c.tenant_id IS NULL OR c.tenant_id = '';
    IF v_attributable > 0 THEN
        RAISE EXCEPTION 'migration 0281: % credentials rows have no tenant although their engagement exists', v_attributable;
    END IF;
END $$;
-- +goose StatementEnd

-- Feed-provider keys live under engagement_id 'default', an operator namespace of the default tenant.
-- 0277 attributed them when the default tenant existed; repeat it so they are never mistaken for orphans.
UPDATE credentials SET tenant_id = 'default'
 WHERE engagement_id = 'default' AND (tenant_id IS NULL OR tenant_id = '')
   AND EXISTS (SELECT 1 FROM tenants WHERE id = 'default');
-- +goose StatementBegin
DO $$
DECLARE
    v_orphans BIGINT;
BEGIN
    SELECT count(*) INTO v_orphans FROM credentials WHERE tenant_id IS NULL OR tenant_id = '';
    IF v_orphans > 0 THEN
        RAISE NOTICE 'migration 0281: deleting % credentials rows whose engagement no longer exists', v_orphans;
    END IF;
END $$;
-- +goose StatementEnd
DELETE FROM credentials WHERE tenant_id IS NULL OR tenant_id = '';
ALTER TABLE credentials ALTER COLUMN tenant_id SET NOT NULL;
CALL synapse_enable_tenant_rls('credentials');

-- +goose Down
-- The unattributable rows deleted on the way up are not restored: no engagement could resolve them.
SET LOCAL lock_timeout = '5s';
DROP POLICY IF EXISTS credentials_tenant_isolation ON credentials;
ALTER TABLE credentials NO FORCE ROW LEVEL SECURITY;
ALTER TABLE credentials DISABLE ROW LEVEL SECURITY;
ALTER TABLE credentials ALTER COLUMN tenant_id DROP NOT NULL;
