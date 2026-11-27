-- +goose Up
-- Contract release for scan_runs (#1697), deferred by 0144, step one of two. scan_runs carried
-- tenant_id but sat outside forced row-level security, so a query that forgot its tenant predicate
-- read every tenant's scan manifests and finding keys with nothing underneath to stop it.
--
-- 0144 named the precondition: every writer binds and supplies tenant identity. v0.2.4 does: every
-- scan_runs statement in it runs inside WithTenant and every INSERT names tenant_id. Deployments must
-- therefore run v0.2.4 or later while these migrations apply, which is the supported upgrade path.
--
-- This step only declares constraints, NOT VALID, so it reads no existing row and holds its locks for
-- milliseconds: the composite key ties every new run to its engagement's tenant, and a check states
-- that tenant_id is present. 0276 validates the check and turns it into NOT NULL. The key stays NOT
-- VALID: validating it would read engagements across tenants with that table's forced RLS lifted
-- under an ACCESS EXCLUSIVE lock, while the 0144 trigger already refuses a run whose tenant disagrees
-- with its engagement's and 0144's backfill checked every existing row.
SET LOCAL lock_timeout = '5s';

-- +goose StatementBegin
DO $$
DECLARE
    v_orphans BIGINT;
BEGIN
    SELECT count(*) INTO v_orphans FROM scan_runs WHERE tenant_id IS NULL OR tenant_id = '';
    IF v_orphans > 0 THEN
        RAISE EXCEPTION 'migration 0275: % scan_runs rows have no tenant; the 0144 bridge should have filled them', v_orphans;
    END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE scan_runs ADD CONSTRAINT fk_scan_runs_engagement_tenant
    FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagements(tenant_id, id) ON DELETE RESTRICT NOT VALID;
ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_tenant_id_present CHECK (tenant_id IS NOT NULL AND tenant_id <> '') NOT VALID;

-- +goose Down
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS scan_runs_tenant_id_present;
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS fk_scan_runs_engagement_tenant;
