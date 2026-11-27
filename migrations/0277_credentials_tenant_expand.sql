-- +goose Up
-- Expand release for credentials (#1687). The engagement secret vault had no tenant column, so its
-- isolation rested on one HTTP wrapper. This release gives every row its tenant and makes the vault
-- bind and filter by it. Forced RLS follows in the contract release, once no deployed binary writes
-- or reads credentials without a tenant; v0.2.4 and earlier do neither.
--
-- tenant_id stays nullable here. A binary from before this migration inserts without it; the
-- trigger below fills it from the owning engagement and refuses a row whose stated tenant
-- disagrees, which also stops a caller in one tenant overwriting another tenant's secret through
-- the (engagement_id, name) upsert.
SET LOCAL lock_timeout = '5s';
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS tenant_id TEXT;

-- The backfill reads the 0144 engagement-tenant bridge rather than engagements. The bridge mirrors
-- every engagement's tenant, is kept in sync by trigger, and has no row-level security, so this all-tenant
-- join needs no lock on engagements and no lifting of its forced policy.
UPDATE credentials c
   SET tenant_id = b.tenant_id
  FROM scan_run_engagement_tenants b
 WHERE b.engagement_id = c.engagement_id
   AND c.tenant_id IS NULL
   AND b.tenant_id IS NOT NULL AND b.tenant_id <> '';

-- engagement_id 'default' is not an engagement. The vulnerability feed providers keep their API keys
-- there as an operator namespace, and they belong to the default tenant.
UPDATE credentials SET tenant_id = 'default'
 WHERE engagement_id = 'default' AND tenant_id IS NULL
   AND EXISTS (SELECT 1 FROM tenants WHERE id = 'default');

-- Created after the backfill, so the backfill does not maintain it row by row.
CREATE INDEX IF NOT EXISTS idx_credentials_tenant_engagement ON credentials (tenant_id, engagement_id);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION fn_assign_credential_tenant()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    owner_tenant TEXT;
BEGIN
    -- The 0144 bridge mirrors every engagement's tenant and is readable without a tenant bound,
    -- which an all-tenant lookup inside FORCE-RLS engagements is not.
    SELECT tenant_id INTO owner_tenant
      FROM public.scan_run_engagement_tenants
     WHERE engagement_id = NEW.engagement_id;
    IF owner_tenant IS NULL AND NEW.engagement_id = 'default' THEN
        owner_tenant := 'default';
    END IF;
    IF owner_tenant IS NULL OR owner_tenant = '' THEN
        RAISE EXCEPTION 'credentials tenant cannot be resolved for engagement %', NEW.engagement_id;
    END IF;
    IF NEW.tenant_id IS NULL OR NEW.tenant_id = '' THEN
        NEW.tenant_id := owner_tenant;
    ELSIF NEW.tenant_id <> owner_tenant THEN
        RAISE EXCEPTION 'credentials tenant conflicts with engagement %', NEW.engagement_id;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION fn_assign_credential_tenant() FROM PUBLIC;
DROP TRIGGER IF EXISTS trg_assign_credential_tenant ON credentials;
CREATE TRIGGER trg_assign_credential_tenant
BEFORE INSERT OR UPDATE ON credentials
FOR EACH ROW
EXECUTE FUNCTION fn_assign_credential_tenant();

-- +goose Down
DROP TRIGGER IF EXISTS trg_assign_credential_tenant ON credentials;
DROP FUNCTION IF EXISTS fn_assign_credential_tenant();
DROP INDEX IF EXISTS idx_credentials_tenant_engagement;
ALTER TABLE credentials DROP COLUMN IF EXISTS tenant_id;
