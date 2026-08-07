-- +goose Up
-- Multi-tenant isolation foundation (#432, epic #405). This migration is NON-BREAKING:
-- it creates two reusable primitives and changes no existing table, so startup migrate is
-- safe. Tables opt in later by calling synapse_enable_tenant_rls(<table>) from their own
-- migration (fleet_assets in #431 is the first). Existing tables are retrofitted incrementally
-- once their stores route through WithTenant, never big-bang here.
--
-- Tenant resolution is a STABLE function reading a per-transaction session variable set by the
-- WithTenant helper. IMPORTANT fail-closed detail: app.current_tenant is a custom (placeholder)
-- GUC whose RESET value is the empty string, not NULL. So after any set_config(..., is_local)
-- transaction runs on a pooled connection, the variable reverts to '' (not "unset") for the next
-- statement on that connection. If the policy compared against a bare current_setting(), a query
-- that FORGOT to go through WithTenant would then match tenant_id = '' and leak default-tenant
-- rows. To make "forgot WithTenant" mean "see nothing", synapse_current_tenant() maps BOTH unset
-- (NULL) AND the empty string to NULL via NULLIF, so `tenant_id = synapse_current_tenant()` is
-- NULL and excludes every row.
--
-- Consequence, a deliberate invariant for RLS-protected tables: the empty string is NOT a usable
-- tenant id under RLS; it means DENY. RLS-protected (new, fleet) tables therefore use non-empty
-- tenant ids, including a non-empty id for the default/single-tenant deployment. This diverges on
-- purpose from the legacy ''=default-tenant convention that pre-RLS tables still use; those tables
-- are migrated onto a non-empty default tenant as part of their incremental retrofit.

-- +goose StatementBegin
CREATE FUNCTION synapse_current_tenant() RETURNS text
    LANGUAGE sql STABLE
    AS $$ SELECT NULLIF(current_setting('app.current_tenant', true), '') $$;
-- +goose StatementEnd

-- synapse_enable_tenant_rls applies the identical, non-weakenable policy shape to a table that
-- has a tenant_id column: enable RLS, FORCE it (so the table owner the app connects as is also
-- subject, since goose migrations run as that owner), and one USING+WITH CHECK policy keyed on
-- synapse_current_tenant(). NOTE: RLS is still bypassed entirely by SUPERUSER and BYPASSRLS roles
-- regardless of FORCE; the runtime DB role must be neither (see CheckRLSRuntimeRole in tenant.go).
-- +goose StatementBegin
CREATE PROCEDURE synapse_enable_tenant_rls(tbl text)
    LANGUAGE plpgsql
    AS $$
BEGIN
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tbl);
    EXECUTE format(
        'CREATE POLICY %I ON %I USING (tenant_id = synapse_current_tenant()) WITH CHECK (tenant_id = synapse_current_tenant())',
        tbl || '_tenant_isolation', tbl);
END;
$$;
-- +goose StatementEnd

-- +goose Down
DROP PROCEDURE IF EXISTS synapse_enable_tenant_rls(text);
DROP FUNCTION IF EXISTS synapse_current_tenant();
