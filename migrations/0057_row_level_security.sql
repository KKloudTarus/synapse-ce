-- +goose Up
-- Multi-tenant isolation foundation (#432, epic #405). This migration is NON-BREAKING:
-- it creates two reusable primitives and changes no existing table, so startup migrate is
-- safe. Tables opt in later by calling synapse_enable_tenant_rls(<table>) from their own
-- migration (fleet_assets in #431 is the first). Existing tables are retrofitted incrementally
-- once their stores route through WithTenant, never big-bang here.
--
-- Tenant resolution is a STABLE function reading a per-transaction session variable set by the
-- WithTenant helper. Unset (never set in the session) yields NULL, so a policy comparison
-- `tenant_id = synapse_current_tenant()` is NULL and excludes every row: unset is DENY-ALL,
-- fail-closed even for the default tenant whose id is the empty string ('' from 0002). Set to
-- '' matches the default tenant; set to a real id matches only that tenant.

-- +goose StatementBegin
CREATE FUNCTION synapse_current_tenant() RETURNS text
    LANGUAGE sql STABLE
    AS $$ SELECT current_setting('app.current_tenant', true) $$;
-- +goose StatementEnd

-- synapse_enable_tenant_rls applies the identical, non-weakenable policy shape to a table that
-- has a tenant_id column: enable RLS, FORCE it (so the table owner the app connects as is also
-- subject, since goose migrations run as that owner), and one USING+WITH CHECK policy keyed on
-- synapse_current_tenant(). Idempotent enough for a fresh table; a table may be enabled once.
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
