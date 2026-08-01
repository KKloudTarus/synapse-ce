-- +goose Up
-- Request adapters set app.tenant_id with set_config(..., true) inside the
-- transaction that performs the query. NULL means no tenant context; RLS
-- migrations use this function rather than defaulting an absent context.
-- The empty string remains the existing single-tenant default context.
CREATE OR REPLACE FUNCTION synapse_current_tenant_id() RETURNS TEXT
LANGUAGE sql
STABLE
AS $$ SELECT current_setting('app.tenant_id', true) $$;

-- +goose Down
DROP FUNCTION synapse_current_tenant_id();
