-- +goose Up
-- These repositories are fully migrated to WithTenantTx. Keep policies narrow:
-- a table is enabled only after every runtime operation establishes a tenant
-- context, preventing a partial rollout from breaking unrelated persistence.
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON projects
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

ALTER TABLE quality_gates ENABLE ROW LEVEL SECURITY;
ALTER TABLE quality_gates FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON quality_gates
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

ALTER TABLE quality_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE quality_profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON quality_profiles
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

-- +goose Down
DROP POLICY synapse_tenant_isolation ON quality_profiles;
ALTER TABLE quality_profiles NO FORCE ROW LEVEL SECURITY;
ALTER TABLE quality_profiles DISABLE ROW LEVEL SECURITY;
DROP POLICY synapse_tenant_isolation ON quality_gates;
ALTER TABLE quality_gates NO FORCE ROW LEVEL SECURITY;
ALTER TABLE quality_gates DISABLE ROW LEVEL SECURITY;
DROP POLICY synapse_tenant_isolation ON projects;
ALTER TABLE projects NO FORCE ROW LEVEL SECURITY;
ALTER TABLE projects DISABLE ROW LEVEL SECURITY;
