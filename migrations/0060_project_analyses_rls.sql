-- +goose Up
-- ProjectAnalysisStore establishes app.tenant_id through WithTenantTx for every operation.
ALTER TABLE project_analyses ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_analyses FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON project_analyses
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

-- +goose Down
DROP POLICY synapse_tenant_isolation ON project_analyses;
ALTER TABLE project_analyses NO FORCE ROW LEVEL SECURITY;
ALTER TABLE project_analyses DISABLE ROW LEVEL SECURITY;
