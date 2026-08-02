-- +goose Up
ALTER TABLE scan_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON scan_runs
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

-- +goose Down
DROP POLICY synapse_tenant_isolation ON scan_runs;
ALTER TABLE scan_runs NO FORCE ROW LEVEL SECURITY;
ALTER TABLE scan_runs DISABLE ROW LEVEL SECURITY;
