-- +goose Up
-- Claim enumerates tenant registry IDs and every queue transition executes with
-- the claimed job's tenant-bound context.
ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON jobs
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

-- +goose Down
DROP POLICY synapse_tenant_isolation ON jobs;
ALTER TABLE jobs NO FORCE ROW LEVEL SECURITY;
ALTER TABLE jobs DISABLE ROW LEVEL SECURITY;
