-- +goose Up
-- Recon and SCA stale recovery enumerate tenant registry IDs, then query each
-- tenant in a bound transaction. All normal reads and writes are tenant-bound.
ALTER TABLE recon_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE recon_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON recon_runs
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

ALTER TABLE scan_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON scan_jobs
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

-- +goose Down
DROP POLICY synapse_tenant_isolation ON scan_jobs;
ALTER TABLE scan_jobs NO FORCE ROW LEVEL SECURITY;
ALTER TABLE scan_jobs DISABLE ROW LEVEL SECURITY;
DROP POLICY synapse_tenant_isolation ON recon_runs;
ALTER TABLE recon_runs NO FORCE ROW LEVEL SECURITY;
ALTER TABLE recon_runs DISABLE ROW LEVEL SECURITY;
