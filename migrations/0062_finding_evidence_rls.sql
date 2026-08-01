-- +goose Up
-- Every repository for these tenant-scoped records now binds app.tenant_id via
-- WithTenantTx or WithContextTenantTx; durable SCA and recon payloads preserve
-- the same tenant context before entering their pipelines.
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON findings
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON evidence
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

ALTER TABLE finding_comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_comments FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON finding_comments
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

ALTER TABLE finding_retests ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_retests FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON finding_retests
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

ALTER TABLE imported_sboms ENABLE ROW LEVEL SECURITY;
ALTER TABLE imported_sboms FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON imported_sboms
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

ALTER TABLE writeup_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE writeup_drafts FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON writeup_drafts
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

-- +goose Down
DROP POLICY synapse_tenant_isolation ON writeup_drafts;
ALTER TABLE writeup_drafts NO FORCE ROW LEVEL SECURITY;
ALTER TABLE writeup_drafts DISABLE ROW LEVEL SECURITY;
DROP POLICY synapse_tenant_isolation ON imported_sboms;
ALTER TABLE imported_sboms NO FORCE ROW LEVEL SECURITY;
ALTER TABLE imported_sboms DISABLE ROW LEVEL SECURITY;
DROP POLICY synapse_tenant_isolation ON finding_retests;
ALTER TABLE finding_retests NO FORCE ROW LEVEL SECURITY;
ALTER TABLE finding_retests DISABLE ROW LEVEL SECURITY;
DROP POLICY synapse_tenant_isolation ON finding_comments;
ALTER TABLE finding_comments NO FORCE ROW LEVEL SECURITY;
ALTER TABLE finding_comments DISABLE ROW LEVEL SECURITY;
DROP POLICY synapse_tenant_isolation ON evidence;
ALTER TABLE evidence NO FORCE ROW LEVEL SECURITY;
ALTER TABLE evidence DISABLE ROW LEVEL SECURITY;
DROP POLICY synapse_tenant_isolation ON findings;
ALTER TABLE findings NO FORCE ROW LEVEL SECURITY;
ALTER TABLE findings DISABLE ROW LEVEL SECURITY;
