-- +goose Up
-- New v2 rows are tenant-local chains. Legacy v1 rows remain platform-global and
-- are intentionally invisible to tenant reviewers; verify them with an offline
-- maintenance connection that has BYPASSRLS rather than this application role.
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;

CREATE POLICY audit_log_tenant_isolation ON audit_log
    USING (hash_version = 2 AND tenant_id = synapse_current_tenant())
    WITH CHECK (hash_version = 2 AND tenant_id = synapse_current_tenant());

-- +goose Down
DROP POLICY IF EXISTS audit_log_tenant_isolation ON audit_log;
ALTER TABLE audit_log NO FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_log DISABLE ROW LEVEL SECURITY;
