-- +goose Up
-- Approval timeout sweeping enumerates tenant registry IDs and executes pending
-- engagement discovery and decisions in a context bound to each tenant.
ALTER TABLE agent_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON agent_approvals
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

-- +goose Down
DROP POLICY synapse_tenant_isolation ON agent_approvals;
ALTER TABLE agent_approvals NO FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_approvals DISABLE ROW LEVEL SECURITY;
