-- +goose Up
-- Agent sessions are reconciled tenant-by-tenant; message, plan, and decision
-- repositories execute under the same context before accessing these tables.
ALTER TABLE agent_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON agent_sessions
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

ALTER TABLE agent_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_messages FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON agent_messages
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

ALTER TABLE agent_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_plans FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON agent_plans
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

ALTER TABLE agent_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_decisions FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON agent_decisions
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

-- +goose Down
DROP POLICY synapse_tenant_isolation ON agent_decisions;
ALTER TABLE agent_decisions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_decisions DISABLE ROW LEVEL SECURITY;
DROP POLICY synapse_tenant_isolation ON agent_plans;
ALTER TABLE agent_plans NO FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_plans DISABLE ROW LEVEL SECURITY;
DROP POLICY synapse_tenant_isolation ON agent_messages;
ALTER TABLE agent_messages NO FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_messages DISABLE ROW LEVEL SECURITY;
DROP POLICY synapse_tenant_isolation ON agent_sessions;
ALTER TABLE agent_sessions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_sessions DISABLE ROW LEVEL SECURITY;
