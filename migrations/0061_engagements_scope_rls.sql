-- +goose Up
-- EngagementRepository binds both parent and scope-target operations to the
-- same tenant transaction. Scope targets derive tenancy from their parent.
ALTER TABLE engagements ENABLE ROW LEVEL SECURITY;
ALTER TABLE engagements FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON engagements
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

ALTER TABLE scope_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE scope_targets FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON scope_targets
    USING (EXISTS (
        SELECT 1 FROM engagements e
        WHERE e.id = engagement_id AND e.tenant_id = synapse_current_tenant_id()
    ))
    WITH CHECK (EXISTS (
        SELECT 1 FROM engagements e
        WHERE e.id = engagement_id AND e.tenant_id = synapse_current_tenant_id()
    ));

-- +goose Down
DROP POLICY synapse_tenant_isolation ON scope_targets;
ALTER TABLE scope_targets NO FORCE ROW LEVEL SECURITY;
ALTER TABLE scope_targets DISABLE ROW LEVEL SECURITY;
DROP POLICY synapse_tenant_isolation ON engagements;
ALTER TABLE engagements NO FORCE ROW LEVEL SECURITY;
ALTER TABLE engagements DISABLE ROW LEVEL SECURITY;
