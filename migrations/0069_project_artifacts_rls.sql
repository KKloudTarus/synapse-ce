-- +goose Up
-- Project artifact repositories bind app.tenant_id for ingestion, list/detail,
-- transition, review history, and analysis-projection reads.
ALTER TABLE project_hotspots ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_hotspots FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON project_hotspots
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

ALTER TABLE project_hotspot_review_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_hotspot_review_events FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON project_hotspot_review_events
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

ALTER TABLE project_analysis_hotspots ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_analysis_hotspots FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON project_analysis_hotspots
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

ALTER TABLE project_issues ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_issues FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON project_issues
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

ALTER TABLE project_issue_review_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_issue_review_events FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON project_issue_review_events
    USING (tenant_id = synapse_current_tenant_id())
    WITH CHECK (tenant_id = synapse_current_tenant_id());

-- +goose Down
DROP POLICY synapse_tenant_isolation ON project_issue_review_events;
ALTER TABLE project_issue_review_events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE project_issue_review_events DISABLE ROW LEVEL SECURITY;
DROP POLICY synapse_tenant_isolation ON project_issues;
ALTER TABLE project_issues NO FORCE ROW LEVEL SECURITY;
ALTER TABLE project_issues DISABLE ROW LEVEL SECURITY;
DROP POLICY synapse_tenant_isolation ON project_analysis_hotspots;
ALTER TABLE project_analysis_hotspots NO FORCE ROW LEVEL SECURITY;
ALTER TABLE project_analysis_hotspots DISABLE ROW LEVEL SECURITY;
DROP POLICY synapse_tenant_isolation ON project_hotspot_review_events;
ALTER TABLE project_hotspot_review_events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE project_hotspot_review_events DISABLE ROW LEVEL SECURITY;
DROP POLICY synapse_tenant_isolation ON project_hotspots;
ALTER TABLE project_hotspots NO FORCE ROW LEVEL SECURITY;
ALTER TABLE project_hotspots DISABLE ROW LEVEL SECURITY;
