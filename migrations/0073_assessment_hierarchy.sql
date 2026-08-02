-- +goose Up
CREATE TABLE assessments (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    business_service_id TEXT NOT NULL REFERENCES appsec_business_services(id),
    name TEXT NOT NULL,
    objective TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    UNIQUE (tenant_id, business_service_id, name)
);
ALTER TABLE engagements ADD COLUMN assessment_id TEXT REFERENCES assessments(id);
CREATE INDEX engagements_assessment_idx ON engagements (assessment_id);
ALTER TABLE assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE assessments FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON assessments USING (tenant_id = synapse_current_tenant_id()) WITH CHECK (tenant_id = synapse_current_tenant_id());
-- +goose Down
DROP INDEX IF EXISTS engagements_assessment_idx;
ALTER TABLE engagements DROP COLUMN assessment_id;
DROP POLICY synapse_tenant_isolation ON assessments;
ALTER TABLE assessments NO FORCE ROW LEVEL SECURITY;
ALTER TABLE assessments DISABLE ROW LEVEL SECURITY;
DROP TABLE assessments;
