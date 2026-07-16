-- +goose Up
ALTER TABLE engagements
    ADD COLUMN project_id TEXT REFERENCES projects(id) ON DELETE CASCADE;
CREATE UNIQUE INDEX idx_engagements_project ON engagements(project_id) WHERE project_id IS NOT NULL;

-- Existing projects receive the same hidden, governed scan context new projects get.
INSERT INTO engagements (id, tenant_id, project_id, name, client, status, created_at, updated_at, created_by, updated_by)
SELECT 'project-' || p.id, p.tenant_id, p.id, p.name || ' analysis', '', 'draft', p.created_at, p.updated_at, p.created_by, p.updated_by
FROM projects p
ON CONFLICT (project_id) WHERE project_id IS NOT NULL DO NOTHING;

INSERT INTO scope_targets (id, engagement_id, in_scope, kind, value)
SELECT 'project-' || p.id || '-source', 'project-' || p.id, TRUE, 'repo', p.source_binding->>'Value'
FROM projects p
WHERE p.source_binding->>'Value' <> ''
ON CONFLICT (id) DO NOTHING;

-- +goose Down
DROP INDEX IF EXISTS idx_engagements_project;
ALTER TABLE engagements DROP COLUMN IF EXISTS project_id;
