-- +goose Up
ALTER TABLE project_analyses ADD COLUMN branch TEXT NOT NULL DEFAULT '';
UPDATE project_analyses SET branch = COALESCE(payload->>'source_ref', '') WHERE branch = '';
CREATE INDEX idx_project_analyses_tenant_project_branch_created
    ON project_analyses (tenant_id, project_id, branch, created_at DESC, id COLLATE "C" DESC);
-- +goose Down
DROP INDEX IF EXISTS idx_project_analyses_tenant_project_branch_created;
ALTER TABLE project_analyses DROP COLUMN branch;
