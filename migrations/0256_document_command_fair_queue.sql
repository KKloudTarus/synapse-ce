-- +goose Up
ALTER TABLE document_commands
 ADD COLUMN checked_at TIMESTAMPTZ,
 ADD COLUMN check_version INT NOT NULL DEFAULT 1 CHECK(check_version>0);
CREATE INDEX document_commands_fair_pending_idx ON document_commands(tenant_id,checked_at,check_version,intent_id);
CREATE INDEX engagements_assessment_project_idx ON engagements(tenant_id,assessment_project_id) WHERE assessment_project_id IS NOT NULL;

-- +goose Down
DROP INDEX document_commands_fair_pending_idx;
DROP INDEX engagements_assessment_project_idx;
ALTER TABLE document_commands DROP COLUMN check_version, DROP COLUMN checked_at;
