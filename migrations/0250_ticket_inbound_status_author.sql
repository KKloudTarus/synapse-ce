-- +goose Up
ALTER TABLE ticket_external_observations
 ADD COLUMN IF NOT EXISTS status_changed_at TIMESTAMPTZ,
 ADD COLUMN IF NOT EXISTS status_author_known BOOLEAN NOT NULL DEFAULT FALSE,
 ADD COLUMN IF NOT EXISTS pending_done BOOLEAN NOT NULL DEFAULT FALSE,
 ADD COLUMN IF NOT EXISTS resolution_name TEXT NOT NULL DEFAULT '' CHECK(octet_length(resolution_name)<=255);
ALTER TABLE ticket_retest_proposals
 ADD COLUMN IF NOT EXISTS resolution_name TEXT NOT NULL DEFAULT '' CHECK(octet_length(resolution_name)<=255);
-- +goose StatementBegin
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='ticket_external_observations_integration_fk') THEN
  ALTER TABLE ticket_external_observations ADD CONSTRAINT ticket_external_observations_integration_fk FOREIGN KEY(tenant_id,integration_id) REFERENCES integrations(tenant_id,id);
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='ticket_retest_proposals_integration_fk') THEN
  ALTER TABLE ticket_retest_proposals ADD CONSTRAINT ticket_retest_proposals_integration_fk FOREIGN KEY(tenant_id,integration_id) REFERENCES integrations(tenant_id,id);
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='ticket_external_comments_integration_fk') THEN
  ALTER TABLE ticket_external_comments ADD CONSTRAINT ticket_external_comments_integration_fk FOREIGN KEY(tenant_id,integration_id) REFERENCES integrations(tenant_id,id);
 END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
LOCK TABLE ticket_external_observations,ticket_retest_proposals,ticket_external_comments IN ACCESS EXCLUSIVE MODE;
ALTER TABLE ticket_external_observations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_retest_proposals NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_external_comments NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM ticket_external_observations) OR EXISTS (SELECT 1 FROM ticket_retest_proposals) OR EXISTS (SELECT 1 FROM ticket_external_comments) THEN
  RAISE EXCEPTION 'ticket inbound history must be retained; use a forward migration';
 END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE ticket_external_observations FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_retest_proposals FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_external_comments FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_external_observations
 DROP CONSTRAINT IF EXISTS ticket_external_observations_integration_fk,
 DROP COLUMN IF EXISTS pending_done,
 DROP COLUMN IF EXISTS status_author_known,
 DROP COLUMN IF EXISTS status_changed_at,
 DROP COLUMN IF EXISTS resolution_name;
ALTER TABLE ticket_retest_proposals DROP CONSTRAINT IF EXISTS ticket_retest_proposals_integration_fk, DROP COLUMN IF EXISTS resolution_name;
ALTER TABLE ticket_external_comments DROP CONSTRAINT IF EXISTS ticket_external_comments_integration_fk;
