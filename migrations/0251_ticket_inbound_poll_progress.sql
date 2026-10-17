-- +goose Up
CREATE TABLE ticket_inbound_poll_progress (
 tenant_id TEXT NOT NULL REFERENCES tenants(id), intent_id TEXT NOT NULL,
 mapping_id TEXT NOT NULL, engagement_id TEXT NOT NULL, finding_id TEXT NOT NULL, remote_id TEXT NOT NULL,
 checked_at TIMESTAMPTZ NOT NULL DEFAULT '-infinity'::timestamptz, version INTEGER NOT NULL DEFAULT 1 CHECK(version>0),
 PRIMARY KEY(tenant_id,intent_id),
 FOREIGN KEY(tenant_id,intent_id) REFERENCES ticket_intents(tenant_id,id),
 FOREIGN KEY(tenant_id,mapping_id) REFERENCES ticket_mappings(tenant_id,id),
 FOREIGN KEY(tenant_id,engagement_id,finding_id) REFERENCES findings(tenant_id,engagement_id,id)
);
CREATE INDEX ticket_inbound_poll_progress_pending_idx ON ticket_inbound_poll_progress(tenant_id,checked_at,version,intent_id);
LOCK TABLE ticket_intents IN SHARE ROW EXCLUSIVE MODE;
ALTER TABLE ticket_intents NO FORCE ROW LEVEL SECURITY;
INSERT INTO ticket_inbound_poll_progress(tenant_id,intent_id,mapping_id,engagement_id,finding_id,remote_id)
 SELECT tenant_id,id,mapping_id,engagement_id,finding_id,remote_id FROM ticket_intents
 WHERE state='done' AND action='create' AND remote_id<>''
 ON CONFLICT DO NOTHING;
ALTER TABLE ticket_intents FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION synapse_ticket_inbound_poll_target() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state='done' AND NEW.action='create' AND NEW.remote_id<>'' THEN
  INSERT INTO ticket_inbound_poll_progress(tenant_id,intent_id,mapping_id,engagement_id,finding_id,remote_id)
  VALUES(NEW.tenant_id,NEW.id,NEW.mapping_id,NEW.engagement_id,NEW.finding_id,NEW.remote_id)
  ON CONFLICT(tenant_id,intent_id) DO NOTHING;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER ticket_inbound_poll_target_after_write
 AFTER INSERT OR UPDATE OF state,action,remote_id ON ticket_intents
 FOR EACH ROW EXECUTE FUNCTION synapse_ticket_inbound_poll_target();
CALL synapse_enable_tenant_rls('ticket_inbound_poll_progress');

-- +goose Down
DROP TRIGGER ticket_inbound_poll_target_after_write ON ticket_intents;
DROP FUNCTION synapse_ticket_inbound_poll_target();
DROP TABLE ticket_inbound_poll_progress;
