-- +goose Up
ALTER TABLE ticket_mappings
    ADD COLUMN status_transitions JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD CONSTRAINT ticket_mappings_status_transitions_object CHECK (jsonb_typeof(status_transitions)='object'),
    ADD CONSTRAINT ticket_mappings_status_transitions_keys CHECK (
      status_transitions - ARRAY['remediated','accepted','false_positive','reopen'] = '{}'::jsonb
      AND COALESCE(jsonb_typeof(status_transitions->'remediated'),'string')='string'
      AND COALESCE(jsonb_typeof(status_transitions->'accepted'),'string')='string'
      AND COALESCE(jsonb_typeof(status_transitions->'false_positive'),'string')='string'
      AND COALESCE(jsonb_typeof(status_transitions->'reopen'),'string')='string'
    );

-- A status target is a durable observation, not a cursor. It fences each
-- state episode so close -> reopen -> close remains actionable while repeated
-- polling converges without duplicate Jira transitions.
CREATE TABLE ticket_status_sync (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    mapping_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    desired_state TEXT NOT NULL CHECK (desired_state IN ('remediated','accepted','false_positive','reopen')),
    applied_state TEXT NOT NULL DEFAULT '',
    source_revision TEXT NOT NULL,
    transition_intent_id TEXT,
    update_intent_id TEXT,
    integration_author TEXT NOT NULL DEFAULT '',
    provider_updated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(tenant_id,mapping_id,finding_id,engagement_id),
    FOREIGN KEY(tenant_id,mapping_id) REFERENCES ticket_mappings(tenant_id,id),
    FOREIGN KEY(tenant_id,engagement_id,finding_id) REFERENCES findings(tenant_id,engagement_id,id),
    FOREIGN KEY(tenant_id,transition_intent_id) REFERENCES ticket_intents(tenant_id,id),
    FOREIGN KEY(tenant_id,update_intent_id) REFERENCES ticket_intents(tenant_id,id)
);
CREATE INDEX ticket_status_sync_pending_idx ON ticket_status_sync(tenant_id,updated_at) WHERE applied_state<>desired_state;
CALL synapse_enable_tenant_rls('ticket_status_sync');

-- +goose Down
LOCK TABLE ticket_mappings,ticket_status_sync IN ACCESS EXCLUSIVE MODE;
ALTER TABLE ticket_mappings NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_status_sync NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM ticket_status_sync) OR EXISTS(SELECT 1 FROM ticket_mappings WHERE status_transitions<>'{}'::jsonb) THEN
   RAISE EXCEPTION 'cannot roll back ticket status sync while data exists' USING ERRCODE='55000';
 END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE ticket_status_sync FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_mappings FORCE ROW LEVEL SECURITY;
DROP TABLE ticket_status_sync;
ALTER TABLE ticket_mappings DROP CONSTRAINT ticket_mappings_status_transitions_keys, DROP CONSTRAINT ticket_mappings_status_transitions_object, DROP COLUMN status_transitions;
