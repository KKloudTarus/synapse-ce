-- +goose Up
-- Auto-push remains disabled until an administrator explicitly enables it. The
-- activation timestamp fences durable finding-status events that predate opt-in.
ALTER TABLE ticket_mappings
    ADD COLUMN auto_push_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN auto_push_min_severity TEXT NOT NULL DEFAULT ''
        CHECK (auto_push_min_severity IN ('','info','low','medium','high','critical')),
    ADD COLUMN auto_push_enabled_at TIMESTAMPTZ,
    ADD CONSTRAINT ticket_mappings_auto_push_activation CHECK (
        (auto_push_enabled AND auto_push_enabled_at IS NOT NULL)
        OR (NOT auto_push_enabled AND auto_push_enabled_at IS NULL)
    );
CREATE INDEX ticket_mappings_auto_push_scope_idx
    ON ticket_mappings (tenant_id, engagement_id, project_id, id)
    WHERE auto_push_enabled;

-- Event receipts avoid a timestamp cursor: notification projection can publish
-- an older source event after a newer one. Pending receipts are retried without
-- blocking later events, and stable request keys make a crash before receipt
-- completion replay-safe.
CREATE TABLE ticket_auto_push_receipts (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    event_id TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    engagement_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    to_status TEXT NOT NULL,
    available_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,event_id),
    FOREIGN KEY (tenant_id,event_id) REFERENCES notification_events(tenant_id,id) ON DELETE CASCADE
);
CREATE INDEX ticket_auto_push_receipts_pending_idx ON ticket_auto_push_receipts (tenant_id,available_at,event_id) WHERE completed_at IS NULL;
CALL synapse_enable_tenant_rls('ticket_auto_push_receipts');
-- +goose StatementBegin
CREATE FUNCTION ticket_capture_auto_push_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.event_type='finding.status_changed' THEN
        INSERT INTO ticket_auto_push_receipts(tenant_id,event_id,occurred_at,engagement_id,finding_id,to_status,available_at,updated_at)
        VALUES(NEW.tenant_id,NEW.id,NEW.occurred_at,NEW.engagement_id,NEW.subject_id,COALESCE(NEW.data->>'to_status',''),NEW.created_at,NEW.created_at)
        ON CONFLICT(tenant_id,event_id) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER ticket_auto_push_event_capture AFTER INSERT ON notification_events
    FOR EACH ROW EXECUTE FUNCTION ticket_capture_auto_push_event();

-- +goose Down
LOCK TABLE ticket_mappings, ticket_auto_push_receipts IN ACCESS EXCLUSIVE MODE;
ALTER TABLE ticket_mappings NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_auto_push_receipts NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM ticket_auto_push_receipts)
       OR EXISTS (SELECT 1 FROM ticket_mappings WHERE auto_push_enabled OR auto_push_min_severity<>'' OR auto_push_enabled_at IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot roll back ticket auto-push while policy or cursor data exists'
            USING ERRCODE = '55000';
    END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE ticket_auto_push_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_mappings FORCE ROW LEVEL SECURITY;
DROP INDEX ticket_auto_push_receipts_pending_idx;
DROP TRIGGER ticket_auto_push_event_capture ON notification_events;
DROP FUNCTION ticket_capture_auto_push_event();
DROP TABLE ticket_auto_push_receipts;
DROP INDEX ticket_mappings_auto_push_scope_idx;
ALTER TABLE ticket_mappings DROP CONSTRAINT ticket_mappings_auto_push_activation,
    DROP COLUMN auto_push_enabled, DROP COLUMN auto_push_min_severity, DROP COLUMN auto_push_enabled_at;
