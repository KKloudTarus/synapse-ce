-- +goose Up
ALTER TABLE ticket_status_sync
    ADD COLUMN version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    ADD COLUMN checked_at TIMESTAMPTZ;

UPDATE ticket_status_sync SET checked_at = updated_at WHERE checked_at IS NULL;
ALTER TABLE ticket_status_sync ALTER COLUMN checked_at SET NOT NULL;
DROP INDEX ticket_status_sync_pending_idx;
CREATE INDEX ticket_status_sync_pending_idx ON ticket_status_sync(tenant_id,checked_at) WHERE applied_state<>desired_state;

-- +goose Down
LOCK TABLE ticket_status_sync IN ACCESS EXCLUSIVE MODE;
DROP INDEX ticket_status_sync_pending_idx;
ALTER TABLE ticket_status_sync DROP COLUMN checked_at, DROP COLUMN version;
CREATE INDEX ticket_status_sync_pending_idx ON ticket_status_sync(tenant_id,updated_at) WHERE applied_state<>desired_state;
