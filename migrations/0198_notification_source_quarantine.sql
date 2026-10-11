-- +goose Up
ALTER TABLE notification_source_records
    ADD COLUMN failed_reason TEXT NOT NULL DEFAULT '' CHECK (length(failed_reason) <= 100);

CREATE INDEX idx_notification_source_quarantined
    ON notification_source_records(tenant_id, processed_at DESC, source_kind, source_id)
    WHERE failed_reason <> '';

-- +goose Down
DROP INDEX IF EXISTS idx_notification_source_quarantined;
ALTER TABLE notification_source_records DROP COLUMN IF EXISTS failed_reason;
