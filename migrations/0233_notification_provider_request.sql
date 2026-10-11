-- +goose Up
ALTER TABLE notification_deliveries ADD COLUMN provider_request_ref text NOT NULL DEFAULT ''
    CHECK (octet_length(provider_request_ref) <= 512);

-- +goose Down
-- Quiesce async provider delivery before rollback; pending request handles are lost.
ALTER TABLE notification_deliveries DROP COLUMN provider_request_ref;
