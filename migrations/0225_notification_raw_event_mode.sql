-- +goose Up
ALTER TABLE notification_channels ADD COLUMN raw_event BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE notification_channels ADD CONSTRAINT notification_raw_event_policy
    CHECK (NOT raw_event OR (channel_type='webhook' AND data_class='detail' AND NOT custom_body));

-- +goose Down
ALTER TABLE notification_channels DROP CONSTRAINT notification_raw_event_policy;
ALTER TABLE notification_channels DROP COLUMN raw_event;
