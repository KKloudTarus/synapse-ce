-- +goose Up
-- Subject threading reads the earliest acknowledged provider message for a subject and pinned
-- channel configuration. These indexes support that lookup without introducing a mapping
-- table or serializing network sends.
CREATE INDEX idx_notification_events_subject
    ON notification_events(tenant_id,subject_kind,subject_id,id)
    WHERE subject_kind <> '' AND subject_id <> '';

CREATE INDEX idx_notification_deliveries_subject_anchor
    ON notification_deliveries(tenant_id,event_id,channel_id,channel_version,delivered_at,id)
    INCLUDE (remote_ref)
    WHERE state = 'delivered' AND remote_ref <> '';

-- +goose Down
DROP INDEX IF EXISTS idx_notification_deliveries_subject_anchor;
DROP INDEX IF EXISTS idx_notification_events_subject;
