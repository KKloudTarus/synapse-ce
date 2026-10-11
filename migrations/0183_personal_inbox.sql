-- +goose Up
-- Personal inbox rows are projections of notification events. They are not
-- deliveries and they do not carry contact addresses.
CREATE TABLE user_notifications (
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
    summary TEXT NOT NULL CHECK (length(summary) <= 500),
    link_path TEXT NOT NULL CHECK (link_path LIKE '/%' AND link_path NOT LIKE '//%' AND position('://' in link_path) = 0),
    created_at TIMESTAMPTZ NOT NULL,
    read_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, user_id, id),
    UNIQUE (tenant_id, user_id, event_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(ownership_tenant_id, id),
    FOREIGN KEY (tenant_id, event_id) REFERENCES notification_events(tenant_id, id)
);
CALL synapse_enable_tenant_rls('user_notifications');
CREATE INDEX user_notifications_feed ON user_notifications(tenant_id, user_id, created_at DESC, id DESC);
CREATE INDEX user_notifications_unread ON user_notifications(tenant_id, user_id, created_at DESC, id DESC) WHERE read_at IS NULL;

CREATE TABLE user_notification_preferences (
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('in_app', 'email')),
    state TEXT NOT NULL CHECK (state IN ('inherit', 'enabled', 'disabled')),
    revision INT NOT NULL CHECK (revision > 0),
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, user_id, event_type, channel),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(ownership_tenant_id, id)
);
CALL synapse_enable_tenant_rls('user_notification_preferences');

-- Retention deletes the inbox row but leaves a fence so a replayed source event
-- cannot insert it again.
CREATE TABLE user_notification_tombstones (
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, user_id, event_id)
);
CALL synapse_enable_tenant_rls('user_notification_tombstones');

-- +goose Down
DROP TABLE user_notification_tombstones;
DROP TABLE user_notification_preferences;
DROP TABLE user_notifications;
