-- +goose Up
-- Data classes per destination (EPIC #1327 D7, #1360). A channel's data_class is the most sensitive
-- content its messages may carry: signal (event type, severity, counts, link), summary (adds titles,
-- names, target hosts) or detail (adds advisories, assets, file paths, item lists).
--
-- Chat and pager channels default to signal, because their messages land in shared rooms and on
-- phones; email and webhooks default to summary. Existing channels get their type's default. No
-- message renders through templates yet, so this changes nothing that is sent until the send-time
-- render (#1365) applies the class.
ALTER TABLE notification_channels
    ADD COLUMN data_class TEXT NOT NULL DEFAULT 'summary'
        CONSTRAINT notification_channels_data_class_check CHECK (data_class IN ('signal', 'summary', 'detail'));
-- Migrations run as the table owner with no app.current_tenant set, and notification_channels has
-- FORCE ROW LEVEL SECURITY, so the update would silently touch nothing. Lift FORCE for this
-- transaction and restore it in the same block; a failure rolls both back (the 0185 pattern).
-- +goose StatementBegin
DO $$
BEGIN
    EXECUTE 'ALTER TABLE notification_channels NO FORCE ROW LEVEL SECURITY';
    UPDATE notification_channels SET data_class = 'signal'
        WHERE channel_type IN ('slack', 'teams', 'telegram', 'google_chat', 'discord');
    EXECUTE 'ALTER TABLE notification_channels FORCE ROW LEVEL SECURITY';
END $$;
-- +goose StatementEnd

-- An engagement can lower what leaves Synapse about it: inherit (each channel's own class), signal
-- (every channel capped at signal) or none (no external notification at all). The lower of the
-- channel class and this setting wins. It lives with the notification settings rather than on the
-- engagement row, so the engagement aggregate does not change; a missing row means inherit.
CREATE TABLE notification_engagement_settings (
    tenant_id              TEXT NOT NULL REFERENCES tenants(id),
    engagement_id          TEXT NOT NULL,
    external_notifications TEXT NOT NULL
        CONSTRAINT notification_engagement_settings_value_check CHECK (external_notifications IN ('inherit', 'signal', 'none')),
    revision               INT NOT NULL CHECK (revision >= 1),
    updated_at             TIMESTAMPTZ NOT NULL,
    updated_by             TEXT NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 200),
    PRIMARY KEY (tenant_id, engagement_id),
    -- The tenant is part of the key, so a setting can only name an engagement of its own tenant.
    FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagements(tenant_id, id) ON DELETE CASCADE
);
CALL synapse_enable_tenant_rls('notification_engagement_settings');

-- +goose Down
DROP TABLE IF EXISTS notification_engagement_settings;
ALTER TABLE notification_channels DROP COLUMN IF EXISTS data_class;
