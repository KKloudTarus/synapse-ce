-- +goose Up
-- External channel digests retain their original event snapshots as members. A
-- member is admitted when its source event is published, then materialized once its
-- publication-time UTC window closes. The event rows are the authority for content;
-- the aggregate source only carries a bounded descriptor.
ALTER TABLE notification_rules
    ADD COLUMN cadence TEXT NOT NULL DEFAULT 'immediate'
        CONSTRAINT notification_rules_cadence_check CHECK (cadence IN ('immediate','hourly','daily')),
    ADD COLUMN recipient_user_ids JSONB NOT NULL DEFAULT '[]'::jsonb
        CONSTRAINT notification_rules_recipient_user_ids_check CHECK (
            jsonb_typeof(recipient_user_ids)='array' AND jsonb_array_length(recipient_user_ids)<=200
        );

-- A console test pins the exact template version used by the test event. It is
-- internal-only and never appears in a public notification envelope.
ALTER TABLE notification_events
    ADD COLUMN test_template JSONB
        CONSTRAINT notification_events_test_template_object CHECK (
            test_template IS NULL OR (jsonb_typeof(test_template)='object' AND pg_column_size(test_template)<=262144)
        );

ALTER TABLE user_notifications DROP CONSTRAINT user_notifications_recipient_roles_check;
ALTER TABLE user_notifications ADD CONSTRAINT user_notifications_recipient_roles_check CHECK (
    jsonb_typeof(recipient_roles)='array' AND recipient_roles <@ '["assignee","team_member","engagement_lead","mentioned_user","approver","tenant_admin","explicit_user"]'::jsonb
);

CREATE TABLE notification_digest_members (
    tenant_id    TEXT NOT NULL REFERENCES tenants(id),
    rule_id      TEXT NOT NULL,
    channel_id   TEXT NOT NULL,
    cadence      TEXT NOT NULL CHECK (cadence IN ('hourly','daily')),
    window_start TIMESTAMPTZ NOT NULL,
    window_end   TIMESTAMPTZ NOT NULL,
    chunk        INT NOT NULL CHECK (chunk >= 0),
    event_id     TEXT NOT NULL,
    PRIMARY KEY (tenant_id,rule_id,channel_id,cadence,window_start,chunk,event_id),
    CHECK (window_end > window_start),
    FOREIGN KEY (tenant_id,channel_id) REFERENCES notification_channels(tenant_id,id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,event_id) REFERENCES notification_events(tenant_id,id) ON DELETE CASCADE
);
CREATE INDEX notification_digest_members_due
    ON notification_digest_members(tenant_id,window_end,rule_id,channel_id,cadence,window_start,chunk);
CREATE INDEX notification_digest_members_tail
    ON notification_digest_members(tenant_id,rule_id,channel_id,cadence,window_start,chunk DESC);
CALL synapse_enable_tenant_rls('notification_digest_members');

-- A completed run fixes the outcome for a closed window. This prevents a later
-- rule/channel re-enable from retroactively releasing content that was suppressed
-- when the window closed.
CREATE TABLE notification_digest_windows (
    tenant_id    TEXT NOT NULL REFERENCES tenants(id),
    rule_id      TEXT NOT NULL,
    channel_id   TEXT NOT NULL,
    cadence      TEXT NOT NULL CHECK (cadence IN ('hourly','daily')),
    window_start TIMESTAMPTZ NOT NULL,
    window_end   TIMESTAMPTZ NOT NULL,
    chunk        INT NOT NULL CHECK (chunk >= 0),
    outcome      TEXT NOT NULL CHECK (outcome IN ('pending','published','suppressed','empty')),
    event_id     TEXT,
    finalized_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id,rule_id,channel_id,cadence,window_start,chunk),
    CHECK (window_end > window_start),
    CHECK ((outcome='pending' AND finalized_at IS NULL AND event_id IS NULL) OR (outcome<>'pending' AND finalized_at IS NOT NULL)),
    FOREIGN KEY (tenant_id,channel_id) REFERENCES notification_channels(tenant_id,id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,event_id) REFERENCES notification_events(tenant_id,id)
);
CALL synapse_enable_tenant_rls('notification_digest_windows');
CREATE INDEX notification_digest_windows_pending_due
    ON notification_digest_windows(tenant_id,window_end,rule_id,channel_id,cadence,window_start,chunk)
    WHERE outcome='pending';
CREATE UNIQUE INDEX notification_digest_windows_event
    ON notification_digest_windows(tenant_id,event_id)
    WHERE event_id IS NOT NULL;

-- +goose Down
-- Do not silently erase queued aggregate members, pinned test templates, or
-- rule recipient/cadence choices. Operators must drain or explicitly retire
-- them before a downgrade.
LOCK TABLE tenants, notification_rules, notification_events, notification_deliveries, user_notifications,
    notification_digest_members, notification_digest_windows IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$
DECLARE tenant_row RECORD;
BEGIN
    FOR tenant_row IN SELECT id FROM tenants WHERE id<>'' LOOP
        PERFORM set_config('app.current_tenant',tenant_row.id,true);
        IF EXISTS(SELECT 1 FROM notification_digest_members WHERE tenant_id=tenant_row.id)
           OR EXISTS(SELECT 1 FROM notification_digest_windows WHERE tenant_id=tenant_row.id)
           OR EXISTS(SELECT 1 FROM notification_events WHERE tenant_id=tenant_row.id AND test_template IS NOT NULL)
           OR EXISTS(SELECT 1 FROM user_notifications WHERE tenant_id=tenant_row.id AND recipient_roles ? 'explicit_user')
           OR EXISTS(SELECT 1 FROM notification_rules WHERE tenant_id=tenant_row.id
                AND (cadence<>'immediate' OR recipient_user_ids<>'[]'::jsonb)) THEN
            RAISE EXCEPTION 'drain notification digests and retire pinned tests and rule cadence/user targets before rollback' USING ERRCODE='55000';
        END IF;
    END LOOP;
END;
$$;
-- +goose StatementEnd
DROP INDEX IF EXISTS notification_digest_windows_pending_due;
DROP INDEX IF EXISTS notification_digest_windows_event;
DROP TABLE IF EXISTS notification_digest_windows;
DROP TABLE IF EXISTS notification_digest_members;
ALTER TABLE notification_events DROP CONSTRAINT IF EXISTS notification_events_test_template_object;
ALTER TABLE notification_events DROP COLUMN IF EXISTS test_template;
ALTER TABLE user_notifications DROP CONSTRAINT IF EXISTS user_notifications_recipient_roles_check;
ALTER TABLE user_notifications ADD CONSTRAINT user_notifications_recipient_roles_check CHECK (
    jsonb_typeof(recipient_roles)='array' AND recipient_roles <@ '["assignee","team_member","engagement_lead","mentioned_user","approver","tenant_admin"]'::jsonb
);
ALTER TABLE notification_rules DROP CONSTRAINT IF EXISTS notification_rules_recipient_user_ids_check;
ALTER TABLE notification_rules DROP COLUMN IF EXISTS recipient_user_ids;
ALTER TABLE notification_rules DROP CONSTRAINT IF EXISTS notification_rules_cadence_check;
ALTER TABLE notification_rules DROP COLUMN IF EXISTS cadence;
