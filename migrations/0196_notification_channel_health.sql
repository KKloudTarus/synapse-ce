-- +goose Up
-- Channel health and automatic pause (#1464). The delivery worker counts consecutive permanent
-- failures a channel owns; at the threshold it pauses the channel, cancels its queued deliveries
-- and tells tenant administrators. Health is system state, not configuration, so it does not bump
-- the channel revision. Codes are bounded identifiers: no destination, response body or error
-- text is stored here.
ALTER TABLE notification_channels
    ADD COLUMN consecutive_permanent_failures INT NOT NULL DEFAULT 0
        CHECK (consecutive_permanent_failures >= 0),
    ADD COLUMN last_failure_code TEXT NOT NULL DEFAULT ''
        CHECK (last_failure_code ~ '^[a-z0-9_-]{0,64}$'),
    ADD COLUMN last_failure_at TIMESTAMPTZ,
    ADD COLUMN paused_at TIMESTAMPTZ,
    ADD COLUMN paused_reason TEXT
        CHECK (paused_reason IS NULL OR paused_reason ~ '^[a-z0-9_]{1,64}$'),
    ADD CONSTRAINT notification_channels_pause_pair CHECK ((paused_at IS NULL) = (paused_reason IS NULL));

-- Append-only pause and resume history. A pause names the delivery and attempt that tripped it; a
-- resume names the administrator who cleared it.
CREATE TABLE notification_channel_health_events (
    tenant_id    TEXT NOT NULL,
    id           TEXT NOT NULL,
    channel_id   TEXT NOT NULL,
    action       TEXT NOT NULL CHECK (action IN ('paused','resumed')),
    reason       TEXT NOT NULL DEFAULT '' CHECK (reason ~ '^[a-z0-9_]{0,64}$'),
    failure_code TEXT NOT NULL DEFAULT '' CHECK (failure_code ~ '^[a-z0-9_-]{0,64}$'),
    failures     INT NOT NULL DEFAULT 0 CHECK (failures >= 0),
    delivery_id  TEXT,
    attempt_id   TEXT,
    actor        TEXT NOT NULL CHECK (length(btrim(actor)) BETWEEN 1 AND 200),
    occurred_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,id),
    FOREIGN KEY (tenant_id,channel_id) REFERENCES notification_channels(tenant_id,id) ON DELETE CASCADE,
    CHECK (action <> 'paused' OR (reason <> '' AND delivery_id IS NOT NULL AND attempt_id IS NOT NULL))
);
CREATE INDEX notification_channel_health_events_channel
    ON notification_channel_health_events(tenant_id,channel_id,occurred_at DESC,id DESC);
CALL synapse_enable_tenant_rls('notification_channel_health_events');

-- +goose StatementBegin
CREATE FUNCTION notification_channel_health_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'notification channel health history is append-only';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER notification_channel_health_guard BEFORE UPDATE OR DELETE ON notification_channel_health_events
    FOR EACH ROW EXECUTE FUNCTION notification_channel_health_guard();

-- +goose Down
DROP TABLE notification_channel_health_events;
DROP FUNCTION notification_channel_health_guard();
ALTER TABLE notification_channels
    DROP CONSTRAINT notification_channels_pause_pair,
    DROP COLUMN paused_reason,
    DROP COLUMN paused_at,
    DROP COLUMN last_failure_at,
    DROP COLUMN last_failure_code,
    DROP COLUMN consecutive_permanent_failures;
