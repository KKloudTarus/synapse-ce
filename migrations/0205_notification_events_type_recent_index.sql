-- +goose NO TRANSACTION
-- +goose Up
-- The template preview (#1372) lists a tenant's newest events of one type. Without this index the
-- query reads every event of the tenant. It is built concurrently so a large notification_events
-- table keeps accepting events while it builds; a failed build can leave an invalid index behind,
-- so it is dropped before retrying.
DROP INDEX CONCURRENTLY IF EXISTS notification_events_type_recent_idx;
CREATE INDEX CONCURRENTLY notification_events_type_recent_idx
    ON notification_events (tenant_id, event_type, occurred_at DESC, id DESC);

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS notification_events_type_recent_idx;
