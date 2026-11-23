-- +goose Up
CREATE TABLE notification_pager_episodes (
 tenant_id TEXT NOT NULL REFERENCES tenants(id), subject_kind TEXT NOT NULL CHECK(subject_kind IN ('finding','incident')),
 subject_id TEXT NOT NULL CHECK(subject_id<>''), episode BIGINT NOT NULL CHECK(episode>0),
 terminal_event_id TEXT,
 PRIMARY KEY(tenant_id,subject_kind,subject_id,episode),
 FOREIGN KEY(tenant_id,terminal_event_id) REFERENCES notification_events(tenant_id,id) ON DELETE RESTRICT
);
CALL synapse_enable_tenant_rls('notification_pager_episodes');
CREATE TABLE notification_pager_operations (
 tenant_id TEXT NOT NULL, delivery_id TEXT NOT NULL, subject_kind TEXT NOT NULL, subject_id TEXT NOT NULL,
 episode BIGINT NOT NULL, channel_id TEXT NOT NULL, channel_version INT NOT NULL CHECK(channel_version>0),
 is_close BOOLEAN NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','sending','confirming','done','unknown','failed','suppressed')),
 operation_id TEXT NOT NULL DEFAULT '', provider_request_ref TEXT NOT NULL DEFAULT '', remote_ref TEXT NOT NULL DEFAULT '', blocked_reason TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(tenant_id,delivery_id),
 FOREIGN KEY(tenant_id,subject_kind,subject_id,episode) REFERENCES notification_pager_episodes(tenant_id,subject_kind,subject_id,episode),
 FOREIGN KEY(tenant_id,delivery_id) REFERENCES notification_deliveries(tenant_id,id),
 FOREIGN KEY(tenant_id,channel_id,channel_version) REFERENCES notification_channel_versions(tenant_id,channel_id,version),
 CHECK(octet_length(provider_request_ref)<=512 AND octet_length(remote_ref)<=512)
);
CREATE UNIQUE INDEX notification_pager_close_once ON notification_pager_operations(tenant_id,subject_kind,subject_id,episode,channel_id) WHERE is_close;
CREATE UNIQUE INDEX notification_pager_lane_inflight ON notification_pager_operations(tenant_id,subject_kind,subject_id,episode,channel_id) WHERE state IN ('sending','confirming','unknown');
CREATE INDEX notification_pager_lane_lookup ON notification_pager_operations(tenant_id,subject_kind,subject_id,episode,channel_id,state);
CALL synapse_enable_tenant_rls('notification_pager_operations');
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'pager obligations require forward recovery' USING ERRCODE='55000'; END $$;
-- +goose StatementEnd
