-- +goose Up
CREATE INDEX ticket_intents_inbound_remote_done_create_idx
    ON ticket_intents(tenant_id,integration_id,remote_id)
    INCLUDE(mapping_id,id)
    WHERE state='done' AND action='create';
CREATE INDEX ticket_external_comments_finding_recent_idx
    ON ticket_external_comments(tenant_id,engagement_id,finding_id,created_at DESC,id DESC);

-- +goose Down
DROP INDEX ticket_external_comments_finding_recent_idx;
DROP INDEX ticket_intents_inbound_remote_done_create_idx;
