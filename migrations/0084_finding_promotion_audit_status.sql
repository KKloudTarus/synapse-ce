-- +goose Up
-- Tracks delivery of the required, idempotent audit record separately from the
-- append-only lifecycle event. The row is inserted in the same transaction as
-- the finding mutation and event; completion is retried after crashes.
ALTER TABLE finding_promotion_events
    ADD CONSTRAINT fpe_tenant_id_unique UNIQUE (tenant_id, id);

CREATE TABLE finding_promotion_audit_status (
    tenant_id    TEXT NOT NULL,
    event_id     TEXT NOT NULL,
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, event_id),
    CONSTRAINT fpas_event_fk FOREIGN KEY (tenant_id, event_id)
        REFERENCES finding_promotion_events(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT fpas_tenant_fk FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
);

INSERT INTO finding_promotion_audit_status (tenant_id, event_id)
    SELECT tenant_id, id FROM finding_promotion_events;

CREATE INDEX fpas_pending_idx
    ON finding_promotion_audit_status (tenant_id, event_id)
    WHERE completed_at IS NULL;

CALL synapse_enable_tenant_rls('finding_promotion_audit_status');

-- +goose Down
DROP INDEX IF EXISTS fpas_pending_idx;
ALTER TABLE finding_promotion_audit_status DROP CONSTRAINT IF EXISTS fpas_tenant_fk;
ALTER TABLE finding_promotion_audit_status DROP CONSTRAINT IF EXISTS fpas_event_fk;
DROP TABLE IF EXISTS finding_promotion_audit_status;
ALTER TABLE finding_promotion_events DROP CONSTRAINT IF EXISTS fpe_tenant_id_unique;
