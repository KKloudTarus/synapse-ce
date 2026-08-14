-- +goose Up
-- The verdict transition and this outbox row commit together. The payload is the
-- exact idempotent audit entry to replay after an audit sink failure or crash.
CREATE TABLE judgment_verdict_audit_status (
    tenant_id     TEXT NOT NULL,
    judgment_id   TEXT NOT NULL,
    version       INTEGER NOT NULL,
    engagement_id TEXT NOT NULL,
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    target        TEXT NOT NULL,
    metadata      JSONB NOT NULL,
    occurred_at   TIMESTAMPTZ NOT NULL,
    completed_at  TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, judgment_id, version),
    CONSTRAINT jvas_version_positive CHECK (version >= 1),
    CONSTRAINT jvas_judgment_fk FOREIGN KEY (tenant_id, engagement_id, judgment_id)
        REFERENCES judgments(tenant_id, engagement_id, id) ON DELETE RESTRICT,
    CONSTRAINT jvas_tenant_fk FOREIGN KEY (tenant_id)
        REFERENCES tenants(id) ON DELETE RESTRICT
);

CREATE INDEX jvas_pending_engagement_idx
    ON judgment_verdict_audit_status (tenant_id, engagement_id, judgment_id, version)
    WHERE completed_at IS NULL;

CALL synapse_enable_tenant_rls('judgment_verdict_audit_status');

-- The generic RLS policy also permits UPDATE and DELETE. This outbox is immutable
-- except for one monotonic delivery acknowledgement, so use command-specific
-- policies and a trigger that remains effective for table owners.
DROP POLICY judgment_verdict_audit_status_tenant_isolation ON judgment_verdict_audit_status;
CREATE POLICY judgment_verdict_audit_status_tenant_select ON judgment_verdict_audit_status
    FOR SELECT USING (tenant_id = synapse_current_tenant());
CREATE POLICY judgment_verdict_audit_status_tenant_insert ON judgment_verdict_audit_status
    FOR INSERT WITH CHECK (tenant_id = synapse_current_tenant());
CREATE POLICY judgment_verdict_audit_status_tenant_update ON judgment_verdict_audit_status
    FOR UPDATE USING (tenant_id = synapse_current_tenant())
    WITH CHECK (tenant_id = synapse_current_tenant());

-- +goose StatementBegin
CREATE FUNCTION judgment_verdict_audit_status_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'judgment_verdict_audit_status is append-only';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.judgment_id IS DISTINCT FROM OLD.judgment_id
        OR NEW.version IS DISTINCT FROM OLD.version
        OR NEW.engagement_id IS DISTINCT FROM OLD.engagement_id
        OR NEW.actor IS DISTINCT FROM OLD.actor
        OR NEW.action IS DISTINCT FROM OLD.action
        OR NEW.target IS DISTINCT FROM OLD.target
        OR NEW.metadata IS DISTINCT FROM OLD.metadata
        OR NEW.occurred_at IS DISTINCT FROM OLD.occurred_at
        OR (OLD.completed_at IS NOT NULL AND NEW.completed_at IS DISTINCT FROM OLD.completed_at) THEN
        RAISE EXCEPTION 'judgment_verdict_audit_status immutable fields cannot change';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER judgment_verdict_audit_status_immutable_trigger
    BEFORE UPDATE OR DELETE ON judgment_verdict_audit_status
    FOR EACH ROW EXECUTE FUNCTION judgment_verdict_audit_status_immutable();

-- +goose StatementBegin
CREATE FUNCTION judgment_verdict_audit_status_no_truncate() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'judgment_verdict_audit_status is append-only';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER judgment_verdict_audit_status_no_truncate_trigger
    BEFORE TRUNCATE ON judgment_verdict_audit_status
    FOR EACH STATEMENT EXECUTE FUNCTION judgment_verdict_audit_status_no_truncate();

-- +goose Down
DROP TRIGGER IF EXISTS judgment_verdict_audit_status_no_truncate_trigger ON judgment_verdict_audit_status;
DROP FUNCTION IF EXISTS judgment_verdict_audit_status_no_truncate();
DROP TRIGGER IF EXISTS judgment_verdict_audit_status_immutable_trigger ON judgment_verdict_audit_status;
DROP FUNCTION IF EXISTS judgment_verdict_audit_status_immutable();
DROP POLICY IF EXISTS judgment_verdict_audit_status_tenant_update ON judgment_verdict_audit_status;
DROP POLICY IF EXISTS judgment_verdict_audit_status_tenant_insert ON judgment_verdict_audit_status;
DROP POLICY IF EXISTS judgment_verdict_audit_status_tenant_select ON judgment_verdict_audit_status;
DROP INDEX IF EXISTS jvas_pending_engagement_idx;
DROP TABLE IF EXISTS judgment_verdict_audit_status;
