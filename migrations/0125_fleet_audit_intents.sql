-- +goose Up
-- Fleet mutations and their exact audit intentions commit together. Delivery to
-- the append-only audit chain may be retried independently after a crash.
CREATE TABLE fleet_audit_intents (
    tenant_id    TEXT NOT NULL,
    intent_id    TEXT NOT NULL,
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    target       TEXT NOT NULL,
    metadata     JSONB NOT NULL,
    occurred_at  TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, intent_id),
    CONSTRAINT fai_tenant_fk FOREIGN KEY (tenant_id)
        REFERENCES tenants(id) ON DELETE RESTRICT,
    CONSTRAINT fai_intent_id_nonempty CHECK (btrim(intent_id) <> ''),
    CONSTRAINT fai_actor_nonempty CHECK (btrim(actor) <> ''),
    CONSTRAINT fai_action_nonempty CHECK (btrim(action) <> ''),
    CONSTRAINT fai_target_nonempty CHECK (btrim(target) <> ''),
    CONSTRAINT fai_idempotency_identity CHECK (metadata->>'idempotency_key' = intent_id)
);

CREATE INDEX fai_pending_idx
    ON fleet_audit_intents (tenant_id, occurred_at, intent_id)
    WHERE completed_at IS NULL;

CALL synapse_enable_tenant_rls('fleet_audit_intents');
DROP POLICY fleet_audit_intents_tenant_isolation ON fleet_audit_intents;
CREATE POLICY fleet_audit_intents_tenant_select ON fleet_audit_intents
    FOR SELECT USING (tenant_id = synapse_current_tenant());
CREATE POLICY fleet_audit_intents_tenant_insert ON fleet_audit_intents
    FOR INSERT WITH CHECK (tenant_id = synapse_current_tenant());
CREATE POLICY fleet_audit_intents_tenant_update ON fleet_audit_intents
    FOR UPDATE USING (tenant_id = synapse_current_tenant())
    WITH CHECK (tenant_id = synapse_current_tenant());

-- +goose StatementBegin
CREATE FUNCTION fleet_audit_intents_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Retention may reclaim an intention that already reached the audit chain, because
    -- the chain is the permanent record and this table is only the delivery guarantee.
    -- A PENDING intention is the sole durable proof that committed state still owes an
    -- audit entry, so deleting one would silently destroy that obligation.
    IF TG_OP = 'DELETE' THEN
        IF OLD.completed_at IS NULL THEN
            RAISE EXCEPTION 'fleet_audit_intents cannot delete an undelivered audit intention';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.intent_id IS DISTINCT FROM OLD.intent_id
        OR NEW.actor IS DISTINCT FROM OLD.actor
        OR NEW.action IS DISTINCT FROM OLD.action
        OR NEW.target IS DISTINCT FROM OLD.target
        OR NEW.metadata IS DISTINCT FROM OLD.metadata
        OR NEW.occurred_at IS DISTINCT FROM OLD.occurred_at
        OR (OLD.completed_at IS NOT NULL AND NEW.completed_at IS DISTINCT FROM OLD.completed_at) THEN
        RAISE EXCEPTION 'fleet_audit_intents immutable fields cannot change';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER fleet_audit_intents_immutable_trigger
    BEFORE UPDATE OR DELETE ON fleet_audit_intents
    FOR EACH ROW EXECUTE FUNCTION fleet_audit_intents_immutable();

-- +goose StatementBegin
CREATE FUNCTION fleet_audit_intents_no_truncate() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'fleet_audit_intents is append-only';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER fleet_audit_intents_no_truncate_trigger
    BEFORE TRUNCATE ON fleet_audit_intents
    FOR EACH STATEMENT EXECUTE FUNCTION fleet_audit_intents_no_truncate();

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM fleet_audit_intents) THEN
        RAISE EXCEPTION 'cannot roll back 0125: fleet audit intention history exists';
    END IF;
END;
$$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS fleet_audit_intents_no_truncate_trigger ON fleet_audit_intents;
DROP FUNCTION IF EXISTS fleet_audit_intents_no_truncate();
DROP TRIGGER IF EXISTS fleet_audit_intents_immutable_trigger ON fleet_audit_intents;
DROP FUNCTION IF EXISTS fleet_audit_intents_immutable();
DROP POLICY IF EXISTS fleet_audit_intents_tenant_update ON fleet_audit_intents;
DROP POLICY IF EXISTS fleet_audit_intents_tenant_insert ON fleet_audit_intents;
DROP POLICY IF EXISTS fleet_audit_intents_tenant_select ON fleet_audit_intents;
DROP INDEX IF EXISTS fai_pending_idx;
DROP TABLE IF EXISTS fleet_audit_intents;
