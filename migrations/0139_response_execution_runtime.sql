-- +goose Up
-- #680 response work-order execution, fencing delivery, audit obligations, observer authorization,
-- and independently recorded verification receipts.
CREATE TABLE response_audit_intents (
    tenant_id    TEXT NOT NULL,
    intent_id    TEXT NOT NULL,
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    target       TEXT NOT NULL,
    metadata     JSONB NOT NULL,
    occurred_at  TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, intent_id),
    CONSTRAINT rai_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT,
    CONSTRAINT rai_intent_id_nonempty CHECK (btrim(intent_id) <> ''),
    CONSTRAINT rai_actor_nonempty CHECK (btrim(actor) <> ''),
    CONSTRAINT rai_action_nonempty CHECK (btrim(action) <> ''),
    CONSTRAINT rai_target_nonempty CHECK (btrim(target) <> ''),
    CONSTRAINT rai_idempotency_identity CHECK (metadata->>'idempotency_key' = intent_id)
);
CREATE INDEX rai_pending_idx ON response_audit_intents (tenant_id, occurred_at, intent_id) WHERE completed_at IS NULL;
CALL synapse_enable_tenant_rls('response_audit_intents');
DROP POLICY response_audit_intents_tenant_isolation ON response_audit_intents;
CREATE POLICY response_audit_intents_tenant_select ON response_audit_intents FOR SELECT USING (tenant_id = synapse_current_tenant());
CREATE POLICY response_audit_intents_tenant_insert ON response_audit_intents FOR INSERT WITH CHECK (tenant_id = synapse_current_tenant());
CREATE POLICY response_audit_intents_tenant_update ON response_audit_intents FOR UPDATE USING (tenant_id = synapse_current_tenant()) WITH CHECK (tenant_id = synapse_current_tenant());

-- +goose StatementBegin
CREATE FUNCTION response_audit_intents_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.completed_at IS NULL THEN
            RAISE EXCEPTION 'response_audit_intents cannot delete an undelivered audit intention';
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
        RAISE EXCEPTION 'response_audit_intents immutable fields cannot change';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER response_audit_intents_immutable_trigger
    BEFORE UPDATE OR DELETE ON response_audit_intents
    FOR EACH ROW EXECUTE FUNCTION response_audit_intents_immutable();

-- +goose StatementBegin
CREATE FUNCTION response_audit_intents_no_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'response_audit_intents is append-only';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER response_audit_intents_no_truncate_trigger
    BEFORE TRUNCATE ON response_audit_intents
    FOR EACH STATEMENT EXECUTE FUNCTION response_audit_intents_no_truncate();

CREATE TABLE response_halt_dispatches (
    tenant_id    TEXT NOT NULL,
    generation   BIGINT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, generation),
    CONSTRAINT rhd_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT,
    CONSTRAINT rhd_generation_positive CHECK (generation > 0)
);
-- Dispatches are immutable delivery obligations. Replaying a signed halt fence is
-- idempotent, whereas a same-role database acknowledgement would be forgeable.
CREATE INDEX rhd_dispatch_idx ON response_halt_dispatches (tenant_id, generation);
CALL synapse_enable_tenant_rls('response_halt_dispatches');
DROP POLICY response_halt_dispatches_tenant_isolation ON response_halt_dispatches;
CREATE POLICY response_halt_dispatches_tenant_select ON response_halt_dispatches FOR SELECT USING (tenant_id = synapse_current_tenant());
CREATE POLICY response_halt_dispatches_tenant_insert ON response_halt_dispatches FOR INSERT WITH CHECK (tenant_id = synapse_current_tenant());

-- +goose StatementBegin
CREATE FUNCTION response_halt_dispatches_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'response_halt_dispatches cannot be deleted';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.generation IS DISTINCT FROM OLD.generation
        OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'response_halt_dispatches immutable fields cannot change';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER response_halt_dispatches_immutable_trigger
    BEFORE UPDATE OR DELETE ON response_halt_dispatches
    FOR EACH ROW EXECUTE FUNCTION response_halt_dispatches_immutable();

-- +goose StatementBegin
CREATE FUNCTION response_halt_dispatches_no_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'response_halt_dispatches is append-only';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER response_halt_dispatches_no_truncate_trigger
    BEFORE TRUNCATE ON response_halt_dispatches
    FOR EACH STATEMENT EXECUTE FUNCTION response_halt_dispatches_no_truncate();

ALTER TABLE response_attempts
    ADD COLUMN verification_challenge TEXT NOT NULL DEFAULT '' CHECK (verification_challenge = '' OR verification_challenge ~ '^[0-9a-f]{64}$');
CREATE UNIQUE INDEX idx_response_attempts_verification_challenge
    ON response_attempts (tenant_id, verification_challenge) WHERE verification_challenge <> '';

CREATE TABLE response_verification_observations (
    tenant_id              TEXT NOT NULL REFERENCES tenants(id),
    report_id              TEXT NOT NULL,
    attempt_key            TEXT NOT NULL,
    verification_challenge TEXT NOT NULL CHECK (verification_challenge ~ '^[0-9a-f]{64}$'),
    action_id              TEXT NOT NULL,
    engagement_id          TEXT NOT NULL,
    agent_id               TEXT NOT NULL,
    asset_id               TEXT NOT NULL,
    observer_id            TEXT NOT NULL,
    observed_at            TIMESTAMPTZ NOT NULL,
    recorded_at            TIMESTAMPTZ NOT NULL,
    signed_content_digest  TEXT NOT NULL CHECK (signed_content_digest ~ '^[0-9a-f]{64}$'),
    report                 JSONB NOT NULL,
    PRIMARY KEY (tenant_id, report_id),
    UNIQUE (tenant_id, attempt_key),
    UNIQUE (tenant_id, verification_challenge)
);
CREATE INDEX idx_response_verification_action ON response_verification_observations (tenant_id, action_id, observed_at);
CALL synapse_enable_tenant_rls('response_verification_observations');
CREATE TRIGGER response_verification_observations_append_only
    BEFORE UPDATE OR DELETE ON response_verification_observations
    FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER response_verification_observations_no_truncate
    BEFORE TRUNCATE ON response_verification_observations
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

ALTER TABLE work_orders
    ADD COLUMN priority INTEGER NOT NULL DEFAULT 0 CHECK (priority >= 0),
    ADD COLUMN response_command JSONB,
    ADD COLUMN lease_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN lease_until TIMESTAMPTZ,
    ADD COLUMN response_result JSONB,
    ADD COLUMN response_halt_command JSONB,
    ADD COLUMN response_observation JSONB;
ALTER TABLE work_orders ADD CONSTRAINT work_orders_response_command_check CHECK (
    (capability = 'response.process' AND priority = 100 AND response_command IS NOT NULL AND response_halt_command IS NULL AND response_observation IS NULL) OR
    (capability = 'response.halt' AND priority = 200 AND response_command IS NULL AND response_halt_command IS NOT NULL AND response_observation IS NULL) OR
    (capability = 'response.observe' AND priority = 150 AND response_command IS NULL AND response_halt_command IS NULL AND response_observation IS NOT NULL) OR
    (capability NOT IN ('response.process', 'response.halt', 'response.observe') AND priority = 0 AND response_command IS NULL AND response_halt_command IS NULL AND response_observation IS NULL)
);
ALTER TABLE work_orders ADD CONSTRAINT work_orders_response_result_check CHECK (
    response_result IS NULL OR (capability = 'response.process' AND response_command IS NOT NULL AND state IN ('succeeded', 'failed'))
);

CREATE TABLE response_observer_bindings (
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    agent_id    TEXT NOT NULL,
    asset_id    TEXT NOT NULL,
    assigned_by TEXT NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    version     INTEGER NOT NULL CHECK (version > 0),
    PRIMARY KEY (tenant_id, agent_id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES fleet_agents(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, asset_id) REFERENCES fleet_assets(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT response_observer_binding_actor_nonempty CHECK (btrim(assigned_by) <> ''),
    CONSTRAINT response_observer_binding_window CHECK (assigned_at < expires_at)
);
CREATE INDEX response_observer_bindings_asset_idx ON response_observer_bindings (tenant_id, asset_id, expires_at);
CALL synapse_enable_tenant_rls('response_observer_bindings');

-- +goose Down
-- Preserve append-only audit and halt history: reject the rollback before removing any dependent runtime schema.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM response_halt_dispatches) THEN
        RAISE EXCEPTION 'cannot roll back 0139: response halt dispatch history exists';
    END IF;
    IF EXISTS (SELECT 1 FROM response_audit_intents) THEN
        RAISE EXCEPTION 'cannot roll back 0139: response audit intention history exists';
    END IF;
END;
$$;
-- +goose StatementEnd
DROP TABLE response_observer_bindings;
ALTER TABLE work_orders DROP CONSTRAINT work_orders_response_result_check;
ALTER TABLE work_orders DROP CONSTRAINT work_orders_response_command_check;
DELETE FROM work_orders WHERE capability IN ('response.process', 'response.halt', 'response.observe');
ALTER TABLE work_orders
    DROP COLUMN response_observation,
    DROP COLUMN response_halt_command,
    DROP COLUMN response_result,
    DROP COLUMN lease_until,
    DROP COLUMN lease_id,
    DROP COLUMN response_command,
    DROP COLUMN priority;
DROP TRIGGER IF EXISTS response_verification_observations_no_truncate ON response_verification_observations;
DROP TRIGGER IF EXISTS response_verification_observations_append_only ON response_verification_observations;
DROP TABLE response_verification_observations;
DROP INDEX IF EXISTS idx_response_attempts_verification_challenge;
ALTER TABLE response_attempts DROP COLUMN verification_challenge;
DROP TRIGGER IF EXISTS response_halt_dispatches_no_truncate_trigger ON response_halt_dispatches;
DROP FUNCTION IF EXISTS response_halt_dispatches_no_truncate();
DROP TRIGGER IF EXISTS response_halt_dispatches_immutable_trigger ON response_halt_dispatches;
DROP FUNCTION IF EXISTS response_halt_dispatches_immutable();
DROP POLICY IF EXISTS response_halt_dispatches_tenant_update ON response_halt_dispatches;
DROP POLICY IF EXISTS response_halt_dispatches_tenant_insert ON response_halt_dispatches;
DROP POLICY IF EXISTS response_halt_dispatches_tenant_select ON response_halt_dispatches;
DROP INDEX IF EXISTS rhd_dispatch_idx;
DROP TABLE response_halt_dispatches;
DROP TRIGGER IF EXISTS response_audit_intents_no_truncate_trigger ON response_audit_intents;
DROP FUNCTION IF EXISTS response_audit_intents_no_truncate();
DROP TRIGGER IF EXISTS response_audit_intents_immutable_trigger ON response_audit_intents;
DROP FUNCTION IF EXISTS response_audit_intents_immutable();
DROP POLICY IF EXISTS response_audit_intents_tenant_update ON response_audit_intents;
DROP POLICY IF EXISTS response_audit_intents_tenant_insert ON response_audit_intents;
DROP POLICY IF EXISTS response_audit_intents_tenant_select ON response_audit_intents;
DROP INDEX IF EXISTS rai_pending_idx;
DROP TABLE response_audit_intents;
