-- +goose Up
-- #680 governed response attempt/action identity, terminal-claim safety, and deadlines.
-- This is the first unpublished migration after immutable 0137, so it incorporates the
-- complete response-attempt runtime while explicitly downgrading pre-journal 0076 actions.
ALTER TABLE response_actions NO FORCE ROW LEVEL SECURITY;
UPDATE response_actions
SET state = 'violation', verification = 'unknown', updated_at = now()
WHERE state = 'applied';
ALTER TABLE response_actions FORCE ROW LEVEL SECURITY;

ALTER TABLE response_actions
    ADD COLUMN reversibility_class TEXT,
    ADD COLUMN authorization_target JSONB,
    ADD COLUMN target_fingerprint JSONB,
    ADD COLUMN submitted_by TEXT NOT NULL DEFAULT '',
    ADD COLUMN reversal_requested_by TEXT NOT NULL DEFAULT '';

ALTER TABLE response_actions NO FORCE ROW LEVEL SECURITY;
UPDATE response_actions
SET reversibility_class = CASE kind
    WHEN 'stop_process' THEN 'best_effort'
    WHEN 'isolate_host' THEN 'compensating'
    WHEN 'quarantine_file' THEN 'compensating'
END;
ALTER TABLE response_actions FORCE ROW LEVEL SECURITY;

-- Keep this column nullable during the expand phase: pre-0138 API binaries omit it from
-- their INSERT list while the database has already migrated. The trigger fills only that
-- omission from the immutable response catalogue; explicit values remain constrained below.
-- +goose StatementBegin
CREATE FUNCTION synapse_response_actions_default_reversibility_class() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.reversibility_class IS NULL THEN
        NEW.reversibility_class = CASE NEW.kind
            WHEN 'stop_process' THEN 'best_effort'
            WHEN 'isolate_host' THEN 'compensating'
            WHEN 'quarantine_file' THEN 'compensating'
        END;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER response_actions_default_reversibility_class
    BEFORE INSERT ON response_actions
    FOR EACH ROW EXECUTE FUNCTION synapse_response_actions_default_reversibility_class();

ALTER TABLE response_actions
    ADD CONSTRAINT response_actions_reversibility_class_check CHECK (
        reversibility_class IS NULL OR
        (kind = 'stop_process' AND reversibility_class = 'best_effort') OR
        (kind IN ('isolate_host', 'quarantine_file') AND reversibility_class = 'compensating')
    );

CREATE TABLE response_halt_fences (
    tenant_id  TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    generation BIGINT NOT NULL DEFAULT 0 CHECK (generation >= 0),
    halted     BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CALL synapse_enable_tenant_rls('response_halt_fences');

-- +goose StatementBegin
CREATE FUNCTION response_halt_fences_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'response_halt_fences cannot be deleted';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
        RAISE EXCEPTION 'response_halt_fences tenant is immutable';
    END IF;
    IF NEW.generation < OLD.generation THEN
        RAISE EXCEPTION 'response_halt_fences generation cannot decrease';
    END IF;
    IF OLD.halted AND NOT NEW.halted THEN
        RAISE EXCEPTION 'response_halt_fences cannot clear a halt';
    END IF;
    IF NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'response_halt_fences updated_at cannot move backwards';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER response_halt_fences_guard_trigger
    BEFORE UPDATE OR DELETE ON response_halt_fences
    FOR EACH ROW EXECUTE FUNCTION response_halt_fences_guard();

-- +goose StatementBegin
CREATE FUNCTION response_halt_fences_no_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'response_halt_fences cannot be truncated';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER response_halt_fences_no_truncate_trigger
    BEFORE TRUNCATE ON response_halt_fences
    FOR EACH STATEMENT EXECUTE FUNCTION response_halt_fences_no_truncate();

CREATE TABLE response_attempts (
    tenant_id                     TEXT NOT NULL,
    action_id                     TEXT NOT NULL,
    attempt                       INTEGER NOT NULL CHECK (attempt >= 1),
    idempotency_key               TEXT NOT NULL,
    target_fingerprint            JSONB NOT NULL,
    is_reversal                   BOOLEAN NOT NULL DEFAULT FALSE,
    state                         TEXT NOT NULL CHECK (state IN (
        'proposed', 'awaiting_approval', 'approved', 'rejected', 'issued', 'claimed', 'executing',
        'command_applied', 'command_failed', 'outcome_unknown', 'verifying', 'verified_succeeded',
        'verification_failed', 'verification_unknown', 'timed_out', 'manual_intervention_required',
        'rollback_requested', 'rolling_back', 'rollback_verifying', 'rollback_outcome_unknown',
        'rolled_back', 'rollback_failed', 'completed'
    )),
    command_outcome               TEXT NOT NULL DEFAULT '',
    verification_outcome          TEXT NOT NULL DEFAULT '' CHECK (verification_outcome IN (
        '', 'succeeded', 'failed', 'unknown_insufficient_coverage', 'timed_out'
    )),
    created_at                    TIMESTAMPTZ NOT NULL,
    updated_at                    TIMESTAMPTZ NOT NULL,
    halt_generation               BIGINT NOT NULL DEFAULT 0 CHECK (halt_generation >= 0),
    observed_radius               TEXT NOT NULL DEFAULT '' CHECK (observed_radius IN ('', 'read_only', 'state_changing')),
    affected_count                INTEGER NOT NULL DEFAULT 0 CHECK (affected_count >= 0),
    already_applied               BOOLEAN NOT NULL DEFAULT FALSE,
    decided_by                    TEXT NOT NULL DEFAULT '',
    executor_id                   TEXT NOT NULL DEFAULT '',
    verifier_id                   TEXT NOT NULL DEFAULT '',
    verification_evidence_id      TEXT NOT NULL DEFAULT '',
    executor_agent_id             TEXT NOT NULL DEFAULT '',
    executor_identity_unavailable BOOLEAN NOT NULL DEFAULT FALSE,
    deadline_at                   TIMESTAMPTZ NOT NULL,
    terminal_reason               TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, idempotency_key),
    CONSTRAINT response_attempts_operation_key UNIQUE (tenant_id, action_id, is_reversal, attempt),
    FOREIGN KEY (tenant_id, action_id) REFERENCES response_actions(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT response_attempts_verified_receipt_check CHECK (
        state NOT IN ('verified_succeeded', 'rolled_back', 'completed') OR (
            verification_outcome = 'succeeded' AND
            btrim(verification_evidence_id) <> '' AND
            btrim(verifier_id) <> '' AND
            btrim(executor_id) <> '' AND
            lower(btrim(verifier_id)) <> lower(btrim(executor_id))
        )
    ),
    CONSTRAINT response_attempts_observed_effect_check CHECK (
        state NOT IN (
            'command_applied', 'verifying', 'verified_succeeded', 'verification_failed',
            'verification_unknown', 'timed_out', 'rollback_verifying', 'rolled_back', 'completed'
        ) OR (observed_radius <> '' AND affected_count <= 1 AND btrim(executor_id) <> '')
    ),
    CONSTRAINT response_attempts_executor_agent_check CHECK (
        (executor_identity_unavailable AND btrim(executor_agent_id) = '') OR
        (NOT executor_identity_unavailable AND btrim(executor_agent_id) <> '')
    ),
    CONSTRAINT response_attempts_deadline_check CHECK (deadline_at > created_at),
    CONSTRAINT response_attempts_terminal_reason_check CHECK (
        state <> 'manual_intervention_required' OR btrim(terminal_reason) <> ''
    )
);
CREATE INDEX idx_response_attempts_action ON response_attempts (tenant_id, action_id, is_reversal, attempt);
CALL synapse_enable_tenant_rls('response_attempts');

-- +goose StatementBegin
CREATE FUNCTION synapse_response_attempt_deadline_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.deadline_at IS DISTINCT FROM OLD.deadline_at THEN
        RAISE EXCEPTION 'response attempt timestamps are immutable';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER response_attempt_deadline_immutable
    BEFORE UPDATE ON response_attempts
    FOR EACH ROW EXECUTE FUNCTION synapse_response_attempt_deadline_immutable();

-- +goose Down
DROP TRIGGER IF EXISTS response_attempt_deadline_immutable ON response_attempts;
DROP FUNCTION IF EXISTS synapse_response_attempt_deadline_immutable();
DROP TABLE response_attempts;
DROP TRIGGER IF EXISTS response_halt_fences_no_truncate_trigger ON response_halt_fences;
DROP FUNCTION IF EXISTS response_halt_fences_no_truncate();
DROP TRIGGER IF EXISTS response_halt_fences_guard_trigger ON response_halt_fences;
DROP FUNCTION IF EXISTS response_halt_fences_guard();
DROP TABLE response_halt_fences;
DROP TRIGGER IF EXISTS response_actions_default_reversibility_class ON response_actions;
DROP FUNCTION IF EXISTS synapse_response_actions_default_reversibility_class();
ALTER TABLE response_actions
    DROP CONSTRAINT IF EXISTS response_actions_reversibility_class_check,
    DROP COLUMN reversal_requested_by,
    DROP COLUMN submitted_by,
    DROP COLUMN target_fingerprint,
    DROP COLUMN authorization_target,
    DROP COLUMN reversibility_class;
