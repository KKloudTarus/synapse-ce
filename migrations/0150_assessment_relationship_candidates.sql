-- +goose Up
-- A9e (#720): append-only historical Assessment relationship candidates, decisions, and blocked repair plans.

ALTER TABLE assessment_snapshots
    ADD CONSTRAINT assessment_snapshots_relationship_candidate_owner_unique
    UNIQUE (tenant_id, cycle_id, assessment_id, id);

CREATE TABLE assessment_relationship_candidates (
    tenant_id                         TEXT NOT NULL,
    id                                TEXT NOT NULL,
    predecessor_cycle_id              TEXT NOT NULL,
    predecessor_assessment_id         TEXT NOT NULL,
    predecessor_relationship_version  BIGINT NOT NULL CHECK (predecessor_relationship_version >= 1),
    predecessor_snapshot_id           TEXT NOT NULL,
    predecessor_snapshot_hash         TEXT NOT NULL CHECK (predecessor_snapshot_hash ~ '^[0-9a-f]{64}$'),
    successor_cycle_id                TEXT NOT NULL,
    successor_assessment_id           TEXT NOT NULL,
    successor_relationship_version    BIGINT NOT NULL CHECK (successor_relationship_version >= 1),
    successor_snapshot_id             TEXT NOT NULL,
    successor_snapshot_hash           TEXT NOT NULL CHECK (successor_snapshot_hash ~ '^[0-9a-f]{64}$'),
    boundary_key_hash                 TEXT NOT NULL CHECK (boundary_key_hash ~ '^[0-9a-f]{64}$'),
    signals                           JSONB NOT NULL,
    input_hash                        TEXT NOT NULL CHECK (input_hash ~ '^[0-9a-f]{64}$'),
    confidence                        TEXT NOT NULL CHECK (confidence IN ('medium','high')),
    expires_at                        TIMESTAMPTZ NOT NULL,
    created_by                        TEXT NOT NULL,
    created_at                        TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, input_hash),
    UNIQUE (tenant_id, id, input_hash),
    FOREIGN KEY (tenant_id, predecessor_cycle_id, predecessor_assessment_id)
        REFERENCES assessment_cycle_members(tenant_id, cycle_id, assessment_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, successor_cycle_id, successor_assessment_id)
        REFERENCES assessment_cycle_members(tenant_id, cycle_id, assessment_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, predecessor_cycle_id, predecessor_assessment_id, predecessor_snapshot_id)
        REFERENCES assessment_snapshots(tenant_id, cycle_id, assessment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, successor_cycle_id, successor_assessment_id, successor_snapshot_id)
        REFERENCES assessment_snapshots(tenant_id, cycle_id, assessment_id, id) ON DELETE RESTRICT,
    CONSTRAINT assessment_relationship_candidates_subject_check CHECK (
        predecessor_cycle_id <> successor_cycle_id AND predecessor_assessment_id <> successor_assessment_id
    ),
    CONSTRAINT assessment_relationship_candidates_signals_check CHECK (
        jsonb_typeof(signals) = 'array' AND jsonb_array_length(signals) BETWEEN 2 AND 4 AND octet_length(signals::text) <= 4096
    ),
    CONSTRAINT assessment_relationship_candidates_actor_check CHECK (
        created_by = btrim(created_by) AND length(created_by) BETWEEN 1 AND 256
    ),
    CONSTRAINT assessment_relationship_candidates_expiry_check CHECK (
        expires_at >= created_at + INTERVAL '1 day' AND expires_at <= created_at + INTERVAL '90 days'
    )
);

CREATE INDEX idx_assessment_relationship_candidates_review
    ON assessment_relationship_candidates (tenant_id, created_at DESC, id DESC);
CREATE INDEX idx_assessment_relationship_candidates_expiry
    ON assessment_relationship_candidates (tenant_id, expires_at, id);

CREATE TABLE assessment_relationship_repair_plans (
    tenant_id     TEXT NOT NULL,
    id            TEXT NOT NULL,
    candidate_id  TEXT NOT NULL,
    input_hash    TEXT NOT NULL CHECK (input_hash ~ '^[0-9a-f]{64}$'),
    plan_hash     TEXT NOT NULL CHECK (plan_hash ~ '^[0-9a-f]{64}$'),
    body          BYTEA NOT NULL,
    created_by    TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, candidate_id),
    UNIQUE (tenant_id, candidate_id, id),
    FOREIGN KEY (tenant_id, candidate_id, input_hash)
        REFERENCES assessment_relationship_candidates(tenant_id, id, input_hash) ON DELETE RESTRICT,
    CONSTRAINT assessment_relationship_repair_plans_body_check CHECK (
        octet_length(body) <= 8192 AND
        jsonb_typeof(convert_from(body, 'UTF8')::jsonb) = 'object' AND
        convert_from(body, 'UTF8')::jsonb->>'execution' = 'blocked' AND
        convert_from(body, 'UTF8')::jsonb->>'requires' = 'separately_approved_move_merge_command'
    ),
    CONSTRAINT assessment_relationship_repair_plans_actor_check CHECK (
        created_by = btrim(created_by) AND length(created_by) BETWEEN 1 AND 256
    )
);

CREATE TABLE assessment_relationship_decisions (
    tenant_id          TEXT NOT NULL,
    id                 TEXT NOT NULL,
    candidate_id       TEXT NOT NULL,
    action             TEXT NOT NULL CHECK (action IN ('confirm','reject','dismiss')),
    actor              TEXT NOT NULL,
    reason             TEXT NOT NULL,
    idempotency_key    TEXT NOT NULL,
    request_hash       TEXT NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    expected_version   BIGINT NOT NULL CHECK (expected_version = 1),
    version            BIGINT NOT NULL CHECK (version = 2),
    repair_plan_id     TEXT,
    created_at         TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, candidate_id),
    UNIQUE (tenant_id, candidate_id, actor, idempotency_key),
    FOREIGN KEY (tenant_id, candidate_id)
        REFERENCES assessment_relationship_candidates(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, candidate_id, repair_plan_id)
        REFERENCES assessment_relationship_repair_plans(tenant_id, candidate_id, id) ON DELETE RESTRICT,
    CONSTRAINT assessment_relationship_decisions_actor_check CHECK (
        actor = btrim(actor) AND length(actor) BETWEEN 1 AND 256
    ),
    CONSTRAINT assessment_relationship_decisions_reason_check CHECK (
        reason = btrim(reason) AND length(reason) BETWEEN 1 AND 2000
    ),
    CONSTRAINT assessment_relationship_decisions_idempotency_check CHECK (
        idempotency_key = btrim(idempotency_key) AND length(idempotency_key) BETWEEN 1 AND 128
    ),
    CONSTRAINT assessment_relationship_decisions_plan_check CHECK (
        (action = 'confirm' AND repair_plan_id IS NOT NULL) OR
        (action IN ('reject','dismiss') AND repair_plan_id IS NULL)
    )
);

CREATE TRIGGER assessment_relationship_candidates_append_only
BEFORE UPDATE OR DELETE ON assessment_relationship_candidates
FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER assessment_relationship_candidates_no_truncate
BEFORE TRUNCATE ON assessment_relationship_candidates
FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

CREATE TRIGGER assessment_relationship_repair_plans_append_only
BEFORE UPDATE OR DELETE ON assessment_relationship_repair_plans
FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER assessment_relationship_repair_plans_no_truncate
BEFORE TRUNCATE ON assessment_relationship_repair_plans
FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

CREATE TRIGGER assessment_relationship_decisions_append_only
BEFORE UPDATE OR DELETE ON assessment_relationship_decisions
FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER assessment_relationship_decisions_no_truncate
BEFORE TRUNCATE ON assessment_relationship_decisions
FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

CALL synapse_enable_tenant_rls('assessment_relationship_candidates');
CALL synapse_enable_tenant_rls('assessment_relationship_repair_plans');
CALL synapse_enable_tenant_rls('assessment_relationship_decisions');

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM assessment_relationship_candidates LIMIT 1) OR
       EXISTS (SELECT 1 FROM assessment_relationship_repair_plans LIMIT 1) OR
       EXISTS (SELECT 1 FROM assessment_relationship_decisions LIMIT 1) THEN
        RAISE EXCEPTION 'cannot roll back assessment relationship review while artifacts exist';
    END IF;
END;
$$;
-- +goose StatementEnd

DROP TABLE IF EXISTS assessment_relationship_decisions;
DROP TABLE IF EXISTS assessment_relationship_repair_plans;
DROP TABLE IF EXISTS assessment_relationship_candidates;

ALTER TABLE assessment_snapshots
    DROP CONSTRAINT IF EXISTS assessment_snapshots_relationship_candidate_owner_unique;
