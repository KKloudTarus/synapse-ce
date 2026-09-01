-- +goose Up
-- A4 (#698): durable immutable ancestry-aware Assessment Comparisons.

CREATE TABLE assessment_comparisons (
    tenant_id                TEXT NOT NULL,
    cycle_id                 TEXT NOT NULL,
    id                       TEXT NOT NULL,
    baseline_snapshot_id     TEXT NOT NULL,
    current_snapshot_id      TEXT NOT NULL,
    mode                     TEXT NOT NULL CHECK (mode IN ('lifecycle','neutral_diff')),
    input_hash               TEXT NOT NULL CHECK (input_hash ~ '^[0-9a-f]{64}$'),
    input_payload            JSONB NOT NULL CHECK (jsonb_typeof(input_payload) = 'object' AND octet_length(input_payload::text) <= 65536),
    algorithm_version        INTEGER NOT NULL CHECK (algorithm_version > 0),
    fingerprint_version      INTEGER NOT NULL CHECK (fingerprint_version > 0),
    risk_model_version       INTEGER NOT NULL CHECK (risk_model_version > 0),
    coverage_policy_version  INTEGER NOT NULL CHECK (coverage_policy_version > 0),
    status                   TEXT NOT NULL CHECK (status IN ('queued','generating','complete','needs_review','failed','superseded')),
    version                  BIGINT NOT NULL CHECK (version > 0),
    attempts                 INTEGER NOT NULL CHECK (attempts >= 0),
    failure_code             TEXT NOT NULL DEFAULT '' CHECK (octet_length(failure_code) <= 64),
    content_hash             TEXT NOT NULL DEFAULT '' CHECK (content_hash = '' OR content_hash ~ '^[0-9a-f]{64}$'),
    summary                  JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(summary) = 'object'),
    created_at               TIMESTAMPTZ NOT NULL,
    updated_at               TIMESTAMPTZ NOT NULL,
    completed_at             TIMESTAMPTZ,
    superseded_at            TIMESTAMPTZ,
    superseded_by            TEXT,
    PRIMARY KEY (tenant_id, cycle_id, id),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, input_hash),
    FOREIGN KEY (tenant_id, cycle_id) REFERENCES assessment_cycles(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, baseline_snapshot_id) REFERENCES assessment_snapshots(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, current_snapshot_id) REFERENCES assessment_snapshots(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, superseded_by) REFERENCES assessment_comparisons(tenant_id, cycle_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT assessment_comparisons_distinct_snapshots CHECK (baseline_snapshot_id <> current_snapshot_id),
    CONSTRAINT assessment_comparisons_state_metadata CHECK (
        (status IN ('queued','generating') AND failure_code = '' AND content_hash = '' AND summary = '{}'::jsonb AND completed_at IS NULL AND superseded_at IS NULL AND superseded_by IS NULL) OR
        (status IN ('complete','needs_review') AND failure_code = '' AND content_hash <> '' AND completed_at IS NOT NULL AND superseded_at IS NULL AND superseded_by IS NULL) OR
        (status = 'failed' AND failure_code <> '' AND content_hash = '' AND summary = '{}'::jsonb AND completed_at IS NULL AND superseded_at IS NULL AND superseded_by IS NULL) OR
        (status = 'superseded' AND failure_code = '' AND content_hash <> '' AND completed_at IS NOT NULL AND superseded_at IS NOT NULL AND superseded_by IS NOT NULL)
    ),
    CONSTRAINT assessment_comparisons_summary_identity CHECK (
        status NOT IN ('complete','needs_review','superseded') OR
        (summary->>'comparison_id' = id AND
         summary->>'baseline_snapshot_id' = baseline_snapshot_id AND
         summary->>'current_snapshot_id' = current_snapshot_id AND
         (summary->>'risk_model_version')::INTEGER = risk_model_version)
    )
);
CREATE INDEX idx_assessment_comparisons_pair ON assessment_comparisons (tenant_id, cycle_id, baseline_snapshot_id, current_snapshot_id, mode, created_at DESC);
CREATE INDEX idx_assessment_comparisons_jobs ON assessment_comparisons (tenant_id, status, updated_at) WHERE status IN ('queued','generating','failed');

CREATE TABLE assessment_comparison_items (
    tenant_id                 TEXT NOT NULL,
    cycle_id                  TEXT NOT NULL,
    comparison_id            TEXT NOT NULL,
    id                       TEXT NOT NULL,
    position                  INTEGER NOT NULL CHECK (position >= 0),
    identity_id               TEXT NOT NULL,
    producer_kind             TEXT NOT NULL DEFAULT '',
    finding_kind              TEXT NOT NULL DEFAULT '',
    target_canonical          TEXT NOT NULL DEFAULT '',
    baseline_observation_id   TEXT,
    current_observation_id    TEXT,
    baseline_observation      JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(baseline_observation) = 'object'),
    current_observation       JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(current_observation) = 'object'),
    presence                  TEXT NOT NULL DEFAULT '' CHECK (presence IN ('','new','still_detected','not_detected_under_comparable_coverage','not_evaluated','reopened','needs_review')),
    neutral_presence          TEXT NOT NULL DEFAULT '' CHECK (neutral_presence IN ('','only_in_a','both','only_in_b','needs_review')),
    change_flags              JSONB NOT NULL CHECK (jsonb_typeof(change_flags) = 'array'),
    coverage_decision         TEXT NOT NULL DEFAULT '' CHECK (coverage_decision IN ('','comparable','partially_comparable','not_comparable')),
    match_methods             JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(match_methods) = 'array'),
    verification_id           TEXT,
    verification_state        TEXT NOT NULL DEFAULT '' CHECK (octet_length(verification_state) <= 64),
    fixed_basis               TEXT NOT NULL DEFAULT '' CHECK (fixed_basis IN ('','comparable_absence','explicit_verification')),
    baseline_actionable       BOOLEAN NOT NULL,
    current_actionable        BOOLEAN NOT NULL,
    comparable_baseline       BOOLEAN NOT NULL,
    baseline_risk_milli       BIGINT NOT NULL CHECK (baseline_risk_milli >= 0),
    current_risk_milli        BIGINT NOT NULL CHECK (current_risk_milli >= 0),
    review_candidate_ids      JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(review_candidate_ids) = 'array'),
    review_candidates         JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(review_candidates) = 'array'),
    PRIMARY KEY (tenant_id, cycle_id, comparison_id, position),
    UNIQUE (tenant_id, comparison_id, id),
    UNIQUE (tenant_id, cycle_id, comparison_id, identity_id),
    FOREIGN KEY (tenant_id, cycle_id, comparison_id) REFERENCES assessment_comparisons(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, identity_id) REFERENCES finding_identities(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, baseline_observation_id) REFERENCES finding_observations(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, current_observation_id) REFERENCES finding_observations(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    CONSTRAINT assessment_comparison_items_mode_presence CHECK ((presence = '') <> (neutral_presence = '')),
    CONSTRAINT assessment_comparison_items_fixed_basis CHECK (
        (fixed_basis = '') OR
        (fixed_basis = 'comparable_absence' AND presence = 'not_detected_under_comparable_coverage') OR
        (fixed_basis = 'explicit_verification' AND presence <> '' AND verification_id IS NOT NULL AND verification_state <> '')
    )
);
CREATE INDEX idx_assessment_comparison_items_explorer ON assessment_comparison_items (tenant_id, comparison_id, producer_kind, finding_kind, position);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION synapse_assessment_comparison_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'assessment comparison is append-only'; END IF;
    IF TG_OP = 'INSERT' THEN RETURN NEW; END IF;
    IF (NEW.tenant_id,NEW.cycle_id,NEW.id,NEW.baseline_snapshot_id,NEW.current_snapshot_id,NEW.mode,NEW.input_hash,NEW.input_payload,
        NEW.algorithm_version,NEW.fingerprint_version,NEW.risk_model_version,NEW.coverage_policy_version,NEW.created_at)
       IS DISTINCT FROM
       (OLD.tenant_id,OLD.cycle_id,OLD.id,OLD.baseline_snapshot_id,OLD.current_snapshot_id,OLD.mode,OLD.input_hash,OLD.input_payload,
        OLD.algorithm_version,OLD.fingerprint_version,OLD.risk_model_version,OLD.coverage_policy_version,OLD.created_at) THEN
        RAISE EXCEPTION 'assessment comparison input is immutable';
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'assessment comparison version must advance by one';
    END IF;
    IF NOT ((OLD.status = 'queued' AND NEW.status = 'generating') OR
            (OLD.status = 'generating' AND NEW.status IN ('queued','complete','needs_review','failed')) OR
            (OLD.status = 'failed' AND NEW.status = 'generating') OR
            (OLD.status IN ('complete','needs_review') AND NEW.status = 'superseded')) THEN
        RAISE EXCEPTION 'assessment comparison transition is invalid';
    END IF;
    IF NEW.attempts <> OLD.attempts + (CASE WHEN NEW.status = 'generating' THEN 1 ELSE 0 END) THEN
        RAISE EXCEPTION 'assessment comparison attempt count is invalid';
    END IF;
    IF OLD.status <> 'generating' AND
       (NEW.content_hash,NEW.summary,NEW.completed_at) IS DISTINCT FROM (OLD.content_hash,OLD.summary,OLD.completed_at) THEN
        RAISE EXCEPTION 'completed assessment comparison output is immutable';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER assessment_comparisons_guard BEFORE UPDATE OR DELETE ON assessment_comparisons FOR EACH ROW EXECUTE FUNCTION synapse_assessment_comparison_guard();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION synapse_assessment_comparison_item_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE parent_status TEXT;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'assessment comparison items are immutable';
    END IF;
    SELECT status INTO parent_status FROM assessment_comparisons
    WHERE tenant_id = NEW.tenant_id AND cycle_id = NEW.cycle_id AND id = NEW.comparison_id
    FOR KEY SHARE;
    IF parent_status = 'generating' THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'assessment comparison items are immutable';
END $$;
-- +goose StatementEnd
CREATE TRIGGER assessment_comparison_items_guard BEFORE INSERT OR UPDATE OR DELETE ON assessment_comparison_items FOR EACH ROW EXECUTE FUNCTION synapse_assessment_comparison_item_guard();

CALL synapse_enable_tenant_rls('assessment_comparisons');
CALL synapse_enable_tenant_rls('assessment_comparison_items');

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM assessment_comparisons LIMIT 1) THEN
        RAISE EXCEPTION 'cannot roll back assessment comparisons while comparison rows exist';
    END IF;
END $$;
-- +goose StatementEnd
DROP TABLE IF EXISTS assessment_comparison_items;
DROP TABLE IF EXISTS assessment_comparisons;
DROP FUNCTION IF EXISTS synapse_assessment_comparison_item_guard();
DROP FUNCTION IF EXISTS synapse_assessment_comparison_guard();
