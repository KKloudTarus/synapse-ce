-- +goose Up
-- Enterprise identity rollout state (#962, D4).
--
-- The legacy users table remains authoritative in this phase. These tables record bounded,
-- resumable projection work and immutable rollout evidence; they do not make the new identity
-- model authoritative and they do not mutate legacy users or historical audit rows.

CREATE TABLE identity_backfill_runs (
    tenant_id             TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    id                    TEXT NOT NULL,
    schema_version        INTEGER NOT NULL CHECK (schema_version > 0),
    batch_size            INTEGER NOT NULL CHECK (batch_size BETWEEN 1 AND 2000),
    snapshot_at           TIMESTAMPTZ NOT NULL,
    checkpoint_user_id    TEXT NOT NULL DEFAULT '' CHECK (octet_length(checkpoint_user_id) <= 512),
    state                 TEXT NOT NULL CHECK (state IN ('running','completed','cancelled','failed')),
    lease_owner           TEXT NOT NULL DEFAULT '',
    lease_token           TEXT NOT NULL DEFAULT '',
    lease_expires_at      TIMESTAMPTZ,
    processed_count       INTEGER NOT NULL DEFAULT 0 CHECK (processed_count >= 0),
    projected_count       INTEGER NOT NULL DEFAULT 0 CHECK (projected_count >= 0),
    unchanged_count       INTEGER NOT NULL DEFAULT 0 CHECK (unchanged_count >= 0),
    drift_count           INTEGER NOT NULL DEFAULT 0 CHECK (drift_count >= 0),
    source_count          INTEGER NOT NULL DEFAULT 0 CHECK (source_count >= 0),
    person_count          INTEGER NOT NULL DEFAULT 0 CHECK (person_count >= 0),
    membership_count      INTEGER NOT NULL DEFAULT 0 CHECK (membership_count >= 0),
    created_by            TEXT NOT NULL CHECK (created_by = btrim(created_by) AND length(created_by) BETWEEN 1 AND 256),
    created_at            TIMESTAMPTZ NOT NULL,
    updated_at            TIMESTAMPTZ NOT NULL,
    completed_at          TIMESTAMPTZ,
    PRIMARY KEY (tenant_id,id),
    CHECK (processed_count = projected_count + unchanged_count + drift_count),
    CHECK (updated_at >= created_at AND snapshot_at <= created_at AND (completed_at IS NULL OR completed_at >= created_at)),
    CHECK (
        (state='running' AND lease_owner=btrim(lease_owner) AND length(lease_owner) BETWEEN 1 AND 256 AND
         length(lease_token) BETWEEN 1 AND 512 AND lease_expires_at IS NOT NULL AND completed_at IS NULL) OR
        (state<>'running' AND lease_owner='' AND lease_token='' AND lease_expires_at IS NULL AND completed_at IS NOT NULL)
    )
);
CREATE UNIQUE INDEX identity_backfill_one_running_per_tenant
    ON identity_backfill_runs(tenant_id) WHERE state='running';
CREATE INDEX identity_backfill_history
    ON identity_backfill_runs(tenant_id,created_at DESC,id DESC);
CALL synapse_enable_tenant_rls('identity_backfill_runs');

CREATE TABLE identity_backfill_items (
    tenant_id      TEXT NOT NULL,
    run_id         TEXT NOT NULL,
    user_id        TEXT NOT NULL,
    person_id      TEXT NOT NULL,
    membership_id  TEXT NOT NULL,
    source_hash    TEXT NOT NULL CHECK (source_hash ~ '^[a-f0-9]{64}$'),
    outcome        TEXT NOT NULL CHECK (outcome IN ('projected','unchanged','drift')),
    reason_code    TEXT NOT NULL CHECK (reason_code ~ '^[a-z0-9_]{1,64}$'),
    processed_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,run_id,user_id),
    FOREIGN KEY (tenant_id,run_id) REFERENCES identity_backfill_runs(tenant_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,user_id) REFERENCES users(ownership_tenant_id,id) ON DELETE RESTRICT,
    -- Do not FK evidence to persons/memberships: a drift item must be able to prove that a
    -- projection is missing or ownership-corrupt without first repairing the derived side.
    UNIQUE (tenant_id,run_id,source_hash,user_id)
);
CREATE INDEX identity_backfill_items_outcome
    ON identity_backfill_items(tenant_id,run_id,outcome,user_id);
CALL synapse_enable_tenant_rls('identity_backfill_items');

-- Offline/canary rollout evidence. Multiple records per phase are allowed so a failed observation
-- window is retained rather than overwritten. The application gate consumes one immutable record.
CREATE TABLE identity_rollout_phase_records (
    tenant_id             TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    id                    TEXT NOT NULL,
    phase                 TEXT NOT NULL CHECK (phase IN (
        'expand','legacy_authoritative_backfill','shadow_comparison','canary_authoritative_read',
        'canary_identity_mutations','point_of_no_return','contract'
    )),
    owner                 TEXT NOT NULL CHECK (owner=btrim(owner) AND length(owner) BETWEEN 1 AND 256),
    source_of_truth       TEXT NOT NULL CHECK (source_of_truth IN ('legacy_users','shadow_compare','enterprise_identity')),
    allowed_writers       TEXT[] NOT NULL DEFAULT '{}',
    source_count          INTEGER NOT NULL DEFAULT 0 CHECK (source_count >= 0),
    projected_count       INTEGER NOT NULL DEFAULT 0 CHECK (projected_count >= 0),
    drift_count           INTEGER NOT NULL DEFAULT 0 CHECK (drift_count >= 0),
    corrupt_credential_count INTEGER NOT NULL DEFAULT 0 CHECK (corrupt_credential_count >= 0),
    duplicate_credential_count INTEGER NOT NULL DEFAULT 0 CHECK (duplicate_credential_count >= 0),
    denial_count          INTEGER NOT NULL DEFAULT 0 CHECK (denial_count >= 0),
    error_count           INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0),
    session_count         INTEGER NOT NULL DEFAULT 0 CHECK (session_count >= 0),
    observation_minutes   INTEGER NOT NULL DEFAULT 0 CHECK (observation_minutes >= 0),
    abort_threshold_bps   INTEGER NOT NULL DEFAULT 0 CHECK (abort_threshold_bps BETWEEN 0 AND 10000),
    last_known_good_phase TEXT NOT NULL DEFAULT '',
    rollback_action       TEXT NOT NULL CHECK (length(btrim(rollback_action)) BETWEEN 1 AND 2048),
    metrics_recorded      BOOLEAN NOT NULL DEFAULT false,
    approval_recorded     BOOLEAN NOT NULL DEFAULT false,
    created_by            TEXT NOT NULL CHECK (created_by=btrim(created_by) AND length(created_by) BETWEEN 1 AND 256),
    created_at            TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,id)
);
CREATE INDEX identity_rollout_phase_history
    ON identity_rollout_phase_records(tenant_id,phase,created_at DESC,id DESC);
CALL synapse_enable_tenant_rls('identity_rollout_phase_records');

-- Rollout evidence is append-only. A new observation creates another record.
-- +goose StatementBegin
CREATE FUNCTION identity_reject_rollout_record_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'identity rollout phase evidence is append-only' USING ERRCODE='55000';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER identity_rollout_phase_records_append_only
    BEFORE UPDATE OR DELETE ON identity_rollout_phase_records
    FOR EACH ROW EXECUTE FUNCTION identity_reject_rollout_record_mutation();

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM identity_rollout_phase_records LIMIT 1) OR
       EXISTS (SELECT 1 FROM identity_backfill_items LIMIT 1) OR
       EXISTS (SELECT 1 FROM identity_backfill_runs LIMIT 1) THEN
        RAISE EXCEPTION 'cannot roll back identity rollout state while rollout history exists';
    END IF;
END;
$$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS identity_rollout_phase_records_append_only ON identity_rollout_phase_records;
DROP FUNCTION IF EXISTS identity_reject_rollout_record_mutation();
DROP TABLE IF EXISTS identity_rollout_phase_records;
DROP TABLE IF EXISTS identity_backfill_items;
DROP TABLE IF EXISTS identity_backfill_runs;
