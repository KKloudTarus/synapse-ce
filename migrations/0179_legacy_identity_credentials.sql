-- +goose Up
-- D5 legacy credential projection (#962).
--
-- users.api_key_hash remains the writer of record before read cutover. This table is derived and
-- tenant-owned. Placeholder/ambiguous rows deliberately carry NO digest, so a random hash that was
-- never issued as a bearer secret cannot accidentally become an authentication credential.
CREATE TABLE legacy_human_credentials (
    tenant_id          TEXT NOT NULL CHECK (btrim(tenant_id) <> '') REFERENCES tenants(id) ON DELETE RESTRICT,
    id                 TEXT NOT NULL CHECK (btrim(id) <> ''),
    user_id            TEXT NOT NULL,
    membership_id      TEXT NOT NULL,
    person_id          TEXT NOT NULL,
    classification     TEXT NOT NULL CHECK (classification IN ('issued','placeholder','ambiguous')),
    digest             TEXT,
    status             TEXT NOT NULL CHECK (status IN ('active','disabled','unavailable')),
    classification_reason TEXT NOT NULL CHECK (classification_reason ~ '^[a-z0-9_]{1,96}$'),
    version            BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    source_updated_at  TIMESTAMPTZ NOT NULL,
    classified_at      TIMESTAMPTZ NOT NULL,
    updated_at         TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,id),
    UNIQUE (tenant_id,user_id),
    UNIQUE (tenant_id,id,user_id),
    UNIQUE (digest),
    FOREIGN KEY (tenant_id,user_id) REFERENCES users(ownership_tenant_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,membership_id,person_id) REFERENCES memberships(tenant_id,id,person_id) ON DELETE RESTRICT,
    CHECK (
        (classification='issued' AND digest ~ '^[a-f0-9]{64}$' AND status IN ('active','disabled')) OR
        (classification IN ('placeholder','ambiguous') AND digest IS NULL AND status='unavailable')
    ),
    CHECK (updated_at >= classified_at)
);
CREATE INDEX legacy_human_credentials_classification
    ON legacy_human_credentials(tenant_id,classification,user_id);
CREATE INDEX legacy_human_credentials_status
    ON legacy_human_credentials(tenant_id,status,user_id);
CALL synapse_enable_tenant_rls('legacy_human_credentials');

-- D5 evidence is part of the same immutable rollout phase record introduced by D4. Zero/default
-- columns keep pre-D5 records readable; credential_projection_complete distinguishes a real D5
-- observation from a legacy all-zero record.
ALTER TABLE identity_rollout_phase_records
    ADD COLUMN credential_projection_complete BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN credential_projected_count INTEGER NOT NULL DEFAULT 0 CHECK (credential_projected_count >= 0),
    ADD COLUMN issued_credential_count INTEGER NOT NULL DEFAULT 0 CHECK (issued_credential_count >= 0),
    ADD COLUMN placeholder_credential_count INTEGER NOT NULL DEFAULT 0 CHECK (placeholder_credential_count >= 0),
    ADD COLUMN ambiguous_credential_count INTEGER NOT NULL DEFAULT 0 CHECK (ambiguous_credential_count >= 0),
    ADD COLUMN missing_credential_count INTEGER NOT NULL DEFAULT 0 CHECK (missing_credential_count >= 0),
    ADD COLUMN credential_drift_count INTEGER NOT NULL DEFAULT 0 CHECK (credential_drift_count >= 0),
    ADD COLUMN credential_index_drift_count INTEGER NOT NULL DEFAULT 0 CHECK (credential_index_drift_count >= 0),
    ADD CONSTRAINT identity_rollout_credential_classification_counts CHECK (
        issued_credential_count + placeholder_credential_count + ambiguous_credential_count = credential_projected_count
    );

-- Explicit administrative classification is retained as immutable evidence; it never carries a
-- credential digest. Resolution to "issued" means the CURRENT users.api_key_hash may be projected;
-- resolution to "placeholder" confirms there was no bearer issuance.
CREATE TABLE legacy_credential_resolutions (
    tenant_id       TEXT NOT NULL CHECK (btrim(tenant_id) <> '') REFERENCES tenants(id) ON DELETE RESTRICT,
    id              TEXT NOT NULL CHECK (btrim(id) <> ''),
    user_id         TEXT NOT NULL,
    resolution      TEXT NOT NULL CHECK (resolution IN ('issued','placeholder')),
    expected_version BIGINT NOT NULL CHECK (expected_version > 0),
    reason          TEXT NOT NULL CHECK (length(btrim(reason)) BETWEEN 1 AND 1024),
    actor           TEXT NOT NULL CHECK (length(btrim(actor)) BETWEEN 1 AND 256),
    created_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,id),
    FOREIGN KEY (tenant_id,user_id) REFERENCES users(ownership_tenant_id,id) ON DELETE RESTRICT
);
CREATE INDEX legacy_credential_resolutions_user
    ON legacy_credential_resolutions(tenant_id,user_id,created_at DESC,id DESC);
CALL synapse_enable_tenant_rls('legacy_credential_resolutions');

-- Classification resolutions are append-only evidence.
-- +goose StatementBegin
CREATE FUNCTION identity_reject_credential_resolution_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'legacy credential classification resolution is append-only' USING ERRCODE='55000';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER legacy_credential_resolutions_append_only
    BEFORE UPDATE OR DELETE ON legacy_credential_resolutions
    FOR EACH ROW EXECUTE FUNCTION identity_reject_credential_resolution_mutation();

-- +goose Down
-- Credential history and rollout observations are security state. Empty development databases may
-- go down; populated ones require paired-backup/forward-fix semantics instead of erasing evidence.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM legacy_credential_resolutions LIMIT 1) OR
       EXISTS (SELECT 1 FROM legacy_human_credentials LIMIT 1) OR
       EXISTS (
           SELECT 1 FROM identity_rollout_phase_records
           WHERE credential_projection_complete OR credential_projected_count<>0 OR issued_credential_count<>0 OR
                 placeholder_credential_count<>0 OR ambiguous_credential_count<>0 OR missing_credential_count<>0 OR
                 credential_drift_count<>0 OR credential_index_drift_count<>0
           LIMIT 1
       ) THEN
        RAISE EXCEPTION 'cannot roll back populated legacy identity credentials';
    END IF;
END;
$$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS legacy_credential_resolutions_append_only ON legacy_credential_resolutions;
DROP FUNCTION IF EXISTS identity_reject_credential_resolution_mutation();
DROP TABLE IF EXISTS legacy_credential_resolutions;
ALTER TABLE identity_rollout_phase_records
    DROP CONSTRAINT IF EXISTS identity_rollout_credential_classification_counts,
    DROP COLUMN IF EXISTS credential_index_drift_count,
    DROP COLUMN IF EXISTS credential_drift_count,
    DROP COLUMN IF EXISTS missing_credential_count,
    DROP COLUMN IF EXISTS ambiguous_credential_count,
    DROP COLUMN IF EXISTS placeholder_credential_count,
    DROP COLUMN IF EXISTS issued_credential_count,
    DROP COLUMN IF EXISTS credential_projected_count,
    DROP COLUMN IF EXISTS credential_projection_complete;
DROP TABLE IF EXISTS legacy_human_credentials;
