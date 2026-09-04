-- +goose Up
-- A9a.1 (#703): feature-disabled persistence foundation for immutable Cycle closure manifests.

CREATE INDEX idx_assessment_cycles_cursor
    ON assessment_cycles (tenant_id, updated_at DESC, id DESC);
CREATE INDEX idx_assessment_cycles_filtered_cursor
    ON assessment_cycles (tenant_id, status, boundary_kind, updated_at DESC, id DESC);
CREATE INDEX idx_assessment_cycle_members_active_tree
    ON assessment_cycle_members (tenant_id, cycle_id, predecessor_assessment_id, retest_number DESC, assessment_id DESC)
    WHERE archived_at IS NULL;
CREATE INDEX idx_assessment_comparison_items_page
    ON assessment_comparison_items (tenant_id, cycle_id, comparison_id, presence, neutral_presence, position);

CREATE TABLE assessment_cycle_closure_manifests (
    tenant_id                         TEXT NOT NULL,
    cycle_id                          TEXT NOT NULL,
    id                                TEXT NOT NULL,
    manifest_version                  BIGINT NOT NULL,
    lifecycle                         TEXT NOT NULL,
    cycle_version                     BIGINT NOT NULL,
    root_assessment_id                TEXT NOT NULL,
    final_assessment_id               TEXT NOT NULL,
    initial_snapshot_id               TEXT NOT NULL,
    final_snapshot_id                 TEXT NOT NULL,
    comparison_id                     TEXT NOT NULL,
    initial_snapshot_hash             TEXT NOT NULL,
    final_snapshot_hash               TEXT NOT NULL,
    comparison_hash                   TEXT NOT NULL,
    canonical_input_hash              TEXT NOT NULL,
    content_hash                      TEXT NOT NULL DEFAULT '',
    policy_version                    TEXT NOT NULL,
    algorithm_version                 TEXT NOT NULL,
    fingerprint_version               TEXT NOT NULL,
    risk_version                      TEXT NOT NULL,
    renderer_contract_version         TEXT NOT NULL,
    coverage_decisions                JSONB NOT NULL DEFAULT '{}'::jsonb,
    scope_profile_changes             JSONB NOT NULL DEFAULT '[]'::jsonb,
    override_blocker_ids              JSONB NOT NULL DEFAULT '[]'::jsonb,
    non_final_branches                JSONB NOT NULL DEFAULT '[]'::jsonb,
    reason                            TEXT NOT NULL DEFAULT '',
    override_reason                   TEXT NOT NULL DEFAULT '',
    as_of_at                          TIMESTAMPTZ NOT NULL,
    created_at                        TIMESTAMPTZ NOT NULL,
    created_by                        TEXT NOT NULL,
    sealed_at                         TIMESTAMPTZ NULL,
    sealed_by                         TEXT NOT NULL DEFAULT '',
    superseded_at                     TIMESTAMPTZ NULL,
    superseded_by_manifest_id         TEXT NULL,
    PRIMARY KEY (tenant_id, cycle_id, id),
    UNIQUE (tenant_id, cycle_id, id, cycle_version),
    UNIQUE (tenant_id, cycle_id, manifest_version),
    UNIQUE (tenant_id, cycle_id, content_hash),
    FOREIGN KEY (tenant_id, cycle_id) REFERENCES assessment_cycles(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, root_assessment_id)
        REFERENCES assessment_cycle_members(tenant_id, cycle_id, assessment_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, final_assessment_id)
        REFERENCES assessment_cycle_members(tenant_id, cycle_id, assessment_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, initial_snapshot_id)
        REFERENCES assessment_snapshots(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, final_snapshot_id)
        REFERENCES assessment_snapshots(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, comparison_id)
        REFERENCES assessment_comparisons(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, superseded_by_manifest_id)
        REFERENCES assessment_cycle_closure_manifests(tenant_id, cycle_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT assessment_cycle_closure_manifest_version_check CHECK (manifest_version >= 1 AND cycle_version >= 1),
    CONSTRAINT assessment_cycle_closure_manifest_lifecycle_check CHECK (lifecycle IN ('building','active','superseded')),
    CONSTRAINT assessment_cycle_closure_manifest_hash_check CHECK (
        initial_snapshot_hash ~ '^[0-9a-f]{64}$' AND
        final_snapshot_hash ~ '^[0-9a-f]{64}$' AND
        comparison_hash ~ '^[0-9a-f]{64}$' AND
        canonical_input_hash ~ '^[0-9a-f]{64}$' AND
        (content_hash = '' OR content_hash ~ '^[0-9a-f]{64}$')
    ),
    CONSTRAINT assessment_cycle_closure_manifest_versions_check CHECK (
        policy_version = btrim(policy_version) AND length(policy_version) BETWEEN 1 AND 128 AND
        algorithm_version = btrim(algorithm_version) AND length(algorithm_version) BETWEEN 1 AND 128 AND
        fingerprint_version = btrim(fingerprint_version) AND length(fingerprint_version) BETWEEN 1 AND 128 AND
        risk_version = btrim(risk_version) AND length(risk_version) BETWEEN 1 AND 128 AND
        renderer_contract_version = btrim(renderer_contract_version) AND length(renderer_contract_version) BETWEEN 1 AND 128
    ),
    CONSTRAINT assessment_cycle_closure_manifest_json_check CHECK (
        jsonb_typeof(coverage_decisions) = 'object' AND pg_column_size(coverage_decisions) <= 262144 AND
        jsonb_typeof(scope_profile_changes) = 'array' AND pg_column_size(scope_profile_changes) <= 262144 AND
        jsonb_typeof(override_blocker_ids) = 'array' AND pg_column_size(override_blocker_ids) <= 65536 AND
        jsonb_typeof(non_final_branches) = 'array' AND pg_column_size(non_final_branches) <= 262144
    ),
    CONSTRAINT assessment_cycle_closure_manifest_text_check CHECK (
        created_by = btrim(created_by) AND length(created_by) BETWEEN 1 AND 256 AND
        sealed_by = btrim(sealed_by) AND length(sealed_by) <= 256 AND
        length(reason) <= 4096 AND length(override_reason) <= 4096
    ),
    CONSTRAINT assessment_cycle_closure_manifest_time_check CHECK (as_of_at <= created_at),
    CONSTRAINT assessment_cycle_closure_manifest_state_check CHECK (
        (lifecycle = 'building' AND content_hash = '' AND sealed_at IS NULL AND sealed_by = '' AND superseded_at IS NULL AND superseded_by_manifest_id IS NULL) OR
        (lifecycle = 'active' AND content_hash <> '' AND sealed_at IS NOT NULL AND sealed_by <> '' AND superseded_at IS NULL AND superseded_by_manifest_id IS NULL) OR
        (lifecycle = 'superseded' AND content_hash <> '' AND sealed_at IS NOT NULL AND sealed_by <> '' AND superseded_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX uq_assessment_cycle_closure_active
    ON assessment_cycle_closure_manifests (tenant_id, cycle_id)
    WHERE lifecycle = 'active';
CREATE INDEX idx_assessment_cycle_closure_history
    ON assessment_cycle_closure_manifests (tenant_id, cycle_id, manifest_version DESC);
CREATE INDEX idx_assessment_cycle_closure_hash
    ON assessment_cycle_closure_manifests (tenant_id, content_hash)
    WHERE content_hash <> '';

CREATE TABLE assessment_cycle_closure_path_members (
    tenant_id             TEXT NOT NULL,
    cycle_id              TEXT NOT NULL,
    manifest_id           TEXT NOT NULL,
    path_position         INTEGER NOT NULL,
    assessment_id         TEXT NOT NULL,
    assessment_type       TEXT NOT NULL,
    retest_number         INTEGER NOT NULL,
    relationship_version  BIGINT NOT NULL,
    snapshot_id           TEXT NULL,
    PRIMARY KEY (tenant_id, cycle_id, manifest_id, path_position),
    UNIQUE (tenant_id, cycle_id, manifest_id, assessment_id),
    FOREIGN KEY (tenant_id, cycle_id, manifest_id)
        REFERENCES assessment_cycle_closure_manifests(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, assessment_id)
        REFERENCES assessment_cycle_members(tenant_id, cycle_id, assessment_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, snapshot_id)
        REFERENCES assessment_snapshots(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    CONSTRAINT assessment_cycle_closure_path_position_check CHECK (path_position >= 0),
    CONSTRAINT assessment_cycle_closure_path_version_check CHECK (relationship_version >= 1),
    CONSTRAINT assessment_cycle_closure_path_member_check CHECK (
        (path_position = 0 AND assessment_type = 'initial' AND retest_number = 0) OR
        (path_position > 0 AND assessment_type = 'retest' AND retest_number > 0)
    )
);

CREATE INDEX idx_assessment_cycle_closure_path_assessment
    ON assessment_cycle_closure_path_members (tenant_id, assessment_id, manifest_id);

CREATE TABLE assessment_cycle_closure_references (
    tenant_id          TEXT NOT NULL,
    cycle_id           TEXT NOT NULL,
    manifest_id        TEXT NOT NULL,
    reference_kind     TEXT NOT NULL,
    reference_id       TEXT NOT NULL,
    reference_version  BIGINT NOT NULL,
    content_hash       TEXT NOT NULL DEFAULT '',
    expires_at         TIMESTAMPTZ NULL,
    metadata           JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, cycle_id, manifest_id, reference_kind, reference_id),
    FOREIGN KEY (tenant_id, cycle_id, manifest_id)
        REFERENCES assessment_cycle_closure_manifests(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    CONSTRAINT assessment_cycle_closure_reference_kind_check CHECK (reference_kind ~ '^[a-z][a-z0-9_]{0,63}$'),
    CONSTRAINT assessment_cycle_closure_reference_id_check CHECK (reference_id = btrim(reference_id) AND length(reference_id) BETWEEN 1 AND 512),
    CONSTRAINT assessment_cycle_closure_reference_version_check CHECK (reference_version >= 1),
    CONSTRAINT assessment_cycle_closure_reference_hash_check CHECK (content_hash = '' OR content_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT assessment_cycle_closure_reference_metadata_check CHECK (jsonb_typeof(metadata) = 'object' AND pg_column_size(metadata) <= 65536)
);

CREATE INDEX idx_assessment_cycle_closure_reference_lookup
    ON assessment_cycle_closure_references (tenant_id, reference_kind, reference_id);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION synapse_guard_assessment_cycle_closure_manifest()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'assessment cycle closure manifests are immutable';
    END IF;
    IF OLD.lifecycle = 'building' AND NEW.lifecycle = 'active' THEN
        IF (to_jsonb(OLD) - 'lifecycle' - 'content_hash' - 'sealed_at' - 'sealed_by') IS DISTINCT FROM
           (to_jsonb(NEW) - 'lifecycle' - 'content_hash' - 'sealed_at' - 'sealed_by') THEN
            RAISE EXCEPTION 'only closure sealing fields may change while activating a manifest';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.lifecycle = 'active' AND NEW.lifecycle = 'superseded' THEN
        IF (to_jsonb(OLD) - 'lifecycle' - 'superseded_at' - 'superseded_by_manifest_id') IS DISTINCT FROM
           (to_jsonb(NEW) - 'lifecycle' - 'superseded_at' - 'superseded_by_manifest_id') THEN
            RAISE EXCEPTION 'only closure supersession fields may change';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'assessment cycle closure manifest transition is invalid';
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION synapse_guard_assessment_cycle_closure_child()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    parent_lifecycle TEXT;
BEGIN
    SELECT lifecycle INTO parent_lifecycle
    FROM assessment_cycle_closure_manifests
    WHERE tenant_id = NEW.tenant_id AND cycle_id = NEW.cycle_id AND id = NEW.manifest_id;
    IF parent_lifecycle IS DISTINCT FROM 'building' THEN
        RAISE EXCEPTION 'closure manifest children may only be added while building';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER assessment_cycle_closure_manifests_guard
BEFORE UPDATE OR DELETE ON assessment_cycle_closure_manifests
FOR EACH ROW EXECUTE FUNCTION synapse_guard_assessment_cycle_closure_manifest();
CREATE TRIGGER assessment_cycle_closure_manifests_no_truncate
BEFORE TRUNCATE ON assessment_cycle_closure_manifests
FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

CREATE TRIGGER assessment_cycle_closure_path_insert_guard
BEFORE INSERT ON assessment_cycle_closure_path_members
FOR EACH ROW EXECUTE FUNCTION synapse_guard_assessment_cycle_closure_child();
CREATE TRIGGER assessment_cycle_closure_path_immutable
BEFORE UPDATE OR DELETE ON assessment_cycle_closure_path_members
FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER assessment_cycle_closure_path_no_truncate
BEFORE TRUNCATE ON assessment_cycle_closure_path_members
FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

CREATE TRIGGER assessment_cycle_closure_references_insert_guard
BEFORE INSERT ON assessment_cycle_closure_references
FOR EACH ROW EXECUTE FUNCTION synapse_guard_assessment_cycle_closure_child();
CREATE TRIGGER assessment_cycle_closure_references_immutable
BEFORE UPDATE OR DELETE ON assessment_cycle_closure_references
FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER assessment_cycle_closure_references_no_truncate
BEFORE TRUNCATE ON assessment_cycle_closure_references
FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

ALTER TABLE assessment_cycles
    ADD COLUMN active_closure_manifest_id TEXT NULL,
    ADD COLUMN active_closure_cycle_version BIGINT NULL,
    ADD CONSTRAINT assessment_cycles_active_closure_pair_check CHECK (
        (active_closure_manifest_id IS NULL AND active_closure_cycle_version IS NULL) OR
        (active_closure_manifest_id IS NOT NULL AND active_closure_cycle_version = version)
    ),
    ADD CONSTRAINT assessment_cycles_active_closure_fk FOREIGN KEY
        (tenant_id, id, active_closure_manifest_id, active_closure_cycle_version)
        REFERENCES assessment_cycle_closure_manifests(tenant_id, cycle_id, id, cycle_version)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CALL synapse_enable_tenant_rls('assessment_cycle_closure_manifests');
CALL synapse_enable_tenant_rls('assessment_cycle_closure_path_members');
CALL synapse_enable_tenant_rls('assessment_cycle_closure_references');

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM assessment_cycle_closure_manifests LIMIT 1) OR
       EXISTS (SELECT 1 FROM assessment_cycles WHERE active_closure_manifest_id IS NOT NULL LIMIT 1) THEN
        RAISE EXCEPTION 'cannot roll back assessment closure manifests while closure rows exist';
    END IF;
END;
$$;
-- +goose StatementEnd

ALTER TABLE assessment_cycles
    DROP CONSTRAINT IF EXISTS assessment_cycles_active_closure_fk,
    DROP CONSTRAINT IF EXISTS assessment_cycles_active_closure_pair_check,
    DROP COLUMN IF EXISTS active_closure_cycle_version,
    DROP COLUMN IF EXISTS active_closure_manifest_id;

DROP INDEX IF EXISTS idx_assessment_comparison_items_page;
DROP INDEX IF EXISTS idx_assessment_cycle_members_active_tree;
DROP INDEX IF EXISTS idx_assessment_cycles_filtered_cursor;
DROP INDEX IF EXISTS idx_assessment_cycles_cursor;

DROP TABLE IF EXISTS assessment_cycle_closure_references;
DROP TABLE IF EXISTS assessment_cycle_closure_path_members;
DROP TABLE IF EXISTS assessment_cycle_closure_manifests;
DROP FUNCTION IF EXISTS synapse_guard_assessment_cycle_closure_child();
DROP FUNCTION IF EXISTS synapse_guard_assessment_cycle_closure_manifest();
