-- +goose Up
-- A2 (#696): immutable Assessment Snapshots and deterministic coverage comparability.

CREATE TABLE assessment_snapshots (
    tenant_id        TEXT NOT NULL,
    id               TEXT NOT NULL,
    cycle_id         TEXT NOT NULL,
    assessment_id    TEXT NOT NULL,
    snapshot_number  INTEGER NOT NULL CHECK (snapshot_number > 0),
    lifecycle        TEXT NOT NULL CHECK (lifecycle IN ('building','finalized','superseded')),
    provenance       TEXT NOT NULL CHECK (provenance IN ('native','legacy')),
    boundary_kind    TEXT NOT NULL CHECK (boundary_kind IN ('standalone','asset','project','asset_project')),
    business_asset_id TEXT,
    project_id       TEXT,
    schema_version   INTEGER NOT NULL CHECK (schema_version = 1),
    content_hash     TEXT NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    request_key      TEXT NOT NULL CHECK (btrim(request_key) <> ''),
    request_hash     TEXT NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    created_at       TIMESTAMPTZ NOT NULL,
    created_by       TEXT NOT NULL,
    finalized_at     TIMESTAMPTZ,
    finalized_by     TEXT NOT NULL DEFAULT '',
    superseded_at    TIMESTAMPTZ,
    superseded_by    TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, assessment_id, snapshot_number),
    UNIQUE (tenant_id, assessment_id, request_key),
    FOREIGN KEY (tenant_id, cycle_id, assessment_id)
        REFERENCES assessment_cycle_members(tenant_id, cycle_id, assessment_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, assessment_id)
        REFERENCES engagements(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT assessment_snapshots_boundary_check CHECK (
        (boundary_kind = 'standalone' AND business_asset_id IS NULL AND project_id IS NULL) OR
        (boundary_kind = 'asset' AND business_asset_id IS NOT NULL AND project_id IS NULL) OR
        (boundary_kind = 'project' AND business_asset_id IS NULL AND project_id IS NOT NULL) OR
        (boundary_kind = 'asset_project' AND business_asset_id IS NOT NULL AND project_id IS NOT NULL)
    ),
    CONSTRAINT assessment_snapshots_lifecycle_metadata_check CHECK (
        (lifecycle = 'building' AND finalized_at IS NULL AND finalized_by = '' AND superseded_at IS NULL AND superseded_by = '') OR
        (lifecycle = 'finalized' AND finalized_at IS NOT NULL AND finalized_by <> '' AND superseded_at IS NULL AND superseded_by = '') OR
        (lifecycle = 'superseded' AND finalized_at IS NOT NULL AND finalized_by <> '' AND superseded_at IS NOT NULL AND superseded_by <> '')
    )
);

CREATE TABLE assessment_snapshot_run_refs (
    tenant_id       TEXT NOT NULL,
    snapshot_id     TEXT NOT NULL,
    position        INTEGER NOT NULL CHECK (position >= 0),
    scan_run_id     TEXT NOT NULL,
    manifest_hash   TEXT NOT NULL CHECK (manifest_hash ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (tenant_id, snapshot_id, position),
    UNIQUE (tenant_id, snapshot_id, scan_run_id),
    UNIQUE (tenant_id, snapshot_id, position, scan_run_id),
    FOREIGN KEY (tenant_id, snapshot_id) REFERENCES assessment_snapshots(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, scan_run_id) REFERENCES scan_runs(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE assessment_snapshot_lane_refs (
    tenant_id       TEXT NOT NULL,
    snapshot_id     TEXT NOT NULL,
    run_position    INTEGER NOT NULL,
    scan_run_id     TEXT NOT NULL,
    lane_key        TEXT NOT NULL,
    manifest_hash   TEXT NOT NULL CHECK (manifest_hash ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (tenant_id, snapshot_id, run_position, lane_key),
    FOREIGN KEY (tenant_id, snapshot_id, run_position, scan_run_id)
        REFERENCES assessment_snapshot_run_refs(tenant_id, snapshot_id, position, scan_run_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, scan_run_id, lane_key)
        REFERENCES scan_run_lanes(tenant_id, scan_run_id, lane_key) ON DELETE RESTRICT
);

CREATE TABLE assessment_snapshot_dimensions (
    tenant_id          TEXT NOT NULL,
    snapshot_id        TEXT NOT NULL,
    position           INTEGER NOT NULL CHECK (position >= 0),
    run_id             TEXT NOT NULL,
    lane_key           TEXT NOT NULL,
    lane_manifest_hash TEXT NOT NULL CHECK (lane_manifest_hash ~ '^[0-9a-f]{64}$'),
    producer           TEXT NOT NULL CHECK (btrim(producer) <> ''),
    finding_kind       TEXT NOT NULL CHECK (btrim(finding_kind) <> ''),
    target_kind        TEXT NOT NULL,
    target_schema_version INTEGER NOT NULL CHECK (target_schema_version > 0),
    target_canonical   TEXT NOT NULL CHECK (btrim(target_canonical) <> ''),
    evaluated_revision TEXT NOT NULL DEFAULT '',
    coverage_state     TEXT NOT NULL CHECK (coverage_state IN ('complete','partial','unknown')),
    reason_code        TEXT NOT NULL CHECK (btrim(reason_code) <> ''),
    included_scope     JSONB NOT NULL CHECK (jsonb_typeof(included_scope) = 'array'),
    excluded_scope     JSONB NOT NULL CHECK (jsonb_typeof(excluded_scope) = 'array'),
    versions           JSONB NOT NULL CHECK (jsonb_typeof(versions) = 'array'),
    PRIMARY KEY (tenant_id, snapshot_id, position),
    UNIQUE (tenant_id, snapshot_id, target_kind, target_schema_version, target_canonical, producer, finding_kind),
    FOREIGN KEY (tenant_id, snapshot_id) REFERENCES assessment_snapshots(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, snapshot_id, run_id) REFERENCES assessment_snapshot_run_refs(tenant_id, snapshot_id, scan_run_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, run_id, lane_key) REFERENCES scan_run_lanes(tenant_id, scan_run_id, lane_key) ON DELETE RESTRICT
);

CREATE TABLE assessment_snapshot_counters (
    tenant_id            TEXT NOT NULL,
    assessment_id        TEXT NOT NULL,
    next_snapshot_number INTEGER NOT NULL CHECK (next_snapshot_number >= 1),
    PRIMARY KEY (tenant_id, assessment_id),
    FOREIGN KEY (tenant_id, assessment_id) REFERENCES engagements(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE assessment_snapshot_defaults (
    tenant_id      TEXT NOT NULL,
    assessment_id  TEXT NOT NULL,
    snapshot_id    TEXT NOT NULL,
    version        BIGINT NOT NULL CHECK (version >= 1),
    updated_at     TIMESTAMPTZ NOT NULL,
    updated_by     TEXT NOT NULL,
    PRIMARY KEY (tenant_id, assessment_id),
    FOREIGN KEY (tenant_id, assessment_id) REFERENCES engagements(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, snapshot_id) REFERENCES assessment_snapshots(tenant_id, id) ON DELETE RESTRICT
);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION synapse_assessment_snapshot_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE engagement_status TEXT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT status INTO engagement_status FROM engagements WHERE tenant_id = NEW.tenant_id AND id = NEW.assessment_id;
        IF engagement_status NOT IN ('draft','active') THEN
            RAISE EXCEPTION 'assessment snapshot requires draft/active engagement';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.lifecycle = 'building' AND NEW.lifecycle = 'finalized' AND
       (NEW.tenant_id,NEW.id,NEW.cycle_id,NEW.assessment_id,NEW.snapshot_number,NEW.provenance,NEW.boundary_kind,
        NEW.business_asset_id,NEW.project_id,NEW.schema_version,NEW.content_hash,NEW.request_key,NEW.request_hash,
        NEW.created_at,NEW.created_by,NEW.superseded_at,NEW.superseded_by)
       IS NOT DISTINCT FROM
       (OLD.tenant_id,OLD.id,OLD.cycle_id,OLD.assessment_id,OLD.snapshot_number,OLD.provenance,OLD.boundary_kind,
        OLD.business_asset_id,OLD.project_id,OLD.schema_version,OLD.content_hash,OLD.request_key,OLD.request_hash,
        OLD.created_at,OLD.created_by,OLD.superseded_at,OLD.superseded_by) THEN
        RETURN NEW;
    END IF;
    IF OLD.lifecycle = 'finalized' AND NEW.lifecycle = 'superseded' AND
       (NEW.tenant_id,NEW.id,NEW.cycle_id,NEW.assessment_id,NEW.snapshot_number,NEW.provenance,NEW.boundary_kind,
        NEW.business_asset_id,NEW.project_id,NEW.schema_version,NEW.content_hash,NEW.request_key,NEW.request_hash,
        NEW.created_at,NEW.created_by,NEW.finalized_at,NEW.finalized_by)
       IS NOT DISTINCT FROM
       (OLD.tenant_id,OLD.id,OLD.cycle_id,OLD.assessment_id,OLD.snapshot_number,OLD.provenance,OLD.boundary_kind,
        OLD.business_asset_id,OLD.project_id,OLD.schema_version,OLD.content_hash,OLD.request_key,OLD.request_hash,
        OLD.created_at,OLD.created_by,OLD.finalized_at,OLD.finalized_by) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'assessment snapshot is immutable';
END $$;
-- +goose StatementEnd

CREATE TRIGGER assessment_snapshots_guard
BEFORE INSERT OR UPDATE OR DELETE ON assessment_snapshots
FOR EACH ROW EXECUTE FUNCTION synapse_assessment_snapshot_guard();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION synapse_assessment_snapshot_child_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE state TEXT;
DECLARE sid TEXT;
DECLARE tenant TEXT;
BEGIN
    sid := CASE WHEN TG_OP = 'DELETE' THEN OLD.snapshot_id ELSE NEW.snapshot_id END;
    tenant := CASE WHEN TG_OP = 'DELETE' THEN OLD.tenant_id ELSE NEW.tenant_id END;
    SELECT lifecycle INTO state FROM assessment_snapshots WHERE tenant_id = tenant AND id = sid;
    IF state <> 'building' THEN
        RAISE EXCEPTION 'finalized assessment snapshot child is immutable';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END $$;
-- +goose StatementEnd

CREATE TRIGGER assessment_snapshot_run_refs_guard BEFORE INSERT OR UPDATE OR DELETE ON assessment_snapshot_run_refs FOR EACH ROW EXECUTE FUNCTION synapse_assessment_snapshot_child_guard();
CREATE TRIGGER assessment_snapshot_lane_refs_guard BEFORE INSERT OR UPDATE OR DELETE ON assessment_snapshot_lane_refs FOR EACH ROW EXECUTE FUNCTION synapse_assessment_snapshot_child_guard();
CREATE TRIGGER assessment_snapshot_dimensions_guard BEFORE INSERT OR UPDATE OR DELETE ON assessment_snapshot_dimensions FOR EACH ROW EXECUTE FUNCTION synapse_assessment_snapshot_child_guard();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION synapse_assessment_snapshot_default_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE engagement_status TEXT;
DECLARE snapshot_state TEXT;
BEGIN
    SELECT status INTO engagement_status FROM engagements WHERE tenant_id = NEW.tenant_id AND id = NEW.assessment_id;
    IF engagement_status NOT IN ('draft','active') THEN
        RAISE EXCEPTION 'default assessment snapshot cannot change after engagement completion';
    END IF;
    SELECT lifecycle INTO snapshot_state FROM assessment_snapshots WHERE tenant_id = NEW.tenant_id AND id = NEW.snapshot_id;
    IF snapshot_state <> 'finalized' THEN
        RAISE EXCEPTION 'default assessment snapshot must be finalized';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd

CREATE TRIGGER assessment_snapshot_defaults_guard BEFORE INSERT OR UPDATE ON assessment_snapshot_defaults FOR EACH ROW EXECUTE FUNCTION synapse_assessment_snapshot_default_guard();

CALL synapse_enable_tenant_rls('assessment_snapshots');
CALL synapse_enable_tenant_rls('assessment_snapshot_run_refs');
CALL synapse_enable_tenant_rls('assessment_snapshot_lane_refs');
CALL synapse_enable_tenant_rls('assessment_snapshot_dimensions');
CALL synapse_enable_tenant_rls('assessment_snapshot_counters');
CALL synapse_enable_tenant_rls('assessment_snapshot_defaults');

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM assessment_snapshots LIMIT 1) THEN
        RAISE EXCEPTION 'cannot roll back assessment snapshots while snapshot rows exist';
    END IF;
END $$;
-- +goose StatementEnd
DROP TABLE IF EXISTS assessment_snapshot_defaults;
DROP TABLE IF EXISTS assessment_snapshot_counters;
DROP TABLE IF EXISTS assessment_snapshot_dimensions;
DROP TABLE IF EXISTS assessment_snapshot_lane_refs;
DROP TABLE IF EXISTS assessment_snapshot_run_refs;
DROP TABLE IF EXISTS assessment_snapshots;
DROP FUNCTION IF EXISTS synapse_assessment_snapshot_default_guard();
DROP FUNCTION IF EXISTS synapse_assessment_snapshot_child_guard();
DROP FUNCTION IF EXISTS synapse_assessment_snapshot_guard();
