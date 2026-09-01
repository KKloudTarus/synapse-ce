-- +goose Up
-- A2a (#708): tenant-owned scan execution headers and sealed native producer provenance.

-- +goose StatementBegin
DO $$
DECLARE
    dependents TEXT;
BEGIN
    SELECT string_agg(conrelid::regclass::text || '.' || conname, ', ' ORDER BY conrelid::regclass::text, conname)
      INTO dependents
      FROM pg_constraint
     WHERE contype = 'f'
       AND confrelid = 'scan_runs'::regclass;
    IF dependents IS NOT NULL THEN
        RAISE EXCEPTION 'unlisted id-only scan_runs foreign keys must be migrated first: %', dependents;
    END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE scan_runs
    ADD COLUMN tenant_id TEXT,
    ADD COLUMN provenance TEXT NOT NULL DEFAULT 'legacy'
        CONSTRAINT scan_runs_provenance_check CHECK (provenance IN ('native', 'legacy')),
    ADD COLUMN terminal_status TEXT NOT NULL DEFAULT 'unknown'
        CONSTRAINT scan_runs_terminal_status_check CHECK (terminal_status IN ('building', 'succeeded', 'partial', 'failed', 'cancelled', 'unknown')),
    ADD COLUMN manifest_schema_version INTEGER NOT NULL DEFAULT 0
        CONSTRAINT scan_runs_manifest_schema_version_check CHECK (manifest_schema_version >= 0),
    ADD COLUMN manifest_hash TEXT
        CONSTRAINT scan_runs_manifest_hash_check CHECK (manifest_hash IS NULL OR manifest_hash ~ '^[0-9a-f]{64}$'),
    ADD COLUMN sealed_at TIMESTAMPTZ,
    ADD CONSTRAINT scan_runs_native_state_check CHECK (
        (provenance = 'legacy' AND terminal_status = 'unknown' AND manifest_schema_version = 0 AND manifest_hash IS NULL AND sealed_at IS NULL) OR
        (provenance = 'native' AND (
            (terminal_status = 'building' AND manifest_schema_version = 0 AND manifest_hash IS NULL AND sealed_at IS NULL) OR
            (terminal_status IN ('succeeded', 'partial', 'failed', 'cancelled') AND manifest_schema_version > 0 AND manifest_hash IS NOT NULL AND sealed_at IS NOT NULL)
        ))
    );

-- +goose StatementBegin
DO $$
DECLARE
    orphan_count BIGINT;
    orphan_sample TEXT;
BEGIN
    SELECT count(*) INTO orphan_count
      FROM scan_runs r
      LEFT JOIN engagements e ON e.id = r.engagement_id
     WHERE e.id IS NULL;
    SELECT string_agg(id, ', ' ORDER BY id) INTO orphan_sample
      FROM (SELECT r.id FROM scan_runs r LEFT JOIN engagements e ON e.id = r.engagement_id WHERE e.id IS NULL ORDER BY r.id LIMIT 20) missing;
    IF orphan_count > 0 THEN
        RAISE EXCEPTION 'scan_runs tenant backfill found % orphan rows (sample: %)', orphan_count, orphan_sample;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
DECLARE
    affected INTEGER;
BEGIN
    LOOP
        WITH batch AS (
            SELECT r.ctid, e.tenant_id
              FROM scan_runs r
              JOIN engagements e ON e.id = r.engagement_id
             WHERE r.tenant_id IS NULL
             LIMIT 1000
        )
        UPDATE scan_runs r
           SET tenant_id = batch.tenant_id
          FROM batch
         WHERE r.ctid = batch.ctid;
        GET DIAGNOSTICS affected = ROW_COUNT;
        EXIT WHEN affected = 0;
    END LOOP;
END $$;
-- +goose StatementEnd

ALTER TABLE scan_runs ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_tenant_id_unique UNIQUE (tenant_id, id);
ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_tenant_engagement_id_unique UNIQUE (tenant_id, engagement_id, id);
ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_engagement_fk_tenant
    FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagements(tenant_id, id) ON DELETE CASCADE NOT VALID;
ALTER TABLE scan_runs VALIDATE CONSTRAINT scan_runs_engagement_fk_tenant;

CREATE TABLE scan_run_lanes (
    tenant_id                        TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    engagement_id                    TEXT NOT NULL,
    scan_run_id                      TEXT NOT NULL,
    lane_key                         TEXT NOT NULL CHECK (btrim(lane_key) <> ''),
    producer                         TEXT NOT NULL CHECK (btrim(producer) <> ''),
    terminal_status                  TEXT NOT NULL CHECK (terminal_status IN ('building', 'succeeded', 'partial', 'failed', 'cancelled')),
    target_kind                      TEXT NOT NULL CHECK (target_kind IN ('repository', 'image', 'host', 'url', 'cloud')),
    target_identity_schema_version   INTEGER NOT NULL CHECK (target_identity_schema_version > 0),
    target_identity_canonical        TEXT NOT NULL CHECK (btrim(target_identity_canonical) <> ''),
    evaluated_revision               TEXT NOT NULL DEFAULT '',
    authoritative_finding_kinds      TEXT[] NOT NULL,
    included_scope                   JSONB NOT NULL CHECK (jsonb_typeof(included_scope) = 'array'),
    excluded_scope                   JSONB NOT NULL CHECK (jsonb_typeof(excluded_scope) = 'array'),
    started_at                       TIMESTAMPTZ NOT NULL,
    finished_at                      TIMESTAMPTZ,
    result_ref                       TEXT NOT NULL DEFAULT '',
    evidence_ref                     TEXT NOT NULL DEFAULT '',
    result_sha256                    TEXT CHECK (result_sha256 IS NULL OR result_sha256 ~ '^[0-9a-f]{64}$'),
    manifest_schema_version          INTEGER NOT NULL CHECK (manifest_schema_version > 0),
    manifest_hash                    TEXT NOT NULL CHECK (manifest_hash ~ '^[0-9a-f]{64}$'),
    sealed_at                        TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, scan_run_id, lane_key),
    FOREIGN KEY (tenant_id, engagement_id, scan_run_id)
        REFERENCES scan_runs(tenant_id, engagement_id, id) ON DELETE CASCADE,
    CONSTRAINT scan_run_lanes_terminal_check CHECK (
        (terminal_status = 'building' AND finished_at IS NULL AND sealed_at IS NULL) OR
        (terminal_status IN ('succeeded', 'partial', 'failed', 'cancelled') AND finished_at IS NOT NULL AND sealed_at IS NOT NULL)
    ),
    CONSTRAINT scan_run_lanes_success_check CHECK (
        terminal_status <> 'succeeded' OR (
            cardinality(authoritative_finding_kinds) > 0 AND
            btrim(result_ref) <> '' AND btrim(evidence_ref) <> '' AND
            result_sha256 IS NOT NULL AND
            ((target_kind IN ('repository', 'image') AND btrim(evaluated_revision) <> '') OR target_kind NOT IN ('repository', 'image'))
        )
    )
);

CREATE TABLE scan_run_lane_versions (
    tenant_id    TEXT NOT NULL,
    scan_run_id  TEXT NOT NULL,
    lane_key     TEXT NOT NULL,
    version_kind TEXT NOT NULL CHECK (version_kind IN ('tool', 'scanner', 'profile', 'rule_pack', 'advisory_database', 'correlation', 'schema')),
    name         TEXT NOT NULL CHECK (btrim(name) <> ''),
    version      TEXT NOT NULL CHECK (btrim(version) <> ''),
    digest       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, scan_run_id, lane_key, version_kind, name),
    FOREIGN KEY (tenant_id, scan_run_id, lane_key)
        REFERENCES scan_run_lanes(tenant_id, scan_run_id, lane_key) ON DELETE CASCADE
);

CREATE TABLE scan_run_lane_stages (
    tenant_id   TEXT NOT NULL,
    scan_run_id TEXT NOT NULL,
    lane_key    TEXT NOT NULL,
    stage_key   TEXT NOT NULL CHECK (btrim(stage_key) <> ''),
    status      TEXT NOT NULL CHECK (status IN ('succeeded', 'failed', 'skipped')),
    reason_code TEXT NOT NULL DEFAULT '',
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, scan_run_id, lane_key, stage_key),
    FOREIGN KEY (tenant_id, scan_run_id, lane_key)
        REFERENCES scan_run_lanes(tenant_id, scan_run_id, lane_key) ON DELETE CASCADE
);

CREATE INDEX idx_scan_runs_tenant_engagement_cursor ON scan_runs (tenant_id, engagement_id, created_at DESC, id);
CREATE INDEX idx_scan_run_lanes_coverage ON scan_run_lanes (tenant_id, producer, target_kind, target_identity_canonical, evaluated_revision, terminal_status);
CREATE INDEX idx_scan_run_lane_versions_lookup ON scan_run_lane_versions (tenant_id, version_kind, name, version);
CREATE INDEX idx_scan_run_lane_stages_non_success ON scan_run_lane_stages (tenant_id, scan_run_id, lane_key, status) WHERE status IN ('failed', 'skipped');

-- +goose StatementBegin
CREATE FUNCTION synapse_guard_scan_run_update() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.sealed_at IS NOT NULL THEN
        RAISE EXCEPTION 'sealed scan run is immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.engagement_id <> OLD.engagement_id OR NEW.created_at <> OLD.created_at OR NEW.provenance <> OLD.provenance THEN
        RAISE EXCEPTION 'scan run identity is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION synapse_guard_scan_run_lane_update() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.sealed_at IS NOT NULL THEN
        RAISE EXCEPTION 'sealed scan run lane is immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW.tenant_id <> OLD.tenant_id OR NEW.engagement_id <> OLD.engagement_id OR NEW.scan_run_id <> OLD.scan_run_id OR NEW.lane_key <> OLD.lane_key THEN
        RAISE EXCEPTION 'scan run lane identity is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION synapse_guard_scan_run_lane_insert() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    header_sealed_at TIMESTAMPTZ;
BEGIN
    SELECT sealed_at INTO header_sealed_at
      FROM scan_runs
     WHERE tenant_id = NEW.tenant_id
       AND engagement_id = NEW.engagement_id
       AND id = NEW.scan_run_id;
    IF header_sealed_at IS NOT NULL THEN
        RAISE EXCEPTION 'sealed scan run cannot accept new lanes' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION synapse_guard_sealed_scan_run_lane_child() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    parent_sealed_at TIMESTAMPTZ;
    row_tenant_id TEXT;
    row_scan_run_id TEXT;
    row_lane_key TEXT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        row_tenant_id := NEW.tenant_id;
        row_scan_run_id := NEW.scan_run_id;
        row_lane_key := NEW.lane_key;
    ELSE
        row_tenant_id := OLD.tenant_id;
        row_scan_run_id := OLD.scan_run_id;
        row_lane_key := OLD.lane_key;
    END IF;
    SELECT sealed_at INTO parent_sealed_at
      FROM scan_run_lanes
     WHERE tenant_id = row_tenant_id
       AND scan_run_id = row_scan_run_id
       AND lane_key = row_lane_key;
    IF parent_sealed_at IS NOT NULL THEN
        RAISE EXCEPTION 'sealed scan run lane children are immutable' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER scan_runs_guard_update BEFORE UPDATE ON scan_runs FOR EACH ROW EXECUTE FUNCTION synapse_guard_scan_run_update();
CREATE TRIGGER scan_run_lanes_guard_insert BEFORE INSERT ON scan_run_lanes FOR EACH ROW EXECUTE FUNCTION synapse_guard_scan_run_lane_insert();
CREATE TRIGGER scan_run_lanes_guard_update BEFORE UPDATE ON scan_run_lanes FOR EACH ROW EXECUTE FUNCTION synapse_guard_scan_run_lane_update();
CREATE TRIGGER scan_run_lane_versions_guard BEFORE INSERT OR UPDATE OR DELETE ON scan_run_lane_versions FOR EACH ROW EXECUTE FUNCTION synapse_guard_sealed_scan_run_lane_child();
CREATE TRIGGER scan_run_lane_stages_guard BEFORE INSERT OR UPDATE OR DELETE ON scan_run_lane_stages FOR EACH ROW EXECUTE FUNCTION synapse_guard_sealed_scan_run_lane_child();

CALL synapse_enable_tenant_rls('scan_runs');
CALL synapse_enable_tenant_rls('scan_run_lanes');
CALL synapse_enable_tenant_rls('scan_run_lane_versions');
CALL synapse_enable_tenant_rls('scan_run_lane_stages');

-- +goose Down
ALTER TABLE scan_runs NO FORCE ROW LEVEL SECURITY;
ALTER TABLE scan_runs DISABLE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM scan_runs WHERE provenance = 'native') THEN
        RAISE EXCEPTION 'cannot roll back scan-run provenance after native rows exist';
    END IF;
END $$;
-- +goose StatementEnd

DROP TABLE IF EXISTS scan_run_lane_stages;
DROP TABLE IF EXISTS scan_run_lane_versions;
DROP TABLE IF EXISTS scan_run_lanes;
DROP TRIGGER IF EXISTS scan_runs_guard_update ON scan_runs;
DROP FUNCTION IF EXISTS synapse_guard_sealed_scan_run_lane_child();
DROP FUNCTION IF EXISTS synapse_guard_scan_run_lane_insert();
DROP FUNCTION IF EXISTS synapse_guard_scan_run_lane_update();
DROP FUNCTION IF EXISTS synapse_guard_scan_run_update();
DROP POLICY IF EXISTS scan_runs_tenant_isolation ON scan_runs;
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS scan_runs_engagement_fk_tenant;
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS scan_runs_tenant_engagement_id_unique;
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS scan_runs_tenant_id_unique;
ALTER TABLE scan_runs
    DROP COLUMN IF EXISTS sealed_at,
    DROP COLUMN IF EXISTS manifest_hash,
    DROP COLUMN IF EXISTS manifest_schema_version,
    DROP COLUMN IF EXISTS terminal_status,
    DROP COLUMN IF EXISTS provenance,
    DROP COLUMN IF EXISTS tenant_id;
