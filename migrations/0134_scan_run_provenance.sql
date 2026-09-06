-- +goose Up
-- Issue #708 (Phase A2a): Promote scan_runs into a tenant-owned execution header
-- and add normalized, sealed producer-lane provenance tables.
--
-- This is the expand release. scan_runs.tenant_id deliberately remains nullable
-- and scan_runs remains outside forced RLS so a pre-0134 binary can keep writing
-- and reading scan history during the migrate-first rollout window. A small
-- transitional engagement-to-tenant map plus BEFORE INSERT/UPDATE trigger fills
-- tenant_id for legacy writers that do not know about the new column. The
-- contract release may remove that bridge, set NOT NULL, add the composite
-- engagement ownership FK, and enable forced RLS only after every writer binds
-- and supplies tenant identity.

-- 1. Expand scan_runs table with tenant-ownership and sealed provenance metadata
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS tenant_id TEXT;
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS provenance TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS terminal_status TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS manifest_schema_version INT NOT NULL DEFAULT 1;
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS manifest_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS sealed_at TIMESTAMPTZ;
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- 2. Keep an owner-only lookup for the migrate-first overlap. engagements has FORCE RLS,
-- so a production NOSUPERUSER/NOBYPASSRLS owner with no tenant GUC must lift
-- FORCE while it performs the all-tenant migration join. The change and its
-- restoration are in the same transaction and roll back together on failure.
CREATE TABLE scan_run_engagement_tenants (
    engagement_id TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL REFERENCES tenants(id)
);

-- This is migration-only bridge state. Runtime roles must reach it only through
-- the SECURITY DEFINER trigger functions below, never by direct cross-tenant reads.
REVOKE ALL ON TABLE scan_run_engagement_tenants FROM PUBLIC;

-- +goose StatementBegin
DO $$
DECLARE
    v_orphans INT;
BEGIN
    EXECUTE 'ALTER TABLE engagements NO FORCE ROW LEVEL SECURITY';

    PERFORM 1 FROM (
        SELECT sr.id
          FROM scan_runs sr
     LEFT JOIN engagements e ON e.id = sr.engagement_id
         WHERE e.id IS NULL
            OR e.tenant_id IS NULL
            OR e.tenant_id = ''
            OR (sr.tenant_id IS NOT NULL AND sr.tenant_id != '' AND sr.tenant_id != e.tenant_id)
         LIMIT 1
    ) bad;
    IF FOUND THEN
        RAISE EXCEPTION 'migration 0134: scan_runs ownership cannot be resolved from engagements';
    END IF;

    UPDATE scan_runs sr
       SET tenant_id = e.tenant_id
      FROM engagements e
      WHERE sr.engagement_id = e.id
       AND (sr.tenant_id IS NULL OR sr.tenant_id = '');

    INSERT INTO scan_run_engagement_tenants (engagement_id, tenant_id)
    SELECT e.id, e.tenant_id
      FROM engagements e
     WHERE e.tenant_id IS NOT NULL
       AND e.tenant_id != '';

    SELECT COUNT(*) INTO v_orphans FROM scan_runs WHERE tenant_id IS NULL OR tenant_id = '';
    IF v_orphans > 0 THEN
        RAISE EXCEPTION 'migration 0134: found % orphaned scan_runs rows with no matching engagement tenant_id', v_orphans;
    END IF;

    EXECUTE 'ALTER TABLE engagements FORCE ROW LEVEL SECURITY';
END $$;
-- +goose StatementEnd

-- Legacy binaries omit tenant_id on INSERT. Keep their writes visible to the
-- new tenant-scoped readers without weakening FORCE RLS on engagements: the
-- bridge is populated by the engagement row triggers and read only by these
-- SECURITY DEFINER functions. It is removed with this expand migration once
-- the later contract release makes every writer tenant-aware.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION fn_sync_scan_run_engagement_tenant()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM public.scan_run_engagement_tenants
         WHERE engagement_id = OLD.id;
        RETURN OLD;
    END IF;

    INSERT INTO public.scan_run_engagement_tenants (engagement_id, tenant_id)
    VALUES (NEW.id, NEW.tenant_id)
    ON CONFLICT (engagement_id) DO UPDATE
       SET tenant_id = EXCLUDED.tenant_id;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION fn_assign_scan_run_tenant()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    mapped_tenant TEXT;
BEGIN
    SELECT tenant_id INTO mapped_tenant
      FROM public.scan_run_engagement_tenants
     WHERE engagement_id = NEW.engagement_id;

    IF mapped_tenant IS NULL OR mapped_tenant = '' THEN
        RAISE EXCEPTION 'scan_runs tenant cannot be resolved for engagement %', NEW.engagement_id;
    END IF;
    IF NEW.tenant_id IS NULL OR NEW.tenant_id = '' THEN
        NEW.tenant_id := mapped_tenant;
    ELSIF NEW.tenant_id != mapped_tenant THEN
        RAISE EXCEPTION 'scan_runs tenant conflicts with engagement %', NEW.engagement_id;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION fn_sync_scan_run_engagement_tenant() FROM PUBLIC;
REVOKE ALL ON FUNCTION fn_assign_scan_run_tenant() FROM PUBLIC;

CREATE TRIGGER trg_sync_scan_run_engagement_tenant
AFTER INSERT OR UPDATE OR DELETE ON engagements
FOR EACH ROW
EXECUTE FUNCTION fn_sync_scan_run_engagement_tenant();

CREATE TRIGGER trg_assign_scan_run_tenant
BEFORE INSERT OR UPDATE ON scan_runs
FOR EACH ROW
EXECUTE FUNCTION fn_assign_scan_run_tenant();

-- 3. Constraints and indexes on scan_runs
ALTER TABLE scan_runs ADD CONSTRAINT chk_scan_runs_provenance
    CHECK (provenance IN ('legacy', 'native'));

ALTER TABLE scan_runs ADD CONSTRAINT chk_scan_runs_terminal_status
    CHECK (terminal_status IN ('building', 'succeeded', 'partial', 'failed', 'cancelled', 'unknown'));

ALTER TABLE scan_runs ADD CONSTRAINT uq_scan_runs_tenant_id
    UNIQUE (tenant_id, id);

-- The legacy single-column relationship is safe during the nullable overlap
-- and makes engagement deletion an explicit conflict instead of orphaning scan
-- history. The tenant-composite FK is deferred to the contract migration.
ALTER TABLE scan_runs ADD CONSTRAINT fk_scan_runs_engagement
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_scan_runs_tenant_engagement
    ON scan_runs (tenant_id, engagement_id, created_at DESC);

-- 4. Create scan_run_lanes child table
CREATE TABLE scan_run_lanes (
    tenant_id                      TEXT NOT NULL,
    engagement_id                  TEXT NOT NULL,
    scan_run_id                    TEXT NOT NULL,
    lane_key                       TEXT NOT NULL,
    producer                       TEXT NOT NULL,
    terminal_status                TEXT NOT NULL,
    target_kind                    TEXT NOT NULL,
    target_identity_schema_version INT NOT NULL DEFAULT 1,
    target_identity_canonical      TEXT NOT NULL,
    evaluated_revision             TEXT NOT NULL DEFAULT '',
    authoritative_finding_kinds    JSONB NOT NULL DEFAULT '[]'::jsonb,
    included_scope                 JSONB NOT NULL DEFAULT '[]'::jsonb,
    excluded_scope                 JSONB NOT NULL DEFAULT '[]'::jsonb,
    started_at                     TIMESTAMPTZ NOT NULL,
    finished_at                    TIMESTAMPTZ,
    result_ref                     TEXT NOT NULL DEFAULT '',
    evidence_ref                   TEXT NOT NULL DEFAULT '',
    result_sha256                  TEXT NOT NULL DEFAULT '',
    manifest_schema_version        INT NOT NULL DEFAULT 1,
    manifest_hash                  TEXT NOT NULL DEFAULT '',
    sealed_at                      TIMESTAMPTZ,
    created_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, scan_run_id, lane_key),
    CONSTRAINT fk_scan_run_lanes_run FOREIGN KEY (tenant_id, scan_run_id) REFERENCES scan_runs(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_scan_run_lanes_engagement FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagements(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT chk_scan_run_lanes_terminal_status CHECK (terminal_status IN ('building', 'succeeded', 'partial', 'failed', 'cancelled', 'unknown')),
    CONSTRAINT chk_scan_run_lanes_target_kind CHECK (target_kind IN ('repository', 'oci', 'host', 'url', 'cloud_resource')),
    CONSTRAINT chk_scan_run_lanes_finding_kinds_array CHECK (jsonb_typeof(authoritative_finding_kinds) = 'array'),
    CONSTRAINT chk_scan_run_lanes_inc_scope_array CHECK (jsonb_typeof(included_scope) = 'array'),
    CONSTRAINT chk_scan_run_lanes_exc_scope_array CHECK (jsonb_typeof(excluded_scope) = 'array')
);

CREATE INDEX idx_scan_run_lanes_lookup ON scan_run_lanes (tenant_id, scan_run_id, lane_key);

-- 5. Create scan_run_lane_versions child table
CREATE TABLE scan_run_lane_versions (
    tenant_id    TEXT NOT NULL,
    scan_run_id  TEXT NOT NULL,
    lane_key     TEXT NOT NULL,
    version_kind TEXT NOT NULL,
    name         TEXT NOT NULL,
    version      TEXT NOT NULL,
    digest       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, scan_run_id, lane_key, version_kind, name),
    CONSTRAINT fk_scan_run_lane_versions_lane FOREIGN KEY (tenant_id, scan_run_id, lane_key) REFERENCES scan_run_lanes(tenant_id, scan_run_id, lane_key) ON DELETE CASCADE,
    CONSTRAINT chk_scan_run_lane_versions_kind CHECK (version_kind IN ('tool', 'scanner', 'profile', 'rule_pack', 'advisory_database', 'correlation', 'schema'))
);

-- 6. Create scan_run_lane_stages child table
CREATE TABLE scan_run_lane_stages (
    tenant_id   TEXT NOT NULL,
    scan_run_id TEXT NOT NULL,
    lane_key    TEXT NOT NULL,
    stage_key   TEXT NOT NULL,
    status      TEXT NOT NULL,
    reason_code TEXT NOT NULL DEFAULT '',
    started_at  TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, scan_run_id, lane_key, stage_key),
    CONSTRAINT fk_scan_run_lane_stages_lane FOREIGN KEY (tenant_id, scan_run_id, lane_key) REFERENCES scan_run_lanes(tenant_id, scan_run_id, lane_key) ON DELETE CASCADE,
    CONSTRAINT chk_scan_run_lane_stages_status CHECK (status IN ('succeeded', 'failed', 'skipped'))
);

-- 7. Immutability trigger protecting sealed scan runs
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION fn_prevent_sealed_scan_run_mutation()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_TABLE_NAME = 'scan_runs' THEN
        IF TG_OP = 'DELETE' THEN
            IF OLD.sealed_at IS NOT NULL THEN
                RAISE EXCEPTION 'cannot delete sealed scan run %', OLD.id;
            END IF;
            RETURN OLD;
        ELSIF TG_OP = 'UPDATE' THEN
            IF OLD.sealed_at IS NOT NULL THEN
                IF OLD.* IS DISTINCT FROM NEW.* THEN
                    RAISE EXCEPTION 'cannot update sealed scan run %', OLD.id;
                END IF;
            END IF;
            RETURN NEW;
        END IF;
    ELSE
        -- Child tables: scan_run_lanes, scan_run_lane_versions, scan_run_lane_stages
        IF TG_OP = 'INSERT' THEN
            IF EXISTS (
                SELECT 1 FROM scan_runs
                WHERE tenant_id = NEW.tenant_id
                  AND id = NEW.scan_run_id
                  AND sealed_at IS NOT NULL
            ) THEN
                RAISE EXCEPTION 'cannot insert into % for sealed scan run %', TG_TABLE_NAME, NEW.scan_run_id;
            END IF;
            RETURN NEW;
        ELSIF TG_OP = 'UPDATE' THEN
            IF EXISTS (
                SELECT 1 FROM scan_runs
                WHERE (tenant_id = OLD.tenant_id AND id = OLD.scan_run_id AND sealed_at IS NOT NULL)
                   OR (tenant_id = NEW.tenant_id AND id = NEW.scan_run_id AND sealed_at IS NOT NULL)
            ) THEN
                RAISE EXCEPTION 'cannot update % for sealed scan run %', TG_TABLE_NAME, OLD.scan_run_id;
            END IF;
            RETURN NEW;
        ELSIF TG_OP = 'DELETE' THEN
            IF EXISTS (
                SELECT 1 FROM scan_runs
                WHERE tenant_id = OLD.tenant_id
                  AND id = OLD.scan_run_id
                  AND sealed_at IS NOT NULL
            ) THEN
                RAISE EXCEPTION 'cannot delete from % for sealed scan run %', TG_TABLE_NAME, OLD.scan_run_id;
            END IF;
            RETURN OLD;
        END IF;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER trg_scan_runs_sealed_immutability
BEFORE UPDATE OR DELETE ON scan_runs
FOR EACH ROW
EXECUTE FUNCTION fn_prevent_sealed_scan_run_mutation();

CREATE TRIGGER trg_scan_run_lanes_sealed_immutability
BEFORE INSERT OR UPDATE OR DELETE ON scan_run_lanes
FOR EACH ROW
EXECUTE FUNCTION fn_prevent_sealed_scan_run_mutation();

CREATE TRIGGER trg_scan_run_lane_versions_sealed_immutability
BEFORE INSERT OR UPDATE OR DELETE ON scan_run_lane_versions
FOR EACH ROW
EXECUTE FUNCTION fn_prevent_sealed_scan_run_mutation();

CREATE TRIGGER trg_scan_run_lane_stages_sealed_immutability
BEFORE INSERT OR UPDATE OR DELETE ON scan_run_lane_stages
FOR EACH ROW
EXECUTE FUNCTION fn_prevent_sealed_scan_run_mutation();

-- 8. Child provenance is new in this release and has no legacy writer, so it
-- can enforce tenant RLS immediately. scan_runs joins in the contract release.
CALL synapse_enable_tenant_rls('scan_run_lanes');
CALL synapse_enable_tenant_rls('scan_run_lane_versions');
CALL synapse_enable_tenant_rls('scan_run_lane_stages');


-- +goose Down
-- Refuse a rollback that would silently erase sealed chain-of-custody data.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM scan_runs WHERE sealed_at IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 0134: cannot roll back while sealed scan runs exist';
    END IF;
END $$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS trg_scan_run_lane_stages_sealed_immutability ON scan_run_lane_stages;
DROP TRIGGER IF EXISTS trg_scan_run_lane_versions_sealed_immutability ON scan_run_lane_versions;
DROP TRIGGER IF EXISTS trg_scan_run_lanes_sealed_immutability ON scan_run_lanes;
DROP TRIGGER IF EXISTS trg_scan_runs_sealed_immutability ON scan_runs;
DROP TRIGGER IF EXISTS trg_assign_scan_run_tenant ON scan_runs;
DROP TRIGGER IF EXISTS trg_sync_scan_run_engagement_tenant ON engagements;
DROP FUNCTION IF EXISTS fn_assign_scan_run_tenant();
DROP FUNCTION IF EXISTS fn_sync_scan_run_engagement_tenant();
DROP FUNCTION IF EXISTS fn_prevent_sealed_scan_run_mutation();

DROP TABLE IF EXISTS scan_run_lane_stages;
DROP TABLE IF EXISTS scan_run_lane_versions;
DROP TABLE IF EXISTS scan_run_lanes;
DROP TABLE IF EXISTS scan_run_engagement_tenants;

DROP INDEX IF EXISTS idx_scan_runs_tenant_engagement;
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS fk_scan_runs_engagement;
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS uq_scan_runs_tenant_id;
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS chk_scan_runs_terminal_status;
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS chk_scan_runs_provenance;

ALTER TABLE scan_runs DROP COLUMN IF EXISTS updated_at;
ALTER TABLE scan_runs DROP COLUMN IF EXISTS sealed_at;
ALTER TABLE scan_runs DROP COLUMN IF EXISTS manifest_hash;
ALTER TABLE scan_runs DROP COLUMN IF EXISTS manifest_schema_version;
ALTER TABLE scan_runs DROP COLUMN IF EXISTS terminal_status;
ALTER TABLE scan_runs DROP COLUMN IF EXISTS provenance;
ALTER TABLE scan_runs DROP COLUMN IF EXISTS tenant_id;
