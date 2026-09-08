-- +goose Up
-- Source metadata is frozen when a job is admitted, then copied into the
-- immutable run manifest. Existing runs are deliberately not reconstructed.
ALTER TABLE scan_jobs ADD COLUMN source_package JSONB;
ALTER TABLE scan_jobs ADD COLUMN source_tenant_id TEXT
 GENERATED ALWAYS AS (source_package->>'tenant_id') STORED;
ALTER TABLE scan_jobs ADD COLUMN source_version_id TEXT
 GENERATED ALWAYS AS (source_package->>'version_id') STORED;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_source_owner_fk
 FOREIGN KEY (source_tenant_id, engagement_id, source_version_id)
 REFERENCES engagement_source_packages(tenant_id, engagement_id, version_id) ON DELETE RESTRICT;
CREATE INDEX scan_jobs_source_reference ON scan_jobs(source_tenant_id, engagement_id, source_version_id)
 WHERE source_version_id IS NOT NULL;

ALTER TABLE scan_runs ADD COLUMN source_version_id TEXT
 GENERATED ALWAYS AS (manifest->'source_package'->>'version_id') STORED;
ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_source_owner_fk
 FOREIGN KEY (tenant_id, engagement_id, source_version_id)
 REFERENCES engagement_source_packages(tenant_id, engagement_id, version_id) ON DELETE RESTRICT;
CREATE INDEX scan_runs_source_reference ON scan_runs(tenant_id, engagement_id, source_version_id)
 WHERE source_version_id IS NOT NULL;

-- +goose StatementBegin
CREATE FUNCTION synapse_validate_scan_source(source JSONB, owner_tenant TEXT, owner_engagement TEXT)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
 IF source IS NULL THEN RETURN; END IF;
 IF jsonb_typeof(source) <> 'object' OR octet_length(source::text) > 16384
    OR COALESCE(source->>'version_id','') = ''
    OR source->>'tenant_id' IS DISTINCT FROM owner_tenant
    OR source->>'engagement_id' IS DISTINCT FROM owner_engagement
    OR source - ARRAY['tenant_id','engagement_id','version_id','reused_from_version_id',
       'filename','size','sha256','created_by','created_at','associated_by','associated_at'] <> '{}'::jsonb THEN
  RAISE EXCEPTION 'invalid scan source metadata' USING ERRCODE='23514';
 END IF;
 PERFORM 1 FROM engagement_source_packages p
 WHERE p.tenant_id = owner_tenant AND p.engagement_id = owner_engagement
   AND p.version_id = source->>'version_id' AND p.filename = source->>'filename'
   AND p.size_bytes = (source->>'size')::bigint AND p.sha256 = source->>'sha256'
   AND p.created_by = source->>'created_by' AND p.created_at = (source->>'created_at')::timestamptz
   AND p.associated_by = source->>'associated_by' AND p.associated_at = (source->>'associated_at')::timestamptz
   AND p.reused_from_version_id IS NOT DISTINCT FROM NULLIF(source->>'reused_from_version_id','');
 IF NOT FOUND THEN
  RAISE EXCEPTION 'scan source metadata does not match its owned version' USING ERRCODE='23514';
 END IF;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION synapse_guard_scan_job_source() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP = 'UPDATE' THEN
  IF NEW.source_package IS DISTINCT FROM OLD.source_package
     OR (OLD.source_package IS NOT NULL AND (NEW.engagement_id IS DISTINCT FROM OLD.engagement_id
         OR NEW.target IS DISTINCT FROM OLD.target OR NEW.kind IS DISTINCT FROM OLD.kind)) THEN
   RAISE EXCEPTION 'scan job source binding is immutable' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF NEW.source_package IS NOT NULL THEN
  IF NEW.kind <> 'upload' OR NEW.target IS DISTINCT FROM ('uploaded-source/sha256/' || (NEW.source_package->>'sha256')) THEN
   RAISE EXCEPTION 'scan job target does not match its source' USING ERRCODE='23514';
  END IF;
  PERFORM synapse_validate_scan_source(NEW.source_package, NEW.source_package->>'tenant_id', NEW.engagement_id);
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER scan_jobs_immutable_source BEFORE INSERT OR UPDATE ON scan_jobs
 FOR EACH ROW EXECUTE FUNCTION synapse_guard_scan_job_source();

-- +goose StatementBegin
CREATE FUNCTION synapse_guard_scan_run_source() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP = 'UPDATE' THEN
  IF NEW.manifest->'source_package' IS DISTINCT FROM OLD.manifest->'source_package' THEN
   RAISE EXCEPTION 'scan run source binding is immutable' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 PERFORM synapse_validate_scan_source(NEW.manifest->'source_package', NEW.tenant_id, NEW.engagement_id);
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER scan_runs_immutable_source BEFORE INSERT OR UPDATE ON scan_runs
 FOR EACH ROW EXECUTE FUNCTION synapse_guard_scan_run_source();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM scan_jobs WHERE source_package IS NOT NULL)
    OR EXISTS (SELECT 1 FROM scan_runs WHERE source_version_id IS NOT NULL) THEN
  RAISE EXCEPTION 'cannot roll back source bindings while scan history references uploaded source';
 END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER scan_runs_immutable_source ON scan_runs;
DROP TRIGGER scan_jobs_immutable_source ON scan_jobs;
DROP FUNCTION synapse_guard_scan_run_source();
DROP FUNCTION synapse_guard_scan_job_source();
DROP FUNCTION synapse_validate_scan_source(JSONB,TEXT,TEXT);
ALTER TABLE scan_runs DROP COLUMN source_version_id;
ALTER TABLE scan_jobs DROP COLUMN source_tenant_id;
ALTER TABLE scan_jobs DROP COLUMN source_version_id;
ALTER TABLE scan_jobs DROP COLUMN source_package;
