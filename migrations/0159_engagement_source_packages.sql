-- +goose Up
CREATE TABLE engagement_source_packages (
 tenant_id TEXT NOT NULL,
 engagement_id TEXT NOT NULL,
 version_id TEXT NOT NULL CHECK (version_id ~ '^[0-9a-f]{32}$'),
 filename TEXT NOT NULL CHECK (octet_length(filename) BETWEEN 1 AND 255),
 size_bytes BIGINT NOT NULL CHECK (size_bytes BETWEEN 1 AND 536870912),
 sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
 locator TEXT NOT NULL CHECK (octet_length(locator) BETWEEN 1 AND 1024),
 object_key TEXT NOT NULL CHECK (octet_length(object_key) BETWEEN 1 AND 1024),
 created_by TEXT NOT NULL CHECK (octet_length(created_by) BETWEEN 1 AND 512),
 created_at TIMESTAMPTZ NOT NULL,
 associated_by TEXT NOT NULL CHECK (octet_length(associated_by) BETWEEN 1 AND 512),
 associated_at TIMESTAMPTZ NOT NULL,
 reused_from_version_id TEXT,
 PRIMARY KEY (tenant_id,version_id),
 UNIQUE (tenant_id,engagement_id),
 UNIQUE (tenant_id,engagement_id,version_id),
 UNIQUE (tenant_id,locator),
 FOREIGN KEY (tenant_id,engagement_id) REFERENCES engagements(tenant_id,id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id,reused_from_version_id) REFERENCES engagement_source_packages(tenant_id,version_id) ON DELETE RESTRICT,
 CHECK (reused_from_version_id IS NULL OR reused_from_version_id <> version_id)
);
CREATE INDEX engagement_source_packages_object_refs ON engagement_source_packages(tenant_id,object_key);
CALL synapse_enable_tenant_rls('engagement_source_packages');
-- +goose StatementBegin
CREATE FUNCTION synapse_source_package_immutable() RETURNS trigger AS $$
BEGIN
 IF TG_OP = 'DELETE' THEN
  IF EXISTS (SELECT 1 FROM scan_runs r WHERE r.tenant_id=OLD.tenant_id AND r.engagement_id=OLD.engagement_id)
   OR EXISTS (SELECT 1 FROM scan_jobs j WHERE j.engagement_id=OLD.engagement_id) THEN
   RAISE EXCEPTION 'uploaded source package is retained by scan history' USING ERRCODE='23503';
  END IF;
  RETURN OLD;
 END IF;
 IF TG_OP = 'UPDATE' THEN
  RAISE EXCEPTION 'uploaded source package metadata is immutable' USING ERRCODE='23514';
 END IF;
 IF NEW.reused_from_version_id IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM engagement_source_packages p
  WHERE p.tenant_id=NEW.tenant_id AND p.version_id=NEW.reused_from_version_id
   AND p.engagement_id<>NEW.engagement_id AND p.sha256=NEW.sha256
   AND p.size_bytes=NEW.size_bytes AND p.filename=NEW.filename
   AND p.object_key=NEW.object_key AND p.created_by=NEW.created_by AND p.created_at=NEW.created_at
 ) THEN
  RAISE EXCEPTION 'reused source package must preserve its original content and upload attribution' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER source_package_immutable BEFORE INSERT OR UPDATE OR DELETE ON engagement_source_packages
 FOR EACH ROW EXECUTE FUNCTION synapse_source_package_immutable();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM engagement_source_packages) THEN
  RAISE EXCEPTION 'cannot roll back uploaded source package metadata while packages exist';
 END IF;
END $$;
-- +goose StatementEnd
DROP TABLE engagement_source_packages;
DROP FUNCTION synapse_source_package_immutable();
