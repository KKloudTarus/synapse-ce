-- +goose Up
CREATE TABLE ownership_sources (
 tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, id TEXT NOT NULL,
 capture_sequence BIGINT GENERATED ALWAYS AS IDENTITY,
 repository TEXT NOT NULL CHECK (length(repository) BETWEEN 1 AND 2048),
 source_revision TEXT NOT NULL DEFAULT '', base_revision TEXT NOT NULL DEFAULT '',
 base_required BOOLEAN NOT NULL DEFAULT false,
 reason TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL CHECK (btrim(created_by)<>''),
 created_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY (tenant_id,engagement_id,id),
 FOREIGN KEY (tenant_id,engagement_id) REFERENCES engagements(tenant_id,id),
 CHECK (source_revision='' OR source_revision ~ '^(git:([a-f0-9]{40}|[a-f0-9]{64})|sha256:[a-f0-9]{64})$'),
 CHECK (base_revision='' OR base_revision ~ '^git:([a-f0-9]{40}|[a-f0-9]{64})$')
);
CALL synapse_enable_tenant_rls('ownership_sources');
CREATE TRIGGER ownership_sources_immutable BEFORE UPDATE OR DELETE ON ownership_sources
 FOR EACH ROW EXECUTE FUNCTION ownership_reject_mutation();

-- Admission/capture alone is not a completed scan. A dispatcher holds source
-- findings until their producer has finished binding and projecting this input.
CREATE TABLE ownership_source_readiness (
 tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, source_id TEXT NOT NULL,
 ready_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (tenant_id,engagement_id,source_id),
 FOREIGN KEY (tenant_id,engagement_id,source_id) REFERENCES ownership_sources(tenant_id,engagement_id,id)
);
CALL synapse_enable_tenant_rls('ownership_source_readiness');
CREATE TRIGGER ownership_source_readiness_immutable BEFORE UPDATE OR DELETE ON ownership_source_readiness
 FOR EACH ROW EXECUTE FUNCTION ownership_reject_mutation();

CREATE TABLE ownership_source_snapshots (
 tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, source_id TEXT NOT NULL,
 snapshot_id TEXT NOT NULL,
 PRIMARY KEY (tenant_id,engagement_id,source_id,snapshot_id),
 FOREIGN KEY (tenant_id,engagement_id,source_id) REFERENCES ownership_sources(tenant_id,engagement_id,id),
 FOREIGN KEY (tenant_id,engagement_id,snapshot_id) REFERENCES ownership_snapshots(tenant_id,engagement_id,id)
);
CALL synapse_enable_tenant_rls('ownership_source_snapshots');
CREATE TRIGGER ownership_source_snapshots_immutable BEFORE UPDATE OR DELETE ON ownership_source_snapshots
 FOR EACH ROW EXECUTE FUNCTION ownership_reject_mutation();

CREATE TABLE ownership_finding_sources (
 tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, finding_id TEXT NOT NULL,
 source_id TEXT NOT NULL, origin_hash TEXT NOT NULL CHECK (length(origin_hash)=64),
 binding_hash TEXT NOT NULL CHECK (length(binding_hash)=64),
 paths JSONB NOT NULL CHECK (jsonb_typeof(paths)='array' AND jsonb_array_length(paths)<=128 AND octet_length(paths::text)<=1048576),
 invalid BOOLEAN NOT NULL,
 PRIMARY KEY (tenant_id,engagement_id,finding_id),
 FOREIGN KEY (tenant_id,engagement_id,finding_id) REFERENCES findings(tenant_id,engagement_id,id) ON DELETE CASCADE,
 FOREIGN KEY (tenant_id,engagement_id,source_id) REFERENCES ownership_sources(tenant_id,engagement_id,id)
);
CALL synapse_enable_tenant_rls('ownership_finding_sources');

-- One coalesced obligation per canonical finding, regardless of producer. A
-- generation CAS prevents a dispatcher from acknowledging a concurrent update.
CREATE TABLE ownership_dirty_findings (
 tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, finding_id TEXT NOT NULL,
 generation BIGINT NOT NULL DEFAULT 1 CHECK (generation>0),
 PRIMARY KEY (tenant_id,engagement_id,finding_id),
 FOREIGN KEY (tenant_id,engagement_id,finding_id) REFERENCES findings(tenant_id,engagement_id,id) ON DELETE CASCADE
);
CALL synapse_enable_tenant_rls('ownership_dirty_findings');

-- +goose StatementBegin
CREATE FUNCTION ownership_mark_finding_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND (NEW.kind,NEW.severity,NEW.occurrence_id,NEW.component_fingerprint,NEW.rule_key)
    IS NOT DISTINCT FROM (OLD.kind,OLD.severity,OLD.occurrence_id,OLD.component_fingerprint,OLD.rule_key) THEN
  RETURN NEW;
 END IF;
 INSERT INTO ownership_dirty_findings(tenant_id,engagement_id,finding_id)
 VALUES(NEW.tenant_id,NEW.engagement_id,NEW.id)
 ON CONFLICT (tenant_id,engagement_id,finding_id) DO UPDATE
 SET generation=ownership_dirty_findings.generation+1;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER ownership_finding_producer AFTER INSERT OR UPDATE ON findings
 FOR EACH ROW EXECUTE FUNCTION ownership_mark_finding_dirty();

-- +goose Down
DROP TRIGGER ownership_finding_producer ON findings;
DROP FUNCTION ownership_mark_finding_dirty();
DROP TABLE ownership_dirty_findings;
DROP TABLE ownership_finding_sources;
DROP TABLE ownership_source_snapshots;
DROP TABLE ownership_source_readiness;
DROP TABLE ownership_sources;
