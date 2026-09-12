-- +goose Up
ALTER TABLE ownership_policies ADD COLUMN activated_at TIMESTAMPTZ;
-- Existing active policies retain a rollout boundary, never implicitly backfill.
UPDATE ownership_policies SET activated_at=clock_timestamp() WHERE active_version IS NOT NULL;

CREATE TABLE ownership_run_requests (
 tenant_id TEXT NOT NULL, actor_id TEXT NOT NULL, request_key TEXT NOT NULL,
 request_hash TEXT NOT NULL CHECK (length(request_hash)=64), run_id TEXT NOT NULL,
 PRIMARY KEY(tenant_id,actor_id,request_key),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES users(ownership_tenant_id,id),
 FOREIGN KEY(tenant_id,run_id) REFERENCES ownership_runs(tenant_id,id)
);
CALL synapse_enable_tenant_rls('ownership_run_requests');
CREATE TRIGGER ownership_run_requests_immutable BEFORE UPDATE OR DELETE ON ownership_run_requests
 FOR EACH ROW EXECUTE FUNCTION ownership_reject_mutation();

-- Inputs/selection never change after admission. Results are committed one item
-- at a time with the same live job fence as assignment/audit/outbox writes.
CREATE TABLE ownership_work_items (
 tenant_id TEXT NOT NULL, job_id TEXT NOT NULL, engagement_id TEXT NOT NULL,
 finding_id TEXT NOT NULL, run_id TEXT,
 policy_id TEXT NOT NULL, policy_version INTEGER NOT NULL, policy_revision INTEGER NOT NULL,
 mode TEXT NOT NULL CHECK(mode IN ('preview','reroute','observe','enforce')),
 finding_version INTEGER NOT NULL, input JSONB NOT NULL,
 binding_hash TEXT NOT NULL, origin JSONB NOT NULL, binding_origin TEXT NOT NULL,
 outcome TEXT NOT NULL DEFAULT 'pending' CHECK(outcome IN ('pending','evaluated','manual_protected','conflict')),
 result JSONB,
 PRIMARY KEY(tenant_id,job_id,finding_id),
 FOREIGN KEY(tenant_id,job_id) REFERENCES jobs(tenant_id,id),
 FOREIGN KEY(tenant_id,engagement_id,finding_id) REFERENCES findings(tenant_id,engagement_id,id),
 FOREIGN KEY(tenant_id,run_id,engagement_id) REFERENCES ownership_runs(tenant_id,id,engagement_id),
 FOREIGN KEY(tenant_id,policy_id,policy_version) REFERENCES ownership_policy_versions(tenant_id,policy_id,version),
 CHECK(jsonb_typeof(input)='object' AND octet_length(input::text)<=2097152),
 CHECK((outcome='pending')=(result IS NULL))
);
CALL synapse_enable_tenant_rls('ownership_work_items');
CREATE INDEX ownership_work_pending ON ownership_work_items(tenant_id,job_id,finding_id) WHERE outcome='pending';
CREATE INDEX ownership_work_run ON ownership_work_items(tenant_id,run_id,finding_id);
-- +goose StatementBegin
CREATE FUNCTION ownership_work_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' OR (NEW.tenant_id,NEW.job_id,NEW.engagement_id,NEW.finding_id,NEW.run_id,NEW.policy_id,NEW.policy_version,NEW.policy_revision,NEW.mode,NEW.finding_version,NEW.input,NEW.binding_hash,NEW.origin,NEW.binding_origin)
 IS DISTINCT FROM (OLD.tenant_id,OLD.job_id,OLD.engagement_id,OLD.finding_id,OLD.run_id,OLD.policy_id,OLD.policy_version,OLD.policy_revision,OLD.mode,OLD.finding_version,OLD.input,OLD.binding_hash,OLD.origin,OLD.binding_origin)
 OR OLD.outcome<>'pending' THEN
  RAISE EXCEPTION 'ownership execution input/result is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER ownership_work_immutable BEFORE UPDATE OR DELETE ON ownership_work_items
 FOR EACH ROW EXECUTE FUNCTION ownership_work_immutable();

-- Engagement association changes are expanded in bounded pages by dispatch,
-- rather than locking every historical finding in an HTTP transaction.
CREATE TABLE ownership_dirty_scopes (
 tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL,
 generation BIGINT NOT NULL DEFAULT 1, after_id TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(tenant_id,engagement_id),
 FOREIGN KEY(tenant_id,engagement_id) REFERENCES engagements(tenant_id,id)
);
CALL synapse_enable_tenant_rls('ownership_dirty_scopes');
-- +goose StatementBegin
CREATE FUNCTION ownership_mark_scope_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.business_asset_id,NEW.assessment_project_id) IS DISTINCT FROM (OLD.business_asset_id,OLD.assessment_project_id) THEN
  INSERT INTO ownership_dirty_scopes(tenant_id,engagement_id) VALUES(NEW.tenant_id,NEW.id)
  ON CONFLICT(tenant_id,engagement_id) DO UPDATE SET generation=ownership_dirty_scopes.generation+1,after_id='';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER ownership_scope_changed AFTER UPDATE OF business_asset_id,assessment_project_id ON engagements
 FOR EACH ROW EXECUTE FUNCTION ownership_mark_scope_dirty();

-- +goose Down
DROP TRIGGER ownership_scope_changed ON engagements;
DROP FUNCTION ownership_mark_scope_dirty();
DROP TABLE ownership_dirty_scopes;
DROP TABLE ownership_work_items;
DROP FUNCTION ownership_work_immutable();
DROP TABLE ownership_run_requests;
ALTER TABLE ownership_policies DROP COLUMN activated_at;
