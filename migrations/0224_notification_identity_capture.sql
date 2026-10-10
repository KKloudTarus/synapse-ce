-- +goose Up
-- Capture stays legacy until an operator switches after deploying capable projectors.
CREATE TABLE notification_capture_policy (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    mode TEXT NOT NULL DEFAULT 'legacy' CHECK (mode IN ('legacy','identity')),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO notification_capture_policy(singleton) VALUES(true);
REVOKE ALL ON notification_capture_policy FROM PUBLIC;
ALTER TABLE notification_source_records ADD COLUMN capture_version INT NOT NULL DEFAULT 1 CHECK (capture_version IN (1,2));
CREATE INDEX notification_pending_identity_capture ON notification_source_records(tenant_id)
    WHERE capture_version=2 AND processed_at IS NULL;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION notification_capture_source() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    tenant TEXT;
    skind TEXT;
    sid TEXT;
    etype TEXT;
    eng TEXT := '';
    sev TEXT := '';
    happened TIMESTAMPTZ;
    body JSONB;
    capture_mode TEXT;
    format_version INT;
BEGIN
    -- Mode changes take the exclusive form of this lock and wait for in-flight captures.
    PERFORM pg_advisory_xact_lock_shared(78146);
    SELECT mode INTO STRICT capture_mode FROM notification_capture_policy WHERE singleton;
    format_version := CASE WHEN capture_mode='identity' THEN 2 ELSE 1 END;
    IF TG_TABLE_NAME='scan_jobs' THEN
        IF NEW.status<>'succeeded' OR NEW.finished_at IS NULL THEN RETURN NEW; END IF;
        SELECT tenant_id INTO tenant FROM engagements WHERE id=NEW.engagement_id;
        skind:='scan_job'; sid:=NEW.id; etype:='scan.completed'; eng:=NEW.engagement_id; happened:=NEW.finished_at;
        body:=CASE WHEN capture_mode='identity' THEN '{}'::jsonb ELSE jsonb_build_object('title','Scan completed','summary','A scan completed successfully.','scan_id',NEW.id,'scan_kind',NEW.kind) END;
    ELSIF TG_TABLE_NAME='project_analyses' THEN
        IF NEW.payload #>> '{gate,Passed}' IS DISTINCT FROM 'false' THEN RETURN NEW; END IF;
        tenant:=NEW.tenant_id; skind:='project_analysis_gate'; sid:=NEW.id; etype:='quality_gate.failed'; happened:=NEW.created_at;
        body:=CASE WHEN capture_mode='identity' THEN '{}'::jsonb ELSE jsonb_build_object('title','Quality gate failed','summary','A finalized project analysis failed its quality gate.','analysis_id',NEW.id,'project_id',NEW.project_id) END;
    ELSE
        IF NEW.kind<>'created' THEN RETURN NEW; END IF;
        tenant:=NEW.tenant_id; skind:='incident'; sid:=NEW.incident_id; etype:='incident.created'; happened:=NEW.occurred_at;
        eng:=COALESCE(NEW.payload->>'EngagementID',''); sev:=COALESCE(NEW.payload->>'Severity','');
        body:=CASE WHEN capture_mode='identity' THEN '{}'::jsonb ELSE jsonb_build_object('title',left(COALESCE(NEW.payload->>'Title','Security incident created'),500),'summary','Fleet correlation created an incident.','incident_id',NEW.incident_id,'asset_id',NEW.asset_id) END;
    END IF;
    IF tenant IS NULL OR NOT EXISTS(SELECT 1 FROM notification_source_state s WHERE s.tenant_id=tenant AND s.source_kind='framework' AND s.source_id='activation' AND s.observed_at<=happened) THEN RETURN NEW; END IF;
    INSERT INTO notification_source_records(tenant_id,source_kind,source_id,event_type,engagement_id,severity,occurred_at,data,capture_version)
    VALUES(tenant,skind,sid,etype,eng,sev,happened,body,format_version) ON CONFLICT DO NOTHING;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION notification_guard_source_capture() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.capture_version IS DISTINCT FROM OLD.capture_version THEN
        RAISE EXCEPTION 'notification capture format is immutable' USING ERRCODE='55000';
    END IF;
    IF OLD.capture_version=2 THEN
        IF (to_jsonb(NEW)-ARRAY['processed_at','failed_reason']) IS DISTINCT FROM
           (to_jsonb(OLD)-ARRAY['processed_at','failed_reason']) THEN
            RAISE EXCEPTION 'notification identity capture is immutable' USING ERRCODE='55000';
        END IF;
        IF NEW.processed_at IS NOT NULL AND OLD.processed_at IS NULL AND
           current_setting('synapse.notification_source_capability',true) IS DISTINCT FROM 'identity-v1' THEN
            RAISE EXCEPTION 'notification capture requires identity-v1 projector' USING ERRCODE='55000';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER notification_source_capture_guard BEFORE UPDATE ON notification_source_records
    FOR EACH ROW EXECUTE FUNCTION notification_guard_source_capture();

-- +goose StatementBegin
CREATE FUNCTION notification_guard_identity_publication() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS(SELECT 1 FROM notification_source_records s
        WHERE s.tenant_id=NEW.tenant_id AND s.source_kind=NEW.source_kind AND s.source_id=NEW.source_id
          AND s.capture_version=2) AND
       current_setting('synapse.notification_source_capability',true) IS DISTINCT FROM 'identity-v1' THEN
        RAISE EXCEPTION 'notification publication requires identity-v1 projector' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER notification_identity_publication_guard BEFORE INSERT ON notification_events
    FOR EACH ROW EXECUTE FUNCTION notification_guard_identity_publication();

-- +goose Down
-- Restore legacy through the operator command and drain identity records before downgrading.
-- +goose StatementBegin
DO $$
DECLARE
    capture_tenant TEXT;
BEGIN
    PERFORM pg_advisory_xact_lock(78146);
    IF (SELECT mode FROM notification_capture_policy WHERE singleton) IS DISTINCT FROM 'legacy' THEN
        RAISE EXCEPTION 'restore legacy capture and drain identity records before downgrade' USING ERRCODE='55000';
    END IF;
    FOR capture_tenant IN SELECT id FROM tenants WHERE id<>'' LOOP
        PERFORM set_config('app.current_tenant',capture_tenant,true);
        IF EXISTS(SELECT 1 FROM notification_source_records WHERE tenant_id=capture_tenant AND capture_version=2 AND processed_at IS NULL) THEN
            RAISE EXCEPTION 'restore legacy capture and drain identity records before downgrade' USING ERRCODE='55000';
        END IF;
    END LOOP;
END;
$$;
-- +goose StatementEnd
DROP TRIGGER notification_identity_publication_guard ON notification_events;
DROP FUNCTION notification_guard_identity_publication();
DROP TRIGGER notification_source_capture_guard ON notification_source_records;
DROP FUNCTION notification_guard_source_capture();
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION notification_capture_source() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    tenant TEXT;
    skind TEXT;
    sid TEXT;
    etype TEXT;
    eng TEXT := '';
    sev TEXT := '';
    happened TIMESTAMPTZ;
    body JSONB;
BEGIN
    IF TG_TABLE_NAME='scan_jobs' THEN
        IF NEW.status<>'succeeded' OR NEW.finished_at IS NULL THEN RETURN NEW; END IF;
        SELECT tenant_id INTO tenant FROM engagements WHERE id=NEW.engagement_id;
        skind:='scan_job'; sid:=NEW.id; etype:='scan.completed'; eng:=NEW.engagement_id; happened:=NEW.finished_at;
        body:=jsonb_build_object('title','Scan completed','summary','A scan completed successfully.','scan_id',NEW.id,'scan_kind',NEW.kind);
    ELSIF TG_TABLE_NAME='project_analyses' THEN
        IF NEW.payload #>> '{gate,Passed}' IS DISTINCT FROM 'false' THEN RETURN NEW; END IF;
        tenant:=NEW.tenant_id; skind:='project_analysis_gate'; sid:=NEW.id; etype:='quality_gate.failed'; happened:=NEW.created_at;
        body:=jsonb_build_object('title','Quality gate failed','summary','A finalized project analysis failed its quality gate.','analysis_id',NEW.id,'project_id',NEW.project_id);
    ELSE
        IF NEW.kind<>'created' THEN RETURN NEW; END IF;
        tenant:=NEW.tenant_id; skind:='incident'; sid:=NEW.incident_id; etype:='incident.created'; happened:=NEW.occurred_at;
        eng:=COALESCE(NEW.payload->>'EngagementID',''); sev:=COALESCE(NEW.payload->>'Severity','');
        body:=jsonb_build_object('title',left(COALESCE(NEW.payload->>'Title','Security incident created'),500),'summary','Fleet correlation created an incident.','incident_id',NEW.incident_id,'asset_id',NEW.asset_id);
    END IF;
    IF tenant IS NULL OR NOT EXISTS(SELECT 1 FROM notification_source_state s WHERE s.tenant_id=tenant AND s.source_kind='framework' AND s.source_id='activation' AND s.observed_at<=happened) THEN RETURN NEW; END IF;
    INSERT INTO notification_source_records(tenant_id,source_kind,source_id,event_type,engagement_id,severity,occurred_at,data)
    VALUES(tenant,skind,sid,etype,eng,sev,happened,body) ON CONFLICT DO NOTHING;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
DROP INDEX notification_pending_identity_capture;
ALTER TABLE notification_source_records DROP COLUMN capture_version;
DROP TABLE notification_capture_policy;
