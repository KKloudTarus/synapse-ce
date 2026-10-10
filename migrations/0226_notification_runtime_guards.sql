-- +goose Up
-- Keep the legacy bigint barrier while mixed 0224/0226 binaries exist. New
-- binaries also take this namespaced two-int lock after it, so either version
-- serializes capture mode changes with trigger capture.
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
    PERFORM pg_advisory_xact_lock_shared(78146);
    PERFORM pg_advisory_xact_lock_shared(78146, 1);
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
CREATE OR REPLACE FUNCTION notification_guard_source_capture() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.capture_version IS DISTINCT FROM OLD.capture_version THEN
        RAISE EXCEPTION 'notification capture format is immutable' USING ERRCODE='55000';
    END IF;
    IF OLD.capture_version=2 THEN
        IF (to_jsonb(NEW)-ARRAY['processed_at','failed_reason']) IS DISTINCT FROM
           (to_jsonb(OLD)-ARRAY['processed_at','failed_reason']) THEN
            RAISE EXCEPTION 'notification identity capture is immutable' USING ERRCODE='55000';
        END IF;
        IF OLD.processed_at IS NOT NULL OR NEW.processed_at IS NULL THEN
            IF NEW.processed_at IS DISTINCT FROM OLD.processed_at OR NEW.failed_reason IS DISTINCT FROM OLD.failed_reason THEN
                RAISE EXCEPTION 'notification identity capture is immutable' USING ERRCODE='55000';
            END IF;
        -- A successful item savepoint can leave the publication marker set on
        -- the outer poll transaction. The narrower missing-source capability
        -- must therefore take priority for this exact terminal transition.
        ELSIF current_setting('synapse.notification_source_quarantine_capability',true) = 'source-missing-v1'
          AND OLD.failed_reason='' AND NEW.failed_reason='source_missing' THEN
            NULL;
        ELSIF current_setting('synapse.notification_source_capability',true) = 'identity-v1' THEN
            IF NEW.failed_reason IS DISTINCT FROM OLD.failed_reason THEN
                RAISE EXCEPTION 'notification identity capture is immutable' USING ERRCODE='55000';
            END IF;
        ELSE
            RAISE EXCEPTION 'notification capture requires identity-v1 projector' USING ERRCODE='55000';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- Every webhook sender must pass current admission in the same transaction.
-- The marker does not contain tenant, destination, or credential material.
-- +goose StatementBegin
CREATE FUNCTION notification_guard_webhook_attempt() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS(
        SELECT 1
        FROM notification_deliveries d
        JOIN notification_channels c ON c.tenant_id=d.tenant_id AND c.id=d.channel_id
        WHERE d.tenant_id=NEW.tenant_id AND d.id=NEW.delivery_id
          AND c.channel_type='webhook'
    ) AND current_setting('synapse.notification_delivery_capability',true) IS DISTINCT FROM 'current-filter-v1' THEN
        RAISE EXCEPTION 'webhook delivery attempt requires current-filter-v1 admission' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER notification_webhook_attempt_guard
    BEFORE INSERT ON notification_delivery_attempts
    FOR EACH ROW EXECUTE FUNCTION notification_guard_webhook_attempt();

-- +goose Down
-- Removing this fence would re-enable an older webhook sender. It is safe only
-- after channels are disabled and all current work has been drained.
-- +goose StatementBegin
DO $$
DECLARE
    capture_tenant TEXT;
BEGIN
    -- These locks fence configuration and admission writes for this entire
    -- rollback transaction. A pre-existing repeatable-read snapshot could
    -- miss a commit that completed while waiting for a fence, so fail closed.
    IF current_setting('transaction_isolation') IS DISTINCT FROM 'read committed' THEN
        RAISE EXCEPTION 'notification runtime guard rollback requires read committed isolation' USING ERRCODE='55000';
    END IF;
    PERFORM set_config('lock_timeout','5s',true);
    LOCK TABLE tenants IN SHARE ROW EXCLUSIVE MODE;
    LOCK TABLE notification_channels IN SHARE ROW EXCLUSIVE MODE;
    LOCK TABLE notification_deliveries IN SHARE ROW EXCLUSIVE MODE;
    LOCK TABLE notification_delivery_attempts IN SHARE ROW EXCLUSIVE MODE;
    PERFORM pg_advisory_xact_lock(78146);
    PERFORM pg_advisory_xact_lock(78146, 1);
    FOR capture_tenant IN SELECT id FROM tenants WHERE id<>'' LOOP
        PERFORM set_config('app.current_tenant',capture_tenant,true);
        IF EXISTS(SELECT 1 FROM notification_channels WHERE tenant_id=capture_tenant AND channel_type='webhook' AND enabled AND deleted_at IS NULL)
           OR EXISTS(SELECT 1 FROM notification_delivery_attempts a JOIN notification_deliveries d ON d.tenant_id=a.tenant_id AND d.id=a.delivery_id JOIN notification_channels c ON c.tenant_id=d.tenant_id AND c.id=d.channel_id WHERE a.tenant_id=capture_tenant AND c.channel_type='webhook' AND a.outcome='started' AND a.finished_at IS NULL)
           OR EXISTS(SELECT 1 FROM notification_deliveries d JOIN notification_channels c ON c.tenant_id=d.tenant_id AND c.id=d.channel_id WHERE d.tenant_id=capture_tenant AND c.channel_type='webhook' AND d.state IN ('pending','retrying')) THEN
            RAISE EXCEPTION 'disable webhook channels and drain webhook deliveries before removing notification runtime guards' USING ERRCODE='55000';
        END IF;
    END LOOP;
END;
$$;
-- +goose StatementEnd
DROP TRIGGER notification_webhook_attempt_guard ON notification_delivery_attempts;
DROP FUNCTION notification_guard_webhook_attempt();

-- Restore the 0224 guard: this migration owns only its narrower quarantine
-- capability, while identity publication remains protected by 0224.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION notification_guard_source_capture() RETURNS trigger LANGUAGE plpgsql AS $$
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

-- Return trigger capture to the 0224 shape; the old controller only knows the
-- bigint barrier, so the bridge above intentionally remains compatible with it.
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
