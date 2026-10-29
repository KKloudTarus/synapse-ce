-- +goose Up
ALTER TABLE notification_source_records
    ADD COLUMN pager_episode BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN pager_revision BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN pager_terminal BOOLEAN NOT NULL DEFAULT false,
    ADD CONSTRAINT notification_source_pager_lifecycle_check CHECK (
        (pager_episode=0 AND pager_revision=0 AND NOT pager_terminal) OR
        (pager_episode>0 AND pager_revision>0 AND subject_kind IN ('finding','incident') AND subject_id<>''));
ALTER TABLE notification_events
    ADD COLUMN pager_episode BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN pager_revision BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN pager_terminal BOOLEAN NOT NULL DEFAULT false,
    ADD CONSTRAINT notification_event_pager_lifecycle_check CHECK (
        (pager_episode=0 AND pager_revision=0 AND NOT pager_terminal) OR
        (pager_episode>0 AND pager_revision>0 AND subject_kind IN ('finding','incident') AND subject_id<>''));

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
    pager_revision BIGINT := 0;
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
        tenant:=NEW.tenant_id; skind:='incident'; sid:=NEW.incident_id; etype:='incident.created'; happened:=NEW.occurred_at; pager_revision:=NEW.seq;
        eng:=COALESCE(NEW.payload->>'EngagementID',''); sev:=COALESCE(NEW.payload->>'Severity','');
        body:=CASE WHEN capture_mode='identity' THEN '{}'::jsonb ELSE jsonb_build_object('title',left(COALESCE(NEW.payload->>'Title','Security incident created'),500),'summary','Fleet correlation created an incident.','incident_id',NEW.incident_id,'asset_id',NEW.asset_id) END;
    END IF;
    IF tenant IS NULL OR NOT EXISTS(SELECT 1 FROM notification_source_state s WHERE s.tenant_id=tenant AND s.source_kind='framework' AND s.source_id='activation' AND s.observed_at<=happened) THEN RETURN NEW; END IF;
    INSERT INTO notification_source_records(tenant_id,source_kind,source_id,event_type,engagement_id,severity,occurred_at,data,capture_version,subject_kind,subject_id,pager_episode,pager_revision,pager_terminal)
    VALUES(tenant,skind,sid,etype,eng,sev,happened,body,format_version,
        CASE WHEN skind='incident' THEN 'incident' ELSE '' END,
        CASE WHEN skind='incident' THEN sid ELSE '' END,
        CASE WHEN skind='incident' THEN 1 ELSE 0 END,
        pager_revision,false) ON CONFLICT DO NOTHING;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- Classified source facts cannot be changed or consumed by a worker that drops them.
-- +goose StatementBegin
CREATE FUNCTION notification_guard_pager_source() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.pager_episode, NEW.pager_revision, NEW.pager_terminal) IS DISTINCT FROM
       (OLD.pager_episode, OLD.pager_revision, OLD.pager_terminal) THEN
        RAISE EXCEPTION 'notification pager lifecycle is immutable' USING ERRCODE='55000';
    END IF;
    IF OLD.pager_episode>0 AND NEW.processed_at IS DISTINCT FROM OLD.processed_at AND
       current_setting('synapse.notification_pager_capability',true) IS DISTINCT FROM 'pager-lifecycle-v1' THEN
        RAISE EXCEPTION 'notification source requires pager-lifecycle-v1 worker' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER notification_pager_source_guard BEFORE UPDATE ON notification_source_records
    FOR EACH ROW EXECUTE FUNCTION notification_guard_pager_source();

-- +goose StatementBegin
CREATE FUNCTION notification_guard_pager_publication() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE source_row notification_source_records%ROWTYPE;
BEGIN
    SELECT * INTO source_row FROM notification_source_records
      WHERE tenant_id=NEW.tenant_id AND source_kind=NEW.source_kind AND source_id=NEW.source_id;
    IF FOUND AND source_row.pager_episode>0 THEN
        IF current_setting('synapse.notification_pager_capability',true) IS DISTINCT FROM 'pager-lifecycle-v1' OR
           (NEW.pager_episode,NEW.pager_revision,NEW.pager_terminal,NEW.subject_kind,NEW.subject_id) IS DISTINCT FROM
           (source_row.pager_episode,source_row.pager_revision,source_row.pager_terminal,source_row.subject_kind,source_row.subject_id) THEN
            RAISE EXCEPTION 'notification publication requires matching pager lifecycle' USING ERRCODE='55000';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER notification_pager_publication_guard BEFORE INSERT ON notification_events
    FOR EACH ROW EXECUTE FUNCTION notification_guard_pager_publication();

-- Existing workers cannot start pager sends for classified events without admission.
-- +goose StatementBegin
CREATE FUNCTION notification_guard_pager_attempt() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS(SELECT 1 FROM notification_deliveries d JOIN notification_events e
        ON e.tenant_id=d.tenant_id AND e.id=d.event_id
        WHERE d.tenant_id=NEW.tenant_id AND d.id=NEW.delivery_id
          AND d.channel_type IN ('pagerduty','jsm') AND e.pager_episode>0)
       AND current_setting('synapse.notification_pager_capability',true) IS DISTINCT FROM 'pager-lifecycle-v1' THEN
        RAISE EXCEPTION 'pager attempt requires pager-lifecycle-v1 admission' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER notification_pager_attempt_guard BEFORE INSERT ON notification_delivery_attempts
    FOR EACH ROW EXECUTE FUNCTION notification_guard_pager_attempt();

-- +goose Down
-- Lifecycle obligations and receipts require forward reconciliation; dropping
-- their classification could cause an old worker to close another episode.
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'pager lifecycle transport requires forward recovery' USING ERRCODE='55000';
END $$;
-- +goose StatementEnd
