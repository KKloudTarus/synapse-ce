-- +goose Up
-- Source snapshots retain event-time facts independently of mutable source rows.
ALTER TABLE notification_source_records DROP CONSTRAINT notification_source_records_capture_version_check;
ALTER TABLE notification_source_records ADD CONSTRAINT notification_source_records_capture_version_check CHECK (capture_version IN (1,2,3));
ALTER TABLE notification_rules ADD COLUMN event_filters JSONB NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(event_filters)='object' AND octet_length(event_filters::text)<=16384);
ALTER TABLE notification_rules DROP CONSTRAINT notification_rules_check;
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_check CHECK (
    NOT all_teams OR event_type IN ('finding.ownership_changed','sla.breached',
        'risk_acceptance.created','risk_acceptance.expiring','risk_acceptance.expired'));
ALTER TABLE cspm_runs ADD COLUMN providers JSONB NOT NULL DEFAULT '[]'::jsonb
    CHECK (jsonb_typeof(providers)='array' AND jsonb_array_length(providers)<=3);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION notification_guard_source_capture() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.capture_version IS DISTINCT FROM OLD.capture_version THEN
        RAISE EXCEPTION 'notification capture format is immutable' USING ERRCODE='55000';
    END IF;
    IF OLD.capture_version=3 THEN
        IF (to_jsonb(NEW)-ARRAY['processed_at','failed_reason']) IS DISTINCT FROM
           (to_jsonb(OLD)-ARRAY['processed_at','failed_reason']) OR
           NEW.failed_reason IS DISTINCT FROM OLD.failed_reason THEN
            RAISE EXCEPTION 'notification snapshot facts are immutable' USING ERRCODE='55000';
        END IF;
        IF NEW.processed_at IS DISTINCT FROM OLD.processed_at AND
           (OLD.processed_at IS NOT NULL OR NEW.processed_at IS NULL OR
            current_setting('synapse.notification_source_capability',true) IS DISTINCT FROM 'snapshot-v1') THEN
            RAISE EXCEPTION 'notification snapshot requires snapshot-v1 projector' USING ERRCODE='55000';
        END IF;
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

-- +goose StatementBegin
CREATE FUNCTION notification_guard_snapshot_publication() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS(SELECT 1 FROM notification_source_records s
        WHERE s.tenant_id=NEW.tenant_id AND s.source_kind=NEW.source_kind AND s.source_id=NEW.source_id
          AND s.capture_version=3) AND
       current_setting('synapse.notification_source_capability',true) IS DISTINCT FROM 'snapshot-v1' THEN
        RAISE EXCEPTION 'notification publication requires snapshot-v1 projector' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER notification_snapshot_publication_guard BEFORE INSERT ON notification_events
    FOR EACH ROW EXECUTE FUNCTION notification_guard_snapshot_publication();
CREATE INDEX idx_notification_snapshot_pending ON notification_source_records(tenant_id,occurred_at,source_kind,source_id)
    WHERE capture_version=3 AND processed_at IS NULL;

-- +goose Down
LOCK TABLE cspm_runs, notification_source_records, notification_rules IN ACCESS EXCLUSIVE MODE;
-- Keep captured intent until a capable worker has consumed it. Rollback retains
-- completed source facts in their legacy body format after removing the guard.
-- +goose StatementBegin
DO $$
DECLARE tenant_row RECORD;
BEGIN
    FOR tenant_row IN SELECT id FROM tenants WHERE id<>'' LOOP
        PERFORM set_config('app.current_tenant',tenant_row.id,true);
        IF EXISTS(SELECT 1 FROM notification_source_records WHERE tenant_id=tenant_row.id AND capture_version=3 AND processed_at IS NULL) OR
           EXISTS(SELECT 1 FROM notification_rules WHERE tenant_id=tenant_row.id AND
               (event_filters<>'{}'::jsonb OR (all_teams AND event_type<>'finding.ownership_changed'))) THEN
            RAISE EXCEPTION 'drain snapshot captures and clear event filters and lifecycle team rules before rollback' USING ERRCODE='55000';
        END IF;
    END LOOP;
END;
$$;
-- +goose StatementEnd
DROP TRIGGER notification_snapshot_publication_guard ON notification_events;
DROP FUNCTION notification_guard_snapshot_publication();
DROP INDEX idx_notification_snapshot_pending;
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
DROP TRIGGER notification_source_capture_guard ON notification_source_records;
-- +goose StatementBegin
DO $$
DECLARE tenant_row RECORD;
BEGIN
    FOR tenant_row IN SELECT id FROM tenants WHERE id<>'' LOOP
        PERFORM set_config('app.current_tenant',tenant_row.id,true);
        UPDATE notification_source_records SET capture_version=1 WHERE tenant_id=tenant_row.id AND capture_version=3 AND processed_at IS NOT NULL;
    END LOOP;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER notification_source_capture_guard BEFORE UPDATE ON notification_source_records FOR EACH ROW EXECUTE FUNCTION notification_guard_source_capture();
ALTER TABLE notification_source_records DROP CONSTRAINT notification_source_records_capture_version_check;
ALTER TABLE notification_source_records ADD CONSTRAINT notification_source_records_capture_version_check CHECK (capture_version IN (1,2));
ALTER TABLE notification_rules DROP COLUMN event_filters;
ALTER TABLE notification_rules DROP CONSTRAINT notification_rules_check;
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_check CHECK (NOT all_teams OR event_type='finding.ownership_changed');
ALTER TABLE cspm_runs DROP COLUMN providers;
