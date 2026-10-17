-- +goose Up
-- An explicit bounded selection extends the legacy primary event without
-- subscribing a rule to future catalog entries.
ALTER TABLE notification_rules
    ADD COLUMN event_types TEXT[] NOT NULL DEFAULT '{}'
        CONSTRAINT notification_rules_event_types_check CHECK (
            cardinality(event_types)<=8
            AND (cardinality(event_types)=0 OR
                 (array_ndims(event_types)=1 AND array_lower(event_types,1)=1
                  AND event_types[1]=event_type))
            AND array_position(event_types,NULL) IS NULL
            AND array_to_string(event_types,',') ~ '^([a-z_]+(\.[a-z_]+)+(,[a-z_]+(\.[a-z_]+)+)*)?$'
        );
ALTER TABLE notification_rules DROP CONSTRAINT notification_rules_check;
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_check CHECK (
    NOT all_teams OR (
        event_type IN ('finding.ownership_changed','sla.breached',
            'risk_acceptance.created','risk_acceptance.expiring','risk_acceptance.expired')
        AND event_types <@ ARRAY['finding.ownership_changed','sla.breached',
            'risk_acceptance.created','risk_acceptance.expiring','risk_acceptance.expired']::text[]
    ));

-- Older publishers only query the primary event type. Refuse their affected
-- inserts before they can mark a source processed while dropping subscriptions.
-- This is a rollout capability fence, not an authorization credential.
-- +goose StatementBegin
CREATE FUNCTION notification_guard_rule_selection() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('synapse.notification_rule_selector',true) IS DISTINCT FROM 'explicit-v1'
       AND EXISTS(SELECT 1 FROM notification_rules r
           WHERE r.tenant_id=NEW.tenant_id AND r.enabled
             AND cardinality(r.event_types)>1
             AND r.event_types @> ARRAY[NEW.event_type]::text[]) THEN
        RAISE EXCEPTION 'notification publisher requires explicit event selection support' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER notification_events_rule_selection
    BEFORE INSERT ON notification_events FOR EACH ROW
    EXECUTE FUNCTION notification_guard_rule_selection();

-- +goose Down
-- A downgrade cannot silently narrow a retained multi-event subscription.
LOCK TABLE tenants, notification_rules IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$
DECLARE tenant_row RECORD;
BEGIN
    FOR tenant_row IN SELECT id FROM tenants WHERE id<>'' LOOP
        PERFORM set_config('app.current_tenant',tenant_row.id,true);
        IF EXISTS(SELECT 1 FROM notification_rules
            WHERE tenant_id=tenant_row.id AND cardinality(event_types)>1) THEN
            RAISE EXCEPTION 'retire explicit multi-event notification rules before rollback' USING ERRCODE='55000';
        END IF;
    END LOOP;
END;
$$;
-- +goose StatementEnd
DROP TRIGGER notification_events_rule_selection ON notification_events;
DROP FUNCTION notification_guard_rule_selection();
ALTER TABLE notification_rules DROP CONSTRAINT notification_rules_check;
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_check CHECK (
    NOT all_teams OR event_type IN ('finding.ownership_changed','sla.breached',
        'risk_acceptance.created','risk_acceptance.expiring','risk_acceptance.expired'));
ALTER TABLE notification_rules DROP COLUMN event_types;
