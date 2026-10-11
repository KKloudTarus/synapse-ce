-- +goose Up
-- Identities removed by retention. Historical backfill must not assign a
-- new sequence to an event that was already captured and then pruned.
CREATE TABLE siem_incident_pruned (
    tenant_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    event_seq INT NOT NULL CHECK (event_seq >= 1),
    pruned_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, incident_id, event_seq)
);
CALL synapse_enable_tenant_rls('siem_incident_pruned');

-- Replace the 0192 trigger body so capture, prune, and backfill share one
-- retention lock.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION siem_capture_incident_event() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    assigned BIGINT;
BEGIN
    IF current_setting('app.siem_capture_enabled', true) = 'off' THEN
        RETURN NEW;
    END IF;
    -- Tenants without an active SIEM sink must not pay the per-tenant
    -- counter lock or accumulate unbounded capture identities.
    IF NOT EXISTS (
        SELECT 1 FROM public.siem_sinks
         WHERE tenant_id = NEW.tenant_id AND enabled
    ) THEN
        RETURN NEW;
    END IF;
    -- Same lock as prune and historical backfill, so a capture row cannot
    -- be inserted into a range that retention is deleting.
    PERFORM pg_catalog.pg_advisory_xact_lock(1484, pg_catalog.hashtext(NEW.tenant_id));
    INSERT INTO public.siem_incident_counters AS counters (tenant_id)
    VALUES (NEW.tenant_id)
    ON CONFLICT (tenant_id) DO NOTHING;
    SELECT live_next INTO assigned
      FROM public.siem_incident_counters
     WHERE tenant_id = NEW.tenant_id
     FOR UPDATE;
    UPDATE public.siem_incident_counters
       SET live_next = live_next + 1
     WHERE tenant_id = NEW.tenant_id;
    INSERT INTO public.siem_incident_capture (
        tenant_id, phase, stream_seq, incident_id, event_seq, occurred_at
    ) VALUES (
        NEW.tenant_id, 'live', assigned, NEW.incident_id, NEW.seq, NEW.occurred_at
    );
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS siem_incident_pruned;
