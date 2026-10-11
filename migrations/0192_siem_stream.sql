-- +goose Up
-- Tenant SIEM streams. Capture rows are an identity index for incident
-- events, written in the same transaction as the append. They are not a
-- second copy of the business payload, and they are not a notification
-- delivery log.
CREATE TABLE siem_sinks (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    origin TEXT NOT NULL,
    target TEXT NOT NULL,
    data_class TEXT NOT NULL,
    ack_mode TEXT NOT NULL,
    indexer_ack BOOLEAN NOT NULL DEFAULT FALSE,
    allow_hosts TEXT[] NOT NULL DEFAULT '{}',
    paused BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    generation BIGINT NOT NULL,
    secret_version BIGINT NOT NULL,
    version BIGINT NOT NULL,
    channel TEXT NOT NULL,
    blocked_reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, name),
    CHECK (generation >= 1 AND secret_version >= 1 AND version >= 1),
    CHECK (char_length(blocked_reason) <= 240)
);
CALL synapse_enable_tenant_rls('siem_sinks');

CREATE TABLE siem_sink_secrets (
    tenant_id TEXT NOT NULL,
    sink_id TEXT NOT NULL,
    version BIGINT NOT NULL,
    ciphertext TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, sink_id, version),
    FOREIGN KEY (tenant_id, sink_id) REFERENCES siem_sinks (tenant_id, id)
);
CALL synapse_enable_tenant_rls('siem_sink_secrets');

CREATE TABLE siem_checkpoints (
    tenant_id TEXT NOT NULL,
    sink_id TEXT NOT NULL,
    source TEXT NOT NULL,
    generation BIGINT NOT NULL,
    position JSONB NOT NULL,
    chain_head TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, sink_id, source),
    FOREIGN KEY (tenant_id, sink_id) REFERENCES siem_sinks (tenant_id, id)
);
CALL synapse_enable_tenant_rls('siem_checkpoints');

CREATE TABLE siem_leases (
    tenant_id TEXT NOT NULL,
    sink_id TEXT NOT NULL,
    source TEXT NOT NULL,
    owner TEXT NOT NULL,
    token BIGINT NOT NULL,
    generation BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, sink_id, source),
    FOREIGN KEY (tenant_id, sink_id) REFERENCES siem_sinks (tenant_id, id)
);
CALL synapse_enable_tenant_rls('siem_leases');

CREATE TABLE siem_batches (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    sink_id TEXT NOT NULL,
    source TEXT NOT NULL,
    generation BIGINT NOT NULL,
    lease_token BIGINT NOT NULL,
    state TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    mapping_version TEXT NOT NULL,
    chain_head TEXT NOT NULL DEFAULT '',
    diagnostic TEXT NOT NULL DEFAULT '',
    attempt INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ,
    indexer_ack_id BIGINT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, sink_id) REFERENCES siem_sinks (tenant_id, id),
    CHECK (char_length(diagnostic) <= 240)
);
CREATE UNIQUE INDEX siem_batches_one_open
    ON siem_batches (tenant_id, sink_id, source)
    WHERE state IN ('prepared', 'sending', 'partial', 'awaiting_ack', 'blocked');
CALL synapse_enable_tenant_rls('siem_batches');

CREATE TABLE siem_batch_items (
    tenant_id TEXT NOT NULL,
    batch_id TEXT NOT NULL,
    ordinal INT NOT NULL,
    record_id TEXT NOT NULL,
    position JSONB NOT NULL,
    disposition TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    mapping TEXT NOT NULL DEFAULT '',
    data_class TEXT NOT NULL,
    engagement_id TEXT NOT NULL DEFAULT '',
    safe_reason TEXT NOT NULL DEFAULT '',
    sealed_payload TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, batch_id, ordinal),
    FOREIGN KEY (tenant_id, batch_id) REFERENCES siem_batches (tenant_id, id),
    CHECK (char_length(safe_reason) <= 240)
);
CALL synapse_enable_tenant_rls('siem_batch_items');

-- One counter row per tenant. Live appends and historical backfill both
-- lock this row before inserting capture identities, which is the same
-- order as the audit advisory lock being taken only after incident writes.
CREATE TABLE siem_incident_counters (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(id),
    live_next BIGINT NOT NULL DEFAULT 1,
    hist_next BIGINT NOT NULL DEFAULT 1,
    CHECK (live_next >= 1 AND hist_next >= 1)
);
CALL synapse_enable_tenant_rls('siem_incident_counters');

CREATE TABLE siem_incident_capture (
    tenant_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('live', 'historical')),
    stream_seq BIGINT NOT NULL CHECK (stream_seq >= 1),
    incident_id TEXT NOT NULL,
    event_seq INT NOT NULL CHECK (event_seq >= 1),
    occurred_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, phase, stream_seq),
    UNIQUE (tenant_id, incident_id, event_seq),
    FOREIGN KEY (tenant_id, incident_id, event_seq)
        REFERENCES incident_events (tenant_id, incident_id, seq)
);
CREATE INDEX siem_incident_capture_keyset
    ON siem_incident_capture (tenant_id, phase, stream_seq);
CALL synapse_enable_tenant_rls('siem_incident_capture');

-- +goose StatementBegin
CREATE FUNCTION siem_capture_incident_event() RETURNS trigger
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

CREATE TRIGGER siem_incident_events_capture
    AFTER INSERT ON incident_events
    FOR EACH ROW EXECUTE FUNCTION siem_capture_incident_event();

-- +goose Down
DROP TRIGGER IF EXISTS siem_incident_events_capture ON incident_events;
DROP FUNCTION IF EXISTS siem_capture_incident_event();
DROP TABLE IF EXISTS siem_incident_capture;
DROP TABLE IF EXISTS siem_incident_counters;
DROP TABLE IF EXISTS siem_batch_items;
DROP TABLE IF EXISTS siem_batches;
DROP TABLE IF EXISTS siem_leases;
DROP TABLE IF EXISTS siem_checkpoints;
DROP TABLE IF EXISTS siem_sink_secrets;
DROP TABLE IF EXISTS siem_sinks;
