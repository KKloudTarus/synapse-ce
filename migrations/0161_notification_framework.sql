-- +goose Up
-- Tenant-managed notification channels, rules, immutable events, and durable
-- per-destination deliveries. Secrets are AES-GCM ciphertext; the master key is
-- process configuration and never enters PostgreSQL.
CREATE TABLE notification_channels (
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    id              TEXT NOT NULL,
    name            TEXT NOT NULL CHECK (btrim(name) <> ''),
    channel_type    TEXT NOT NULL CHECK (channel_type IN ('webhook','slack','email')),
    enabled         BOOLEAN NOT NULL DEFAULT true,
    destination     TEXT NOT NULL DEFAULT '',
    recipients      JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(recipients) = 'array'),
    revision        INT NOT NULL DEFAULT 1 CHECK (revision > 0),
    secret_version  INT NOT NULL DEFAULT 1 CHECK (secret_version > 0),
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    deleted_at      TIMESTAMPTZ,
    last_attempt_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id,id),
    UNIQUE (tenant_id,id,secret_version)
);

CREATE TABLE notification_channel_versions (
    tenant_id       TEXT NOT NULL,
    channel_id      TEXT NOT NULL,
    version         INT NOT NULL CHECK (version > 0),
    sealed_config   TEXT NOT NULL CHECK (btrim(sealed_config) <> ''),
    created_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,channel_id,version),
    FOREIGN KEY (tenant_id,channel_id) REFERENCES notification_channels(tenant_id,id) ON DELETE CASCADE
);

CREATE TABLE notification_rules (
    tenant_id        TEXT NOT NULL REFERENCES tenants(id),
    id               TEXT NOT NULL,
    name             TEXT NOT NULL CHECK (btrim(name) <> ''),
    enabled          BOOLEAN NOT NULL DEFAULT true,
    event_type       TEXT NOT NULL CHECK (event_type IN ('vulnerability_action.created','scan.completed','quality_gate.failed','sla.approaching_deadline','fleet.agent.offline','incident.created')),
    min_severity     TEXT NOT NULL DEFAULT '',
    action_types     JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(action_types) = 'array'),
    engagement_ids  JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(engagement_ids) = 'array'),
    lead_time_secs   BIGINT NOT NULL DEFAULT 0 CHECK (lead_time_secs >= 0 AND lead_time_secs <= 2592000),
    revision         INT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at       TIMESTAMPTZ NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,id)
);

CREATE TABLE notification_rule_channels (
    tenant_id       TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    channel_id      TEXT NOT NULL,
    PRIMARY KEY (tenant_id,rule_id,channel_id),
    FOREIGN KEY (tenant_id,rule_id) REFERENCES notification_rules(tenant_id,id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,channel_id) REFERENCES notification_channels(tenant_id,id)
);

CREATE TABLE notification_events (
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    id              TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    source_kind     TEXT NOT NULL CHECK (btrim(source_kind) <> ''),
    source_id       TEXT NOT NULL CHECK (btrim(source_id) <> ''),
    engagement_id   TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL DEFAULT '',
    schema_version  INT NOT NULL CHECK (schema_version = 1),
    occurred_at     TIMESTAMPTZ NOT NULL,
    data            JSONB NOT NULL CHECK (jsonb_typeof(data) = 'object'),
    matched_rules   JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(matched_rules) = 'array'),
    rule_revisions  JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,id),
    UNIQUE (tenant_id,source_kind,source_id)
);

CREATE TABLE notification_deliveries (
    tenant_id       TEXT NOT NULL,
    id              TEXT NOT NULL,
    event_id        TEXT NOT NULL,
    channel_id      TEXT NOT NULL,
    channel_version INT NOT NULL CHECK (channel_version > 0),
    channel_type    TEXT NOT NULL CHECK (channel_type IN ('webhook','slack','email')),
    recipient       TEXT NOT NULL DEFAULT '',
    matched_rules   JSONB NOT NULL CHECK (jsonb_typeof(matched_rules) = 'array'),
    state           TEXT NOT NULL CHECK (state IN ('pending','retrying','delivered','dead_letter','cancelled')),
    attempts        INT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error      TEXT NOT NULL DEFAULT '',
    next_attempt_at TIMESTAMPTZ,
    delivered_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,id),
    UNIQUE (tenant_id,event_id,channel_id,recipient),
    FOREIGN KEY (tenant_id,event_id) REFERENCES notification_events(tenant_id,id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,channel_id,channel_version) REFERENCES notification_channel_versions(tenant_id,channel_id,version)
);
CREATE INDEX idx_notification_deliveries_history ON notification_deliveries(tenant_id,created_at DESC,id DESC);
CREATE INDEX idx_notification_deliveries_state ON notification_deliveries(tenant_id,state,next_attempt_at);

CREATE TABLE notification_delivery_attempts (
    tenant_id       TEXT NOT NULL,
    id              TEXT NOT NULL,
    delivery_id     TEXT NOT NULL,
    attempt_number  INT NOT NULL CHECK (attempt_number > 0),
    started_at      TIMESTAMPTZ NOT NULL,
    finished_at     TIMESTAMPTZ,
    outcome         TEXT NOT NULL CHECK (outcome IN ('started','delivered','retrying','failed','cancelled')),
    response_code   INT NOT NULL DEFAULT 0,
    error_code      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id,id),
    UNIQUE (tenant_id,delivery_id,attempt_number),
    FOREIGN KEY (tenant_id,delivery_id) REFERENCES notification_deliveries(tenant_id,id) ON DELETE CASCADE
);

-- Persistent scheduler observations provide episode dedup for SLA reminders and
-- fleet offline transitions. The event unique key remains the final safety net.
CREATE TABLE notification_source_state (
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    source_kind     TEXT NOT NULL,
    source_id       TEXT NOT NULL,
    fingerprint     TEXT NOT NULL,
    active          BOOLEAN NOT NULL,
    observed_at     TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,source_kind,source_id)
);

CALL synapse_enable_tenant_rls('notification_channels');
CALL synapse_enable_tenant_rls('notification_channel_versions');
CALL synapse_enable_tenant_rls('notification_rules');
CALL synapse_enable_tenant_rls('notification_rule_channels');
CALL synapse_enable_tenant_rls('notification_events');
CALL synapse_enable_tenant_rls('notification_deliveries');
CALL synapse_enable_tenant_rls('notification_delivery_attempts');
CALL synapse_enable_tenant_rls('notification_source_state');

-- Delivery completion and its audit obligation commit together. A worker drains
-- these intents independently, so audit outages never resend acknowledged mail.
CREATE TABLE notification_audit_intents (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    id TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    action TEXT NOT NULL,
    error_code TEXT NOT NULL DEFAULT '',
    occurred_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id,id),
    FOREIGN KEY (tenant_id,delivery_id) REFERENCES notification_deliveries(tenant_id,id)
);
CALL synapse_enable_tenant_rls('notification_audit_intents');
CREATE INDEX idx_notification_audit_pending ON notification_audit_intents(tenant_id,occurred_at) WHERE recorded_at IS NULL;

-- The inbox is inserted by the authoritative persistence write, never by an
-- HTTP callback. Source deletion or a worker outage cannot lose a notification.
CREATE TABLE notification_source_records (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    source_kind TEXT NOT NULL,
    source_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    engagement_id TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',
    occurred_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL,
    processed_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id,source_kind,source_id)
);
CALL synapse_enable_tenant_rls('notification_source_records');
CREATE INDEX idx_notification_source_pending ON notification_source_records(tenant_id,occurred_at,source_id) WHERE processed_at IS NULL;

-- +goose StatementBegin
CREATE FUNCTION notification_capture_source() RETURNS trigger LANGUAGE plpgsql AS $$
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
        body:=jsonb_build_object('title',COALESCE(NEW.payload->>'Title','Security incident created'),'summary','Fleet correlation created an incident.','incident_id',NEW.incident_id,'asset_id',NEW.asset_id);
    END IF;
    IF tenant IS NULL OR NOT EXISTS(SELECT 1 FROM notification_source_state s WHERE s.tenant_id=tenant AND s.source_kind='framework' AND s.source_id='activation' AND s.observed_at<=happened) THEN RETURN NEW; END IF;
    INSERT INTO notification_source_records(tenant_id,source_kind,source_id,event_type,engagement_id,severity,occurred_at,data)
    VALUES(tenant,skind,sid,etype,eng,sev,happened,body) ON CONFLICT DO NOTHING;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER notification_capture_scan AFTER INSERT OR UPDATE OF status ON scan_jobs FOR EACH ROW EXECUTE FUNCTION notification_capture_source();
CREATE TRIGGER notification_capture_gate AFTER INSERT ON project_analyses FOR EACH ROW EXECUTE FUNCTION notification_capture_source();
CREATE TRIGGER notification_capture_incident AFTER INSERT ON incident_events FOR EACH ROW EXECUTE FUNCTION notification_capture_source();

-- Started attempts may be finalized once. Final results, event envelopes and
-- encrypted versions are immutable; unknown outcomes stay visible after a crash.
-- +goose StatementBegin
CREATE FUNCTION notification_guard_history() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'notification history is append-only'; END IF;
    IF TG_TABLE_NAME='notification_delivery_attempts' THEN
        IF OLD.outcome<>'started' OR
           (to_jsonb(NEW)-ARRAY['finished_at','outcome','response_code','error_code'])
           IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['finished_at','outcome','response_code','error_code'])
        THEN RAISE EXCEPTION 'notification attempt is immutable'; END IF;
    ELSIF TG_TABLE_NAME='notification_events' THEN
        IF (to_jsonb(NEW)-ARRAY['matched_rules','rule_revisions']) IS DISTINCT FROM
           (to_jsonb(OLD)-ARRAY['matched_rules','rule_revisions'])
        THEN RAISE EXCEPTION 'notification event envelope is immutable'; END IF;
    ELSE RAISE EXCEPTION 'notification version is immutable';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER notification_attempt_guard BEFORE UPDATE OR DELETE ON notification_delivery_attempts FOR EACH ROW EXECUTE FUNCTION notification_guard_history();
CREATE TRIGGER notification_event_guard BEFORE UPDATE OR DELETE ON notification_events FOR EACH ROW EXECUTE FUNCTION notification_guard_history();
CREATE TRIGGER notification_version_guard BEFORE UPDATE OR DELETE ON notification_channel_versions FOR EACH ROW EXECUTE FUNCTION notification_guard_history();

-- +goose Down
DROP FUNCTION IF EXISTS notification_guard_history() CASCADE;
DROP TRIGGER IF EXISTS notification_capture_scan ON scan_jobs;
DROP TRIGGER IF EXISTS notification_capture_gate ON project_analyses;
DROP TRIGGER IF EXISTS notification_capture_incident ON incident_events;
DROP FUNCTION IF EXISTS notification_capture_source();
DROP TABLE IF EXISTS notification_source_records;
DROP TABLE IF EXISTS notification_audit_intents;
DROP TABLE IF EXISTS notification_source_state;
DROP TABLE IF EXISTS notification_delivery_attempts;
DROP TABLE IF EXISTS notification_deliveries;
DROP TABLE IF EXISTS notification_events;
DROP TABLE IF EXISTS notification_rule_channels;
DROP TABLE IF EXISTS notification_rules;
DROP TABLE IF EXISTS notification_channel_versions;
DROP TABLE IF EXISTS notification_channels;
