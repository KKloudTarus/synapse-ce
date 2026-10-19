-- +goose Up
-- Durable report schedules are intentionally separate from notification jobs:
-- one occurrence freezes one report artifact and fans out one SMTP transaction
-- per verified recipient, while document publication retains its own intent.
CREATE TABLE document_schedules (
    tenant_id TEXT NOT NULL REFERENCES tenants(id), id TEXT NOT NULL,
    source_kind TEXT NOT NULL CHECK (source_kind IN ('engagement_report','assessment_closure_report','project_quality_summary')),
    source_ref TEXT NOT NULL CHECK (octet_length(source_ref) BETWEEN 1 AND 512 AND btrim(source_ref)<>''),
    engagement_id TEXT, project_id TEXT,
    destination TEXT NOT NULL CHECK (destination IN ('confluence','email')),
    integration_id TEXT, email_channel_id TEXT,
    owner_user_id TEXT NOT NULL, owner_membership_id TEXT, owner_person_id TEXT,
    timezone TEXT NOT NULL CHECK (octet_length(timezone) BETWEEN 1 AND 128),
    frequency TEXT NOT NULL CHECK (frequency IN ('weekly','monthly')),
    weekday INT NOT NULL DEFAULT 0 CHECK (weekday BETWEEN 0 AND 6), day_of_month INT NOT NULL DEFAULT 0 CHECK (day_of_month BETWEEN 0 AND 31),
    hour INT NOT NULL CHECK (hour BETWEEN 0 AND 23), minute INT NOT NULL CHECK (minute BETWEEN 0 AND 59),
    enabled BOOLEAN NOT NULL DEFAULT true, version INT NOT NULL CHECK (version>0), next_due_at TIMESTAMPTZ NOT NULL,
    checked_at TIMESTAMPTZ, check_version INT NOT NULL DEFAULT 0 CHECK (check_version>=0),
    created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,id),
    FOREIGN KEY(tenant_id,integration_id) REFERENCES integrations(tenant_id,id),
    FOREIGN KEY(tenant_id,email_channel_id) REFERENCES notification_channels(tenant_id,id),
    FOREIGN KEY(tenant_id,engagement_id) REFERENCES engagements(tenant_id,id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_id,project_id) REFERENCES projects(tenant_id,id) ON DELETE RESTRICT,
    CHECK ((engagement_id IS NOT NULL) <> (project_id IS NOT NULL)),
    CHECK ((destination='confluence') = (integration_id IS NOT NULL) AND (destination='email') = (email_channel_id IS NOT NULL)),
    CHECK ((owner_membership_id IS NULL) = (owner_person_id IS NULL)),
    CHECK ((frequency='weekly' AND day_of_month=0) OR (frequency='monthly' AND weekday=0 AND day_of_month BETWEEN 1 AND 31)),
    CHECK ((source_kind='engagement_report' AND engagement_id IS NOT NULL) OR (source_kind IN ('assessment_closure_report','project_quality_summary') AND project_id IS NOT NULL)),
    CHECK(updated_at>=created_at)
);
CREATE INDEX document_schedules_due_idx ON document_schedules(tenant_id,checked_at,check_version,id) WHERE enabled;
CALL synapse_enable_tenant_rls('document_schedules');

CREATE TABLE document_schedule_occurrences (
    tenant_id TEXT NOT NULL REFERENCES tenants(id), id TEXT NOT NULL, schedule_id TEXT NOT NULL, due_at TIMESTAMPTZ NOT NULL,
    schedule_version INT NOT NULL CHECK(schedule_version>0), state TEXT NOT NULL CHECK(state IN ('pending','in_flight','done','failed','uncertain')),
    version INT NOT NULL CHECK(version>0), lease_until TIMESTAMPTZ, artifact JSONB NOT NULL DEFAULT 'null'::jsonb,
    artifact_digest TEXT NOT NULL DEFAULT '' CHECK(artifact_digest='' OR artifact_digest~'^[a-f0-9]{64}$'),
    document_intent_id TEXT NOT NULL DEFAULT '', remote_page_id TEXT NOT NULL DEFAULT '', remote_version INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,schedule_id,due_at),
    FOREIGN KEY(tenant_id,schedule_id) REFERENCES document_schedules(tenant_id,id) ON DELETE RESTRICT,
    CHECK((state='in_flight')=(lease_until IS NOT NULL)), CHECK(octet_length(artifact::text)<=33554432), CHECK(updated_at>=created_at)
);
CREATE INDEX document_schedule_occurrences_work_idx ON document_schedule_occurrences(tenant_id,state,lease_until,updated_at,id);
CREATE INDEX document_schedule_occurrences_history_idx ON document_schedule_occurrences(tenant_id,schedule_id,due_at DESC,id DESC);
CALL synapse_enable_tenant_rls('document_schedule_occurrences');

CREATE TABLE document_schedule_deliveries (
    tenant_id TEXT NOT NULL REFERENCES tenants(id), id TEXT NOT NULL, occurrence_id TEXT NOT NULL,
    recipient TEXT NOT NULL CHECK(octet_length(recipient) BETWEEN 3 AND 320), recipient_hash TEXT NOT NULL CHECK(recipient_hash~'^[a-f0-9]{64}$'),
    message_id TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','in_flight','done','failed','uncertain','rejected')),
    version INT NOT NULL CHECK(version>0), lease_until TIMESTAMPTZ, error_code TEXT NOT NULL DEFAULT '' CHECK(error_code='' OR error_code~'^[a-z][a-z0-9_]{0,63}$'),
    created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,occurrence_id,recipient_hash), UNIQUE(tenant_id,message_id),
    FOREIGN KEY(tenant_id,occurrence_id) REFERENCES document_schedule_occurrences(tenant_id,id) ON DELETE RESTRICT,
    CHECK((state='in_flight')=(lease_until IS NOT NULL)), CHECK(updated_at>=created_at)
);
CREATE INDEX document_schedule_deliveries_work_idx ON document_schedule_deliveries(tenant_id,occurrence_id,state,lease_until,id);
CALL synapse_enable_tenant_rls('document_schedule_deliveries');

-- +goose Down
LOCK TABLE document_schedule_deliveries,document_schedule_occurrences,document_schedules IN ACCESS EXCLUSIVE MODE;
ALTER TABLE document_schedule_deliveries NO FORCE ROW LEVEL SECURITY;
ALTER TABLE document_schedule_occurrences NO FORCE ROW LEVEL SECURITY;
ALTER TABLE document_schedules NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM document_schedule_deliveries) OR EXISTS(SELECT 1 FROM document_schedule_occurrences) OR EXISTS(SELECT 1 FROM document_schedules) THEN RAISE EXCEPTION 'cannot roll back report schedules with durable data'; END IF;
END $$;
-- +goose StatementEnd
DROP TABLE document_schedule_deliveries;
DROP TABLE document_schedule_occurrences;
DROP TABLE document_schedules;
