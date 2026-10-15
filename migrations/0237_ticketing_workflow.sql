-- +goose Up
ALTER TABLE ticket_mappings
    ADD COLUMN summary_template TEXT NOT NULL DEFAULT '',
    ADD COLUMN description_template TEXT NOT NULL DEFAULT '',
    ADD COLUMN field_values JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN transition_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN data_class TEXT NOT NULL DEFAULT 'summary',
    ADD COLUMN locale TEXT NOT NULL DEFAULT 'en',
    ADD COLUMN waiver_reason TEXT NOT NULL DEFAULT '',
    ADD CONSTRAINT ticket_mappings_templates_size CHECK (octet_length(summary_template)<=4096 AND octet_length(description_template)<=16384 AND octet_length(transition_name)<=255 AND jsonb_typeof(field_values)='object' AND octet_length(field_values::text)<=16384 AND data_class IN ('signal','summary','detail') AND locale IN ('en','vi') AND octet_length(waiver_reason)<=1024);
ALTER TABLE ticket_intents
    ADD COLUMN payload_snapshot JSONB,
    ADD COLUMN mapping_version INT,
    ADD COLUMN connection_revision INT,
    ADD COLUMN credential_revision INT,
    ADD COLUMN security_level TEXT NOT NULL DEFAULT '',
    ADD CONSTRAINT ticket_intents_snapshot CHECK ((payload_snapshot IS NULL AND mapping_version IS NULL AND connection_revision IS NULL AND credential_revision IS NULL) OR (payload_snapshot IS NOT NULL AND mapping_version>0 AND connection_revision>0 AND credential_revision>=0 AND octet_length(payload_snapshot::text)<=65536));
CREATE INDEX ticket_intents_pending_idx ON ticket_intents (tenant_id,updated_at,id) WHERE state='pending';
CREATE TABLE ticket_dispatch_breakers (
    tenant_id TEXT NOT NULL REFERENCES tenants(id), integration_id TEXT NOT NULL,
    project_key TEXT NOT NULL CHECK(length(btrim(project_key)) BETWEEN 1 AND 255),
    issue_type TEXT NOT NULL CHECK(length(btrim(issue_type)) BETWEEN 1 AND 255),
    active_intent_id TEXT, lease_until TIMESTAMPTZ, gate_until TIMESTAMPTZ,
    breaker_code TEXT NOT NULL DEFAULT '' CHECK (breaker_code='' OR breaker_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    version INT NOT NULL DEFAULT 1 CHECK(version>0), updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(tenant_id,integration_id,project_key,issue_type),
    FOREIGN KEY(tenant_id,integration_id) REFERENCES integrations(tenant_id,id),
    FOREIGN KEY(tenant_id,active_intent_id) REFERENCES ticket_intents(tenant_id,id),
    CHECK((active_intent_id IS NULL)=(lease_until IS NULL))
);
CALL synapse_enable_tenant_rls('ticket_dispatch_breakers');

-- +goose Down
-- Preserve provider commands and policy decisions across every tenant. A failed
-- guard rolls back the temporary owner visibility with the Goose transaction.
-- +goose StatementBegin
LOCK TABLE ticket_mappings, ticket_intents, ticket_dispatch_breakers IN ACCESS EXCLUSIVE MODE;
ALTER TABLE ticket_mappings NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_intents NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_dispatch_breakers NO FORCE ROW LEVEL SECURITY;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM ticket_intents WHERE payload_snapshot IS NOT NULL LIMIT 1)
        OR EXISTS (SELECT 1 FROM ticket_dispatch_breakers LIMIT 1)
        OR EXISTS (SELECT 1 FROM ticket_mappings WHERE summary_template<>'' OR description_template<>''
            OR field_values<>'{}'::jsonb OR transition_name<>'' OR data_class<>'summary'
            OR locale<>'en' OR waiver_reason<>'' LIMIT 1) THEN
        RAISE EXCEPTION 'cannot roll back ticket workflow while durable commands or policy decisions exist'
            USING ERRCODE = '55000';
    END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE ticket_mappings FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_intents FORCE ROW LEVEL SECURITY;
DROP INDEX ticket_intents_pending_idx;
DROP TABLE ticket_dispatch_breakers;
ALTER TABLE ticket_intents DROP CONSTRAINT ticket_intents_snapshot, DROP COLUMN security_level, DROP COLUMN credential_revision, DROP COLUMN connection_revision, DROP COLUMN mapping_version, DROP COLUMN payload_snapshot;
ALTER TABLE ticket_mappings DROP CONSTRAINT ticket_mappings_templates_size, DROP COLUMN waiver_reason, DROP COLUMN locale, DROP COLUMN data_class, DROP COLUMN transition_name, DROP COLUMN field_values, DROP COLUMN description_template, DROP COLUMN summary_template;
