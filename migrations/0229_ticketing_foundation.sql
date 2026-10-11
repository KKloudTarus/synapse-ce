-- +goose Up
-- Ticketing is a bounded context, not an integration operation or notification channel.
CREATE TABLE ticket_mappings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    integration_id TEXT NOT NULL,
    project_id TEXT,
    engagement_id TEXT,
    project_key TEXT NOT NULL CHECK (length(btrim(project_key)) BETWEEN 1 AND 255),
    issue_type TEXT NOT NULL CHECK (length(btrim(issue_type)) BETWEEN 1 AND 255),
    component TEXT NOT NULL DEFAULT '' CHECK (octet_length(component) <= 255),
    -- jsonb::text adds a space after each array comma. The domain admits a
    -- compact JSON representation through 8192 bytes (at most 32 labels),
    -- so retain that contract after PostgreSQL normalizes it.
    labels JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(labels)='array' AND octet_length(labels::text)<=8223),
    -- Object normalization adds a space after each comma and colon (at most
    -- 32 entries), so allow the corresponding 63-byte representation delta.
    priority_map JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(priority_map)='object' AND octet_length(priority_map::text)<=8255),
    security_level TEXT NOT NULL DEFAULT '' CHECK (octet_length(security_level)<=255),
    version INT NOT NULL CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id,id), UNIQUE (tenant_id,integration_id,id),
    FOREIGN KEY (tenant_id,integration_id) REFERENCES integrations(tenant_id,id),
    FOREIGN KEY (tenant_id,project_id) REFERENCES projects(tenant_id,id),
    FOREIGN KEY (tenant_id,engagement_id) REFERENCES engagements(tenant_id,id),
    CHECK ((project_id IS NOT NULL) <> (engagement_id IS NOT NULL)),
    CHECK (updated_at>=created_at)
);
CREATE UNIQUE INDEX ticket_mappings_project_unique ON ticket_mappings (tenant_id,integration_id,project_id) WHERE project_id IS NOT NULL;
CREATE UNIQUE INDEX ticket_mappings_engagement_unique ON ticket_mappings (tenant_id,integration_id,engagement_id) WHERE engagement_id IS NOT NULL;
CALL synapse_enable_tenant_rls('ticket_mappings');

-- Manual links deliberately do not need an integration. A display URL is never fetched.
CREATE TABLE ticket_links (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    finding_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    integration_id TEXT,
    external_id TEXT NOT NULL DEFAULT '' CHECK (octet_length(external_id)<=512),
    CHECK ((integration_id IS NULL AND external_id='') OR (integration_id IS NOT NULL AND external_id<>'')),
    external_url TEXT NOT NULL CHECK (octet_length(external_url)<=2048 AND external_url ~ '^https://[^/?#@]+(/[^?#]*)?$'),
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id,id), UNIQUE (tenant_id,finding_id,external_url),
    FOREIGN KEY (tenant_id,engagement_id,finding_id) REFERENCES findings(tenant_id,engagement_id,id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,integration_id) REFERENCES integrations(tenant_id,id)
);
CREATE INDEX ticket_links_finding_idx ON ticket_links (tenant_id,finding_id,created_at DESC,id DESC);
CALL synapse_enable_tenant_rls('ticket_links');

-- A request key is a logical command identity; the marker identifies its remote side effect.
-- An expired in_flight lease is ambiguous, NOT permission to repeat an external POST.
CREATE TABLE ticket_intents (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    integration_id TEXT NOT NULL,
    mapping_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('create','update','transition','comment')),
    request_key TEXT NOT NULL CHECK (length(btrim(request_key)) BETWEEN 1 AND 128),
    payload_digest TEXT NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
    correlation_marker TEXT NOT NULL CHECK (length(correlation_marker) BETWEEN 16 AND 256 AND correlation_marker = 'synapse-intent-' || id),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','in_flight','done','failed','uncertain')),
    version INT NOT NULL DEFAULT 1 CHECK (version > 0),
    attempts INT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    lease_until TIMESTAMPTZ,
    error_code TEXT NOT NULL DEFAULT '' CHECK (error_code='' OR error_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id,id), UNIQUE (tenant_id,integration_id,request_key),
    UNIQUE (tenant_id,integration_id,correlation_marker),
    FOREIGN KEY (tenant_id,integration_id,mapping_id) REFERENCES ticket_mappings(tenant_id,integration_id,id),
    FOREIGN KEY (tenant_id,engagement_id,finding_id) REFERENCES findings(tenant_id,engagement_id,id),
    CHECK ((state='in_flight') = (lease_until IS NOT NULL)),
    CHECK (lease_until IS NULL OR lease_until>updated_at),
    CHECK (updated_at>=created_at)
);
CREATE INDEX ticket_intents_due_idx ON ticket_intents (tenant_id,state,lease_until,updated_at,id) WHERE state IN ('pending','in_flight','uncertain');
CREATE INDEX ticket_intents_finding_idx ON ticket_intents (tenant_id,finding_id,created_at DESC);
CALL synapse_enable_tenant_rls('ticket_intents');

-- +goose Down
-- The rollback check must see every tenant even though these tables use FORCE
-- RLS. Keep the migration owner visible only while the tables are locked; if
-- the guard fails, Goose rolls the policy changes back with this transaction.
-- +goose StatementBegin
LOCK TABLE ticket_mappings IN ACCESS EXCLUSIVE MODE;
LOCK TABLE ticket_links IN ACCESS EXCLUSIVE MODE;
LOCK TABLE ticket_intents IN ACCESS EXCLUSIVE MODE;
ALTER TABLE ticket_mappings NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_links NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_intents NO FORCE ROW LEVEL SECURITY;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM ticket_intents LIMIT 1)
        OR EXISTS (SELECT 1 FROM ticket_links LIMIT 1)
        OR EXISTS (SELECT 1 FROM ticket_mappings LIMIT 1) THEN
        RAISE EXCEPTION 'cannot roll back ticketing foundation while durable ticket data exists'
            USING ERRCODE = '55000';
    END IF;
END $$;
-- +goose StatementEnd

DROP TABLE ticket_intents;
DROP TABLE ticket_links;
DROP TABLE ticket_mappings;
