-- +goose Up
-- Documentation publishing is a bounded context beside ticketing, not an integration
-- operation or a notification channel. A link is the CURRENT state of one remote page; every
-- publish or republish is its own intent, because a done intent is terminal.

-- A display URL is never fetched. A link exists only because an intent completed, so its
-- page identity and version are always known.
CREATE TABLE document_links (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    integration_id TEXT NOT NULL,
    source_kind TEXT NOT NULL CHECK (source_kind IN ('engagement_report','assessment_closure_report','project_quality_summary')),
    -- Opaque to the schema: the engagement report is rendered on demand, the closure report is
    -- stored per cycle, manifest and renderer version, and the publisher names each of them.
    source_ref TEXT NOT NULL CHECK (octet_length(source_ref) BETWEEN 1 AND 512 AND btrim(source_ref) <> ''),
    engagement_id TEXT,
    project_id TEXT,
    container TEXT NOT NULL CHECK (octet_length(container) BETWEEN 1 AND 255 AND btrim(container) <> ''),
    remote_page_id TEXT NOT NULL CHECK (octet_length(remote_page_id) BETWEEN 1 AND 512 AND btrim(remote_page_id) <> ''),
    remote_version INT NOT NULL CHECK (remote_version > 0),
    remote_url TEXT NOT NULL CHECK (octet_length(remote_url)<=2048 AND remote_url ~ '^https://[^/?#@]+(/[^?#]*)?$'),
    content_hash TEXT NOT NULL CHECK (content_hash ~ '^[a-f0-9]{64}$'),
    revision INT NOT NULL CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id,id),
    -- Source references are local to their parent scope; another container is another page.
    -- Treat the unused scope column's NULL as equal so duplicate targets still conflict.
    CONSTRAINT document_links_target_unique UNIQUE NULLS NOT DISTINCT
        (tenant_id,integration_id,source_kind,source_ref,engagement_id,project_id,container),
    FOREIGN KEY (tenant_id,integration_id) REFERENCES integrations(tenant_id,id),
    CONSTRAINT document_links_engagement_fk FOREIGN KEY (tenant_id,engagement_id)
        REFERENCES engagements(tenant_id,id) ON DELETE RESTRICT,
    CONSTRAINT document_links_project_fk FOREIGN KEY (tenant_id,project_id)
        REFERENCES projects(tenant_id,id) ON DELETE RESTRICT,
    CONSTRAINT document_links_scope_check CHECK ((engagement_id IS NOT NULL) <> (project_id IS NOT NULL)),
    -- Each source kind lives in exactly one scope.
    CONSTRAINT document_links_kind_scope_check CHECK (
        (source_kind = 'engagement_report' AND engagement_id IS NOT NULL) OR
        (source_kind IN ('assessment_closure_report','project_quality_summary') AND project_id IS NOT NULL)),
    CHECK (updated_at >= created_at)
);
CREATE INDEX document_links_engagement_idx ON document_links (tenant_id,engagement_id,created_at DESC,id DESC) WHERE engagement_id IS NOT NULL;
CREATE INDEX document_links_project_idx ON document_links (tenant_id,project_id,created_at DESC,id DESC) WHERE project_id IS NOT NULL;
CALL synapse_enable_tenant_rls('document_links');

-- A request key is a logical command identity; the marker identifies its remote side effect.
-- An expired in_flight lease is ambiguous, NOT permission to repeat an external write.
-- link_id has no foreign key on purpose: an intent is the evidence of a remote write and must
-- outlive the link it wrote to.
CREATE TABLE document_intents (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    integration_id TEXT NOT NULL,
    source_kind TEXT NOT NULL CHECK (source_kind IN ('engagement_report','assessment_closure_report','project_quality_summary')),
    source_ref TEXT NOT NULL CHECK (octet_length(source_ref) BETWEEN 1 AND 512 AND btrim(source_ref) <> ''),
    engagement_id TEXT,
    project_id TEXT,
    container TEXT NOT NULL CHECK (octet_length(container) BETWEEN 1 AND 255 AND btrim(container) <> ''),
    link_id TEXT,
    action TEXT NOT NULL CHECK (action IN ('create','update')),
    request_key TEXT NOT NULL CHECK (octet_length(request_key) BETWEEN 1 AND 128 AND btrim(request_key) <> ''),
    payload_digest TEXT NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
    content_hash TEXT NOT NULL CHECK (content_hash ~ '^[a-f0-9]{64}$'),
    correlation_marker TEXT NOT NULL CHECK (length(correlation_marker) BETWEEN 16 AND 256 AND correlation_marker = 'synapse-intent-' || id),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','in_flight','done','failed','uncertain')),
    version INT NOT NULL DEFAULT 1 CHECK (version > 0),
    attempts INT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    lease_until TIMESTAMPTZ,
    remote_id TEXT NOT NULL DEFAULT '' CHECK (remote_id='' OR (btrim(remote_id)<>'' AND octet_length(remote_id)<=512)),
    remote_url TEXT NOT NULL DEFAULT '' CHECK (remote_url='' OR (octet_length(remote_url)<=2048 AND remote_url ~ '^https://[^/?#@]+(/[^?#]*)?$')),
    remote_version INT NOT NULL DEFAULT 0 CHECK (remote_version >= 0),
    error_code TEXT NOT NULL DEFAULT '' CHECK (error_code='' OR error_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id,id),
    UNIQUE (tenant_id,integration_id,request_key),
    UNIQUE (tenant_id,integration_id,correlation_marker),
    FOREIGN KEY (tenant_id,integration_id) REFERENCES integrations(tenant_id,id),
    CONSTRAINT document_intents_engagement_fk FOREIGN KEY (tenant_id,engagement_id)
        REFERENCES engagements(tenant_id,id) ON DELETE RESTRICT,
    CONSTRAINT document_intents_project_fk FOREIGN KEY (tenant_id,project_id)
        REFERENCES projects(tenant_id,id) ON DELETE RESTRICT,
    CONSTRAINT document_intents_scope_check CHECK ((engagement_id IS NOT NULL) <> (project_id IS NOT NULL)),
    CONSTRAINT document_intents_kind_scope_check CHECK (
        (source_kind = 'engagement_report' AND engagement_id IS NOT NULL) OR
        (source_kind IN ('assessment_closure_report','project_quality_summary') AND project_id IS NOT NULL)),
    CHECK ((action = 'create') = (link_id IS NULL)),
    CHECK ((state='in_flight') = (lease_until IS NOT NULL)),
    CHECK ((state='done' AND remote_id<>'' AND remote_url<>'' AND remote_version>0) OR
           (state<>'done' AND remote_id='' AND remote_url='' AND remote_version=0)),
    CHECK (state<>'failed' OR error_code<>''),
    CHECK (state IN ('failed','uncertain') OR error_code=''),
    CHECK (state<>'uncertain' OR error_code IN ('','multiple_matches')),
    CHECK (lease_until IS NULL OR lease_until>updated_at),
    CHECK (updated_at>=created_at)
);
CREATE INDEX document_intents_due_idx ON document_intents (tenant_id,state,lease_until,updated_at,id) WHERE state IN ('pending','in_flight','uncertain');
CREATE INDEX document_intents_target_idx ON document_intents (tenant_id,integration_id,source_kind,source_ref,container,created_at DESC);
CALL synapse_enable_tenant_rls('document_intents');

-- +goose Down
-- The rollback check must see every tenant even though these tables use FORCE
-- RLS. Keep the migration owner visible only while the tables are locked; if
-- the guard fails, Goose rolls the policy changes back with this transaction.
-- +goose StatementBegin
LOCK TABLE document_links IN ACCESS EXCLUSIVE MODE;
LOCK TABLE document_intents IN ACCESS EXCLUSIVE MODE;
ALTER TABLE document_links NO FORCE ROW LEVEL SECURITY;
ALTER TABLE document_intents NO FORCE ROW LEVEL SECURITY;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM document_intents LIMIT 1)
        OR EXISTS (SELECT 1 FROM document_links LIMIT 1) THEN
        RAISE EXCEPTION 'cannot roll back documentation publishing while durable document data exists'
            USING ERRCODE = '55000';
    END IF;
END $$;
-- +goose StatementEnd

DROP TABLE document_intents;
DROP TABLE document_links;
