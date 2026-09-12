-- +goose Up
-- Additive ownership foundations. No automatic routing or historical reassignment
-- is enabled by this migration. Preserve the legacy users.tenant_id representation.
ALTER TABLE users ADD COLUMN ownership_tenant_id TEXT GENERATED ALWAYS AS (COALESCE(NULLIF(tenant_id, ''), 'default')) STORED;
ALTER TABLE users ADD CONSTRAINT users_ownership_tenant_id_unique UNIQUE (ownership_tenant_id,id);

CREATE TABLE ownership_teams (
    tenant_id TEXT NOT NULL REFERENCES tenants(id), id TEXT NOT NULL,
    slug TEXT NOT NULL CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,78}[a-z0-9])?$'),
    name TEXT NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    archived BOOLEAN NOT NULL DEFAULT false, revision INT NOT NULL CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,slug), CHECK (updated_at >= created_at)
);
CREATE TABLE ownership_memberships (
    tenant_id TEXT NOT NULL, team_id TEXT NOT NULL, user_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,team_id,user_id),
    FOREIGN KEY (tenant_id,team_id) REFERENCES ownership_teams(tenant_id,id),
    FOREIGN KEY (tenant_id,user_id) REFERENCES users(ownership_tenant_id,id)
);
CREATE INDEX ownership_memberships_user ON ownership_memberships(tenant_id,user_id,team_id);

CREATE TABLE ownership_mappings (
    tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, repository TEXT NOT NULL CHECK (length(repository) BETWEEN 1 AND 2048),
    owner_token TEXT NOT NULL CHECK (length(owner_token) BETWEEN 1 AND 320), team_id TEXT NOT NULL,
    suggested_user_id TEXT, revision INT NOT NULL CHECK (revision>0),
    PRIMARY KEY (tenant_id,engagement_id,repository,owner_token),
    FOREIGN KEY (tenant_id,engagement_id) REFERENCES engagements(tenant_id,id),
    FOREIGN KEY (tenant_id,team_id) REFERENCES ownership_teams(tenant_id,id),
    FOREIGN KEY (tenant_id,suggested_user_id) REFERENCES users(ownership_tenant_id,id)
);
CREATE TABLE ownership_asset_mappings (
    tenant_id TEXT NOT NULL, asset_id TEXT NOT NULL, team_id TEXT NOT NULL, revision INT NOT NULL CHECK (revision>0),
    PRIMARY KEY (tenant_id,asset_id),
    FOREIGN KEY (tenant_id,asset_id) REFERENCES fleet_business_services(tenant_id,id),
    FOREIGN KEY (tenant_id,team_id) REFERENCES ownership_teams(tenant_id,id)
);
CREATE TABLE ownership_snapshots (
    tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, id TEXT NOT NULL,
    repository TEXT NOT NULL CHECK (length(repository) BETWEEN 1 AND 2048),
    source_revision TEXT NOT NULL CHECK (source_revision ~ '^(git:([a-f0-9]{40}|[a-f0-9]{64})|sha256:[a-f0-9]{64})$'),
    file_path TEXT NOT NULL CHECK (file_path IN ('.github/CODEOWNERS','CODEOWNERS','docs/CODEOWNERS')),
    content TEXT NOT NULL CHECK (octet_length(content)<=3000000),
    content_hash TEXT NOT NULL CHECK (content_hash ~ '^[a-f0-9]{64}$'), parser_version TEXT NOT NULL,
    trust TEXT NOT NULL CHECK (trust IN ('untrusted','base_ref','admin_import')),
    approved_by TEXT NOT NULL DEFAULT '', accept_diagnostics BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,engagement_id,id),
    FOREIGN KEY (tenant_id,engagement_id) REFERENCES engagements(tenant_id,id),
    CHECK (trust='untrusted' OR btrim(approved_by)<>'')
);

CREATE TABLE ownership_policies (
    tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, id TEXT NOT NULL,
    repository TEXT NOT NULL DEFAULT '', revision INT NOT NULL DEFAULT 1 CHECK (revision>0), active_version INT,
    PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,engagement_id,id), UNIQUE (tenant_id,engagement_id,repository),
    FOREIGN KEY (tenant_id,engagement_id) REFERENCES engagements(tenant_id,id)
);
CREATE TABLE ownership_policy_versions (
    tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, policy_id TEXT NOT NULL,
    version INT NOT NULL CHECK (version>0), snapshot_id TEXT,
    content_hash TEXT NOT NULL CHECK (content_hash ~ '^[a-f0-9]{64}$'),
    payload JSONB NOT NULL CHECK (jsonb_typeof(payload)='object' AND octet_length(payload::text)<=8388608),
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,policy_id,version),
    FOREIGN KEY (tenant_id,engagement_id,policy_id) REFERENCES ownership_policies(tenant_id,engagement_id,id),
    FOREIGN KEY (tenant_id,engagement_id,snapshot_id) REFERENCES ownership_snapshots(tenant_id,engagement_id,id)
);
ALTER TABLE ownership_policies ADD CONSTRAINT ownership_active_version_fk
    FOREIGN KEY (tenant_id,id,active_version) REFERENCES ownership_policy_versions(tenant_id,policy_id,version);
CREATE TABLE ownership_policy_team_refs (
    tenant_id TEXT NOT NULL, policy_id TEXT NOT NULL, version INT NOT NULL, team_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id,policy_id,version,team_id),
    FOREIGN KEY (tenant_id,policy_id,version) REFERENCES ownership_policy_versions(tenant_id,policy_id,version),
    FOREIGN KEY (tenant_id,team_id) REFERENCES ownership_teams(tenant_id,id)
);
CREATE TABLE ownership_policy_project_refs (
    tenant_id TEXT NOT NULL, policy_id TEXT NOT NULL, version INT NOT NULL, project_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id,policy_id,version,project_id),
    FOREIGN KEY (tenant_id,policy_id,version) REFERENCES ownership_policy_versions(tenant_id,policy_id,version),
    FOREIGN KEY (tenant_id,project_id) REFERENCES projects(tenant_id,id)
);
CREATE TABLE ownership_policy_asset_refs (
    tenant_id TEXT NOT NULL, policy_id TEXT NOT NULL, version INT NOT NULL, asset_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id,policy_id,version,asset_id),
    FOREIGN KEY (tenant_id,policy_id,version) REFERENCES ownership_policy_versions(tenant_id,policy_id,version),
    FOREIGN KEY (tenant_id,asset_id) REFERENCES fleet_business_services(tenant_id,id)
);

CREATE TABLE ownership_assignments (
    tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, finding_id TEXT NOT NULL,
    team_id TEXT, assignee_id TEXT, legacy_assignee TEXT NOT NULL DEFAULT '',
    mode TEXT NOT NULL CHECK (mode IN ('auto','manual')), revision INT NOT NULL CHECK (revision>0),
    manual_generation BIGINT NOT NULL DEFAULT 0 CHECK (manual_generation>=0),
    resolution TEXT NOT NULL CHECK (resolution IN ('resolved','unresolved','ambiguous','excluded','unsupported')),
    reason TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,engagement_id,finding_id),
    FOREIGN KEY (tenant_id,engagement_id,finding_id) REFERENCES findings(tenant_id,engagement_id,id),
    FOREIGN KEY (tenant_id,team_id) REFERENCES ownership_teams(tenant_id,id),
    FOREIGN KEY (tenant_id,assignee_id) REFERENCES users(ownership_tenant_id,id),
    CHECK (assignee_id IS NULL OR assignee_id=legacy_assignee)
);
CREATE INDEX ownership_assignments_inbox ON ownership_assignments(tenant_id,team_id,updated_at DESC,finding_id DESC);
CREATE INDEX ownership_assignments_assignee ON ownership_assignments(tenant_id,assignee_id,updated_at DESC,finding_id DESC);
CREATE INDEX ownership_assignments_resolution ON ownership_assignments(tenant_id,resolution,updated_at DESC,finding_id DESC);
CREATE TABLE ownership_decisions (
    tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, finding_id TEXT NOT NULL, id TEXT NOT NULL,
    transition_key TEXT NOT NULL CHECK (length(transition_key) BETWEEN 1 AND 256),
    request_hash TEXT NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
    policy_id TEXT, policy_version INT,
    payload JSONB NOT NULL CHECK (jsonb_typeof(payload)='object' AND octet_length(payload::text)<=4194304),
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,transition_key), UNIQUE (tenant_id,engagement_id,finding_id,id),
    FOREIGN KEY (tenant_id,engagement_id,finding_id) REFERENCES findings(tenant_id,engagement_id,id),
    FOREIGN KEY (tenant_id,policy_id,policy_version) REFERENCES ownership_policy_versions(tenant_id,policy_id,version),
    CHECK ((policy_id IS NULL) = (policy_version IS NULL))
);
CREATE INDEX ownership_decisions_history ON ownership_decisions(tenant_id,engagement_id,finding_id,created_at DESC,id DESC);
CREATE TABLE ownership_intents (
    tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, finding_id TEXT NOT NULL, id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('route','notification')), source_key TEXT NOT NULL,
    decision_id TEXT, payload JSONB NOT NULL CHECK (jsonb_typeof(payload)='object' AND octet_length(payload::text)<=16384),
    state TEXT NOT NULL CHECK (state IN ('pending','processed','suppressed')), created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,kind,source_key),
    FOREIGN KEY (tenant_id,engagement_id,finding_id) REFERENCES findings(tenant_id,engagement_id,id),
    FOREIGN KEY (tenant_id,engagement_id,finding_id,decision_id) REFERENCES ownership_decisions(tenant_id,engagement_id,finding_id,id)
);
CREATE INDEX ownership_intents_pending ON ownership_intents(tenant_id,kind,created_at,id) WHERE state='pending';

CREATE TABLE ownership_runs (
    tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, id TEXT NOT NULL, policy_id TEXT NOT NULL, policy_version INT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('preview','reroute')), state TEXT NOT NULL CHECK (state IN ('queued','running','completed','cancelled','failed')),
    revision INT NOT NULL CHECK (revision>0), policy_revision INT NOT NULL CHECK (policy_revision>0),
    policy_hash TEXT NOT NULL CHECK (policy_hash ~ '^[a-f0-9]{64}$'),
    cutoff TIMESTAMPTZ NOT NULL, total INT NOT NULL CHECK (total>=0), processed INT NOT NULL DEFAULT 0 CHECK (processed>=0 AND processed<=total),
    filter JSONB NOT NULL CHECK (jsonb_typeof(filter)='object' AND octet_length(filter::text)<=16384),
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,id,engagement_id),
    FOREIGN KEY (tenant_id,engagement_id,policy_id) REFERENCES ownership_policies(tenant_id,engagement_id,id),
    FOREIGN KEY (tenant_id,policy_id,policy_version) REFERENCES ownership_policy_versions(tenant_id,policy_id,version)
);
CREATE TABLE ownership_run_items (
    tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, engagement_id TEXT NOT NULL, finding_id TEXT NOT NULL,
    finding_version INT NOT NULL CHECK (finding_version>0), ownership_revision INT NOT NULL CHECK (ownership_revision>=0),
    manual_generation BIGINT NOT NULL CHECK (manual_generation>=0),
    result JSONB NOT NULL CHECK (jsonb_typeof(result)='object' AND octet_length(result::text)<=4194304),
    PRIMARY KEY (tenant_id,run_id,finding_id),
    FOREIGN KEY (tenant_id,run_id,engagement_id) REFERENCES ownership_runs(tenant_id,id,engagement_id),
    FOREIGN KEY (tenant_id,engagement_id,finding_id) REFERENCES findings(tenant_id,engagement_id,id)
);

-- Source/policy/decision evidence cannot be rewritten after it has been used.
-- +goose StatementBegin
CREATE FUNCTION ownership_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'ownership evidence is append-only' USING ERRCODE='55000'; END;
$$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$ DECLARE tbl text; BEGIN
    FOREACH tbl IN ARRAY ARRAY['ownership_snapshots','ownership_policy_versions','ownership_policy_team_refs','ownership_policy_project_refs','ownership_policy_asset_refs','ownership_decisions','ownership_run_items'] LOOP
        EXECUTE format('CREATE TRIGGER ownership_append_only BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION ownership_reject_mutation()',tbl);
    END LOOP;
    FOREACH tbl IN ARRAY ARRAY['ownership_teams','ownership_memberships','ownership_mappings','ownership_asset_mappings','ownership_snapshots','ownership_policies','ownership_policy_versions','ownership_policy_team_refs','ownership_policy_project_refs','ownership_policy_asset_refs','ownership_assignments','ownership_decisions','ownership_intents','ownership_runs','ownership_run_items'] LOOP
        CALL synapse_enable_tenant_rls(tbl);
    END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE ownership_run_items;
DROP TABLE ownership_runs;
DROP TABLE ownership_intents;
DROP TABLE ownership_decisions;
DROP TABLE ownership_assignments;
DROP TABLE ownership_policy_asset_refs;
DROP TABLE ownership_policy_project_refs;
DROP TABLE ownership_policy_team_refs;
ALTER TABLE ownership_policies DROP CONSTRAINT ownership_active_version_fk;
DROP TABLE ownership_policy_versions;
DROP TABLE ownership_policies;
DROP TABLE ownership_snapshots;
DROP TABLE ownership_asset_mappings;
DROP TABLE ownership_mappings;
DROP TABLE ownership_memberships;
DROP TABLE ownership_teams;
DROP FUNCTION ownership_reject_mutation();
ALTER TABLE users DROP CONSTRAINT users_ownership_tenant_id_unique;
ALTER TABLE users DROP COLUMN ownership_tenant_id;
