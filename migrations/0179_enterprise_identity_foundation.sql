-- +goose Up
-- Enterprise human-identity foundation (#962, D3).
--
-- Organization is the existing tenant boundary. Global tables are deliberately few and have no
-- ordinary tenant-scoped query surface: persons, the derived person->organization index, the exact
-- credential locator, and the platform identity audit chain. All organization-owned state uses
-- tenant_id, composite ownership keys and FORCE RLS through synapse_enable_tenant_rls.

CREATE TABLE persons (
    id               TEXT PRIMARY KEY CHECK (btrim(id) <> ''),
    display_name     TEXT NOT NULL CHECK (length(btrim(display_name)) BETWEEN 1 AND 200),
    status           TEXT NOT NULL CHECK (status IN ('active','suspended')),
    credential_epoch BIGINT NOT NULL DEFAULT 1 CHECK (credential_epoch > 0),
    version          BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at       TIMESTAMPTZ NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL,
    CHECK (updated_at >= created_at)
);

CREATE TABLE memberships (
    tenant_id TEXT NOT NULL CHECK (btrim(tenant_id) <> '') REFERENCES tenants(id) ON DELETE RESTRICT,
    id        TEXT NOT NULL CHECK (btrim(id) <> ''),
    person_id TEXT NOT NULL REFERENCES persons(id) ON DELETE RESTRICT,
    role      TEXT NOT NULL CHECK (role IN ('admin','consultant','reviewer','readonly','member')),
    status    TEXT NOT NULL CHECK (status IN ('active','suspended','removed')),
    epoch     BIGINT NOT NULL DEFAULT 1 CHECK (epoch > 0),
    version   BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,id),
    UNIQUE (tenant_id,person_id),
    UNIQUE (tenant_id,id,person_id),
    CHECK (updated_at >= created_at)
);
CREATE INDEX memberships_person ON memberships(person_id,tenant_id);
CALL synapse_enable_tenant_rls('memberships');

-- This is a derived platform-only exact-person fan-out index. It intentionally exposes neither
-- display names nor emails and is maintained atomically with membership writes by the identity store.
CREATE TABLE person_organization_index (
    person_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    PRIMARY KEY (person_id,tenant_id),
    FOREIGN KEY (person_id) REFERENCES persons(id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,person_id) REFERENCES memberships(tenant_id,person_id) ON DELETE CASCADE
);

CREATE TABLE sso_connections (
    tenant_id        TEXT NOT NULL CHECK (btrim(tenant_id) <> '') REFERENCES tenants(id) ON DELETE RESTRICT,
    id               TEXT NOT NULL CHECK (btrim(id) <> ''),
    protocol         TEXT NOT NULL CHECK (protocol IN ('oidc')),
    trust_identifier TEXT NOT NULL CHECK (length(btrim(trust_identifier)) BETWEEN 1 AND 2048),
    enabled          BOOLEAN NOT NULL DEFAULT true,
    active_revision  BIGINT,
    connection_epoch BIGINT NOT NULL DEFAULT 1 CHECK (connection_epoch > 0),
    version          BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at       TIMESTAMPTZ NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,id),
    UNIQUE (tenant_id,protocol,trust_identifier),
    UNIQUE (tenant_id,id,protocol),
    CHECK (updated_at >= created_at)
);
CALL synapse_enable_tenant_rls('sso_connections');

CREATE TABLE sso_connection_revisions (
    tenant_id             TEXT NOT NULL,
    connection_id         TEXT NOT NULL,
    revision              BIGINT NOT NULL CHECK (revision > 0),
    protocol              TEXT NOT NULL CHECK (protocol IN ('oidc')),
    configuration         JSONB NOT NULL CHECK (jsonb_typeof(configuration)='object' AND octet_length(configuration::text) <= 32768),
    encrypted_secret_ref  TEXT NOT NULL DEFAULT '' CHECK (length(encrypted_secret_ref) <= 2048),
    test_status           TEXT NOT NULL DEFAULT 'untested' CHECK (test_status IN ('untested','passed','failed')),
    test_result           JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(test_result)='object' AND octet_length(test_result::text) <= 16384),
    created_by            TEXT NOT NULL CHECK (length(btrim(created_by)) BETWEEN 1 AND 256),
    created_at            TIMESTAMPTZ NOT NULL,
    tested_at             TIMESTAMPTZ,
    PRIMARY KEY (tenant_id,connection_id,revision),
    FOREIGN KEY (tenant_id,connection_id,protocol) REFERENCES sso_connections(tenant_id,id,protocol) ON DELETE RESTRICT,
    CHECK (tested_at IS NULL OR tested_at >= created_at),
    CHECK ((test_status='untested' AND tested_at IS NULL) OR (test_status<>'untested' AND tested_at IS NOT NULL))
);
CALL synapse_enable_tenant_rls('sso_connection_revisions');
ALTER TABLE sso_connections ADD CONSTRAINT sso_connections_active_revision_fk
    FOREIGN KEY (tenant_id,id,active_revision) REFERENCES sso_connection_revisions(tenant_id,connection_id,revision) ON DELETE RESTRICT;

-- Revisions are immutable evidence. Testing publishes a NEW immutable revision row with its result;
-- activation only moves sso_connections.active_revision after a passed revision exists.
-- +goose StatementBegin
CREATE FUNCTION identity_reject_revision_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'identity connection revisions are immutable' USING ERRCODE='55000';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER sso_connection_revisions_append_only
    BEFORE UPDATE OR DELETE ON sso_connection_revisions
    FOR EACH ROW EXECUTE FUNCTION identity_reject_revision_mutation();

CREATE TABLE authentication_identities (
    tenant_id          TEXT NOT NULL CHECK (btrim(tenant_id) <> ''),
    id                 TEXT NOT NULL CHECK (btrim(id) <> ''),
    membership_id      TEXT NOT NULL,
    person_id          TEXT NOT NULL,
    connection_id      TEXT NOT NULL,
    protocol_subject   TEXT NOT NULL CHECK (length(btrim(protocol_subject)) BETWEEN 1 AND 2048),
    creation_revision  BIGINT NOT NULL CHECK (creation_revision > 0),
    created_at         TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,id),
    UNIQUE (tenant_id,connection_id,protocol_subject),
    FOREIGN KEY (tenant_id,membership_id,person_id) REFERENCES memberships(tenant_id,id,person_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,connection_id) REFERENCES sso_connections(tenant_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,connection_id,creation_revision) REFERENCES sso_connection_revisions(tenant_id,connection_id,revision) ON DELETE RESTRICT
);
CREATE INDEX authentication_identities_membership ON authentication_identities(tenant_id,membership_id);
CALL synapse_enable_tenant_rls('authentication_identities');

-- The ONE new raw pre-authentication routing surface. It can answer only an exact digest and contains
-- no person, subject, email, role, connection or other listable identity data. The application port
-- deliberately exposes ResolveExactHash only.
CREATE TABLE credential_index (
    digest            TEXT PRIMARY KEY CHECK (digest ~ '^[a-f0-9]{64}$'),
    organization_id   TEXT NOT NULL CHECK (btrim(organization_id) <> '') REFERENCES tenants(id) ON DELETE RESTRICT,
    credential_kind   TEXT NOT NULL CHECK (credential_kind IN ('legacy_api_key','browser_session','oidc_state','invitation','break_glass','connection_launch')),
    credential_id     TEXT NOT NULL CHECK (btrim(credential_id) <> '')
);
CREATE UNIQUE INDEX credential_index_target ON credential_index(organization_id,credential_kind,credential_id);

-- Platform person mutations need an audit record that cannot disappear with any one tenant. This
-- chain is separate from the existing tenant audit chain; D6 writes mutation+audit atomically.
CREATE TABLE platform_identity_audit (
    sequence          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id                TEXT NOT NULL UNIQUE CHECK (btrim(id) <> ''),
    actor              TEXT NOT NULL CHECK (length(btrim(actor)) BETWEEN 1 AND 256),
    action             TEXT NOT NULL CHECK (length(btrim(action)) BETWEEN 1 AND 128),
    target_person_id   TEXT NOT NULL REFERENCES persons(id) ON DELETE RESTRICT,
    previous_hash      TEXT NOT NULL CHECK (previous_hash = '' OR previous_hash ~ '^[a-f0-9]{64}$'),
    hash               TEXT NOT NULL CHECK (hash ~ '^[a-f0-9]{64}$'),
    metadata           JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata)='object' AND octet_length(metadata::text) <= 16384),
    created_at         TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX platform_identity_audit_hash ON platform_identity_audit(hash);

-- Immutable fan-out payload/idempotency with a monotonic completion marker. Tenant workers consume
-- only their own rows through RLS; the platform mutation inserts all obligations atomically.
CREATE TABLE identity_fanout_obligations (
    tenant_id       TEXT NOT NULL CHECK (btrim(tenant_id) <> '') REFERENCES tenants(id) ON DELETE RESTRICT,
    id              TEXT NOT NULL CHECK (btrim(id) <> ''),
    person_id       TEXT NOT NULL,
    audit_id        TEXT NOT NULL,
    idempotency_key TEXT NOT NULL CHECK (length(btrim(idempotency_key)) BETWEEN 1 AND 256),
    payload         JSONB NOT NULL CHECK (jsonb_typeof(payload)='object' AND octet_length(payload::text) <= 32768),
    state           TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','completed')),
    created_at      TIMESTAMPTZ NOT NULL,
    completed_at    TIMESTAMPTZ,
    PRIMARY KEY (tenant_id,id),
    UNIQUE (tenant_id,idempotency_key),
    FOREIGN KEY (person_id,tenant_id) REFERENCES person_organization_index(person_id,tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (audit_id) REFERENCES platform_identity_audit(id) ON DELETE RESTRICT,
    CHECK ((state='pending' AND completed_at IS NULL) OR (state='completed' AND completed_at IS NOT NULL AND completed_at >= created_at))
);
CREATE INDEX identity_fanout_pending ON identity_fanout_obligations(tenant_id,created_at,id) WHERE state='pending';
CALL synapse_enable_tenant_rls('identity_fanout_obligations');

-- Fan-out payload and identity are immutable; the only legal update is pending -> completed with a
-- completion timestamp. This prevents a tenant worker from rewriting the platform obligation.
-- +goose StatementBegin
CREATE FUNCTION identity_guard_fanout_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.tenant_id<>NEW.tenant_id OR OLD.id<>NEW.id OR OLD.person_id<>NEW.person_id OR
       OLD.audit_id<>NEW.audit_id OR OLD.idempotency_key<>NEW.idempotency_key OR OLD.payload<>NEW.payload OR
       OLD.created_at<>NEW.created_at OR OLD.state<>'pending' OR NEW.state<>'completed' OR NEW.completed_at IS NULL THEN
        RAISE EXCEPTION 'identity fan-out obligation is immutable except pending-to-completed' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER identity_fanout_update_guard
    BEFORE UPDATE ON identity_fanout_obligations
    FOR EACH ROW EXECUTE FUNCTION identity_guard_fanout_update();
CREATE TRIGGER identity_fanout_no_delete
    BEFORE DELETE ON identity_fanout_obligations
    FOR EACH ROW EXECUTE FUNCTION identity_reject_revision_mutation();

-- +goose Down
DROP TRIGGER IF EXISTS identity_fanout_no_delete ON identity_fanout_obligations;
DROP TRIGGER IF EXISTS identity_fanout_update_guard ON identity_fanout_obligations;
DROP FUNCTION IF EXISTS identity_guard_fanout_update();
DROP TABLE IF EXISTS identity_fanout_obligations;
DROP TABLE IF EXISTS platform_identity_audit;
DROP INDEX IF EXISTS credential_index_target;
DROP TABLE IF EXISTS credential_index;
DROP TABLE IF EXISTS authentication_identities;
ALTER TABLE sso_connections DROP CONSTRAINT IF EXISTS sso_connections_active_revision_fk;
DROP TRIGGER IF EXISTS sso_connection_revisions_append_only ON sso_connection_revisions;
DROP FUNCTION IF EXISTS identity_reject_revision_mutation();
DROP TABLE IF EXISTS sso_connection_revisions;
DROP TABLE IF EXISTS sso_connections;
DROP TABLE IF EXISTS person_organization_index;
DROP TABLE IF EXISTS memberships;
DROP TABLE IF EXISTS persons;
