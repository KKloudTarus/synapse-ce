-- +goose Up
-- Additive identity foundation. The legacy users table stays the writer of record: nothing here
-- changes how bearer or fixed-tenant OIDC authentication works today.
--
-- Access model:
--   * Global platform tables (persons, person audit, digest and membership routing indexes) are
--     owner-only under FORCE RLS and carry no runtime grant. The runtime role reaches them only
--     through the narrow SECURITY DEFINER functions below (exact digest routing, the
--     exact-authenticated-person membership projection and epoch read, and the create-only
--     person command). The general person command stays owner-only.
--   * Every tenant-owned table rejects an empty tenant, uses (tenant_id, id) ownership keys and
--     the standard synapse_enable_tenant_rls FORCE policy.
--   * Routing indexes are written only by triggers on the tenant tables they derive from, so no
--     independent projection writer exists.
--
-- Stable SQLSTATEs raised by the guards below:
--   SYN01 the write is not representable in the legacy users model before cutover declaration
--   SYN02 an identity lifecycle rule rejected the transition

-- +goose StatementBegin
CREATE PROCEDURE synapse_enable_owner_only_rls(tbl text)
    LANGUAGE plpgsql
    AS $owner_only$
BEGIN
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tbl);
    EXECUTE format(
        'CREATE POLICY %I ON %I FOR ALL TO PUBLIC '
        'USING (current_user = pg_get_userbyid((SELECT relowner FROM pg_class WHERE oid = %L::regclass))) '
        'WITH CHECK (current_user = pg_get_userbyid((SELECT relowner FROM pg_class WHERE oid = %L::regclass)))',
        tbl || '_owner_only', tbl, 'public.' || tbl, 'public.' || tbl);
    EXECUTE format('REVOKE ALL ON TABLE %I FROM PUBLIC', tbl);
END;
$owner_only$;
-- +goose StatementEnd

-- Global persons. The epoch revokes every session of the person across tenants when it moves.
CREATE TABLE identity_persons (
    id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128 AND btrim(id) = id AND id <> ''),
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'suspended')),
    epoch BIGINT NOT NULL DEFAULT 1 CHECK (epoch > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (updated_at >= created_at)
);
CALL synapse_enable_owner_only_rls('identity_persons');

-- Platform-only person audit: append-only and hash-chained.
CREATE TABLE identity_person_audit (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    person_id TEXT NOT NULL REFERENCES identity_persons(id),
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 256),
    action TEXT NOT NULL CHECK (action IN ('person.created', 'person.sessions_revoked', 'person.suspended', 'person.reactivated')),
    reason TEXT NOT NULL DEFAULT '' CHECK (length(reason) <= 512),
    person_epoch BIGINT NOT NULL CHECK (person_epoch > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    previous_hash TEXT NOT NULL DEFAULT '',
    hash TEXT NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$')
);
CREATE UNIQUE INDEX identity_person_audit_chain_link ON identity_person_audit(previous_hash) WHERE previous_hash <> '';
CALL synapse_enable_owner_only_rls('identity_person_audit');

-- +goose StatementBegin
CREATE FUNCTION synapse_identity_append_only()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $append_only$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = 'SYN02';
END;
$append_only$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_append_only() FROM PUBLIC;
CREATE TRIGGER identity_person_audit_append_only BEFORE UPDATE OR DELETE ON identity_person_audit
    FOR EACH ROW EXECUTE FUNCTION synapse_identity_append_only();

-- Per-tenant cutover phase and authentication policy. Missing row means phase 'legacy'.
CREATE TABLE identity_policies (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) CHECK (tenant_id <> ''),
    id TEXT NOT NULL CHECK (id <> ''),
    cutover_phase TEXT NOT NULL DEFAULT 'legacy' CHECK (cutover_phase IN ('legacy', 'shadow', 'declared')),
    sso_requirement TEXT NOT NULL DEFAULT 'optional' CHECK (sso_requirement IN ('optional', 'required')),
    recent_auth_max_age_seconds INT NOT NULL DEFAULT 900 CHECK (recent_auth_max_age_seconds BETWEEN 60 AND 86400),
    legacy_bearer_grace_until TIMESTAMPTZ,
    break_glass_enabled BOOLEAN NOT NULL DEFAULT false,
    version INT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id)
);
CALL synapse_enable_tenant_rls('identity_policies');

-- +goose StatementBegin
CREATE FUNCTION synapse_identity_guard_policy()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $policy_guard$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.cutover_phase = 'declared' THEN
            RAISE EXCEPTION 'identity cutover must pass through shadow before declaration' USING ERRCODE = 'SYN02';
        END IF;
        NEW.version := 1;
        RETURN NEW;
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id THEN
        RAISE EXCEPTION 'identity policy ownership is immutable' USING ERRCODE = 'SYN02';
    END IF;
    -- The phase only advances, except that shadow may be rolled back to legacy. Declaration is
    -- the point of no return.
    IF NEW.cutover_phase IS DISTINCT FROM OLD.cutover_phase AND NOT (
        (OLD.cutover_phase = 'legacy' AND NEW.cutover_phase = 'shadow') OR
        (OLD.cutover_phase = 'shadow' AND NEW.cutover_phase IN ('legacy', 'declared'))) THEN
        RAISE EXCEPTION 'identity cutover phase cannot move from % to %', OLD.cutover_phase, NEW.cutover_phase
            USING ERRCODE = 'SYN02';
    END IF;
    NEW.version := OLD.version + 1;
    RETURN NEW;
END;
$policy_guard$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_guard_policy() FROM PUBLIC;
CREATE TRIGGER identity_policies_guard BEFORE INSERT OR UPDATE ON identity_policies
    FOR EACH ROW EXECUTE FUNCTION synapse_identity_guard_policy();

-- Versioned connections. (protocol, trust_namespace) is the pinned trust namespace; revision is
-- provenance only. Connections start disabled.
CREATE TABLE identity_connections (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) CHECK (tenant_id <> ''),
    id TEXT NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    protocol TEXT NOT NULL CHECK (protocol IN ('oidc', 'saml')),
    trust_namespace TEXT NOT NULL CHECK (length(trust_namespace) BETWEEN 1 AND 2048 AND btrim(trust_namespace) = trust_namespace),
    display_name TEXT NOT NULL CHECK (length(btrim(display_name)) BETWEEN 1 AND 200),
    enabled BOOLEAN NOT NULL DEFAULT false,
    revision INT NOT NULL DEFAULT 1 CHECK (revision > 0),
    epoch BIGINT NOT NULL DEFAULT 1 CHECK (epoch > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, protocol, trust_namespace)
);
CALL synapse_enable_tenant_rls('identity_connections');

CREATE TABLE identity_connection_revisions (
    tenant_id TEXT NOT NULL CHECK (tenant_id <> ''),
    connection_id TEXT NOT NULL,
    revision INT NOT NULL CHECK (revision > 0),
    settings JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(settings) = 'object' AND octet_length(settings::text) <= 16384),
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 256),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, connection_id, revision),
    FOREIGN KEY (tenant_id, connection_id) REFERENCES identity_connections(tenant_id, id)
);
CALL synapse_enable_tenant_rls('identity_connection_revisions');
CREATE TRIGGER identity_connection_revisions_append_only BEFORE UPDATE OR DELETE ON identity_connection_revisions
    FOR EACH ROW EXECUTE FUNCTION synapse_identity_append_only();

-- +goose StatementBegin
CREATE FUNCTION synapse_identity_guard_connection()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $connection_guard$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id OR
       NEW.protocol IS DISTINCT FROM OLD.protocol OR NEW.trust_namespace IS DISTINCT FROM OLD.trust_namespace OR
       NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'identity connection trust namespace is pinned' USING ERRCODE = 'SYN02';
    END IF;
    IF NEW.revision < OLD.revision THEN
        RAISE EXCEPTION 'identity connection revision cannot decrease' USING ERRCODE = 'SYN02';
    END IF;
    -- Disabling revokes every session bound to the connection.
    IF OLD.enabled AND NOT NEW.enabled THEN
        NEW.epoch := OLD.epoch + 1;
    ELSE
        NEW.epoch := OLD.epoch;
    END IF;
    RETURN NEW;
END;
$connection_guard$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_guard_connection() FROM PUBLIC;
CREATE TRIGGER identity_connections_guard BEFORE UPDATE ON identity_connections
    FOR EACH ROW EXECUTE FUNCTION synapse_identity_guard_connection();

-- Tenant memberships. One row per (tenant, person); rejoin reuses the row with a new epoch, and
-- the audit log keeps historical attribution. legacy_user_id is the stable actor ID.
CREATE TABLE identity_memberships (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) CHECK (tenant_id <> ''),
    id TEXT NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    person_id TEXT NOT NULL REFERENCES identity_persons(id),
    legacy_user_id TEXT,
    role TEXT NOT NULL CHECK (role IN ('admin', 'consultant', 'reviewer', 'readonly', 'member', 'integration_admin')),
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'suspended', 'removed')),
    suspension_source TEXT CHECK (suspension_source IN ('manual', 'source')),
    last_transition_source TEXT NOT NULL DEFAULT 'manual'
        CHECK (last_transition_source IN ('manual', 'source', 'rejoin', 'legacy_projection')),
    epoch BIGINT NOT NULL DEFAULT 1 CHECK (epoch > 0),
    version INT NOT NULL DEFAULT 1 CHECK (version > 0),
    rejoin_approved_by TEXT CHECK (rejoin_approved_by IS NULL OR length(rejoin_approved_by) BETWEEN 1 AND 256),
    rejoined_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, id, person_id),
    CHECK ((state = 'suspended') = (suspension_source IS NOT NULL)),
    -- The stable actor ID: every existing users(ownership_tenant_id, id) foreign key (ownership,
    -- contacts, finding assignee, inbox) resolves a member through this tenant-local users row.
    CONSTRAINT identity_memberships_legacy_user_fk FOREIGN KEY (tenant_id, legacy_user_id)
        REFERENCES users(ownership_tenant_id, id)
);
CREATE UNIQUE INDEX identity_memberships_person ON identity_memberships(tenant_id, person_id);
CREATE UNIQUE INDEX identity_memberships_legacy_user ON identity_memberships(tenant_id, legacy_user_id) WHERE legacy_user_id IS NOT NULL;
CREATE INDEX identity_memberships_admins ON identity_memberships(tenant_id, id) WHERE role = 'admin' AND state = 'active';
CALL synapse_enable_tenant_rls('identity_memberships');

-- +goose StatementBegin
CREATE FUNCTION synapse_identity_guard_membership()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $membership_guard$
DECLARE
    phase TEXT;
BEGIN
    -- Before declaration users is the writer of record: only the legacy projection moves a
    -- membership, so every membership state stays round-trippable to users.
    SELECT p.cutover_phase INTO phase FROM public.identity_policies p WHERE p.tenant_id = NEW.tenant_id;
    IF COALESCE(phase, 'legacy') <> 'declared' AND NEW.last_transition_source <> 'legacy_projection' THEN
        RAISE EXCEPTION 'a native membership change is not representable before cutover' USING ERRCODE = 'SYN01';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id OR
       NEW.person_id IS DISTINCT FROM OLD.person_id OR NEW.legacy_user_id IS DISTINCT FROM OLD.legacy_user_id OR
       NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'identity membership ownership is immutable' USING ERRCODE = 'SYN02';
    END IF;
    IF NEW.last_transition_source = 'rejoin' AND NEW.state IS DISTINCT FROM OLD.state AND OLD.state <> 'removed' THEN
        RAISE EXCEPTION 'rejoin applies only to a removed membership' USING ERRCODE = 'SYN02';
    END IF;
    IF OLD.state = 'removed' AND NEW.state <> 'removed' THEN
        IF NEW.state <> 'active' OR NEW.last_transition_source <> 'rejoin' OR
           NEW.rejoin_approved_by IS NULL OR NEW.rejoined_at IS NULL THEN
            RAISE EXCEPTION 'a removed membership returns only through an approved rejoin' USING ERRCODE = 'SYN02';
        END IF;
    END IF;
    IF OLD.state = 'suspended' AND OLD.suspension_source = 'manual' AND NEW.last_transition_source = 'source' AND
       (NEW.state = 'active' OR NEW.suspension_source IS DISTINCT FROM 'manual') THEN
        RAISE EXCEPTION 'source lifecycle cannot override a manual suspension' USING ERRCODE = 'SYN02';
    END IF;
    -- Any lifecycle or role change revokes sessions issued under the previous membership epoch.
    IF NEW.state IS DISTINCT FROM OLD.state OR NEW.role IS DISTINCT FROM OLD.role THEN
        NEW.epoch := OLD.epoch + 1;
    ELSE
        NEW.epoch := OLD.epoch;
    END IF;
    NEW.version := OLD.version + 1;
    RETURN NEW;
END;
$membership_guard$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_guard_membership() FROM PUBLIC;
CREATE TRIGGER identity_memberships_guard BEFORE UPDATE ON identity_memberships
    FOR EACH ROW EXECUTE FUNCTION synapse_identity_guard_membership();

-- Platform-only derivative of identity_memberships, maintained solely by trigger. It lets the
-- exact-person projection and person-global fan-out find a person's tenants without granting
-- any cross-tenant read on the tenant table itself.
CREATE TABLE identity_person_membership_index (
    tenant_id TEXT NOT NULL,
    membership_id TEXT NOT NULL,
    person_id TEXT NOT NULL,
    role TEXT NOT NULL,
    state TEXT NOT NULL,
    PRIMARY KEY (tenant_id, membership_id)
);
CREATE INDEX identity_person_membership_index_person ON identity_person_membership_index(person_id, state);
CALL synapse_enable_owner_only_rls('identity_person_membership_index');

-- +goose StatementBegin
CREATE FUNCTION synapse_identity_index_membership()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $membership_index$
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        DELETE FROM public.identity_person_membership_index
         WHERE tenant_id = OLD.tenant_id AND membership_id = OLD.id;
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        INSERT INTO public.identity_person_membership_index(tenant_id, membership_id, person_id, role, state)
        VALUES (NEW.tenant_id, NEW.id, NEW.person_id, NEW.role, NEW.state);
    END IF;
    RETURN NULL;
END;
$membership_index$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_index_membership() FROM PUBLIC;
CREATE TRIGGER identity_memberships_index AFTER INSERT OR UPDATE OR DELETE ON identity_memberships
    FOR EACH ROW EXECUTE FUNCTION synapse_identity_index_membership();

-- Representability: before the tenant declares cutover, a membership must round-trip to exactly
-- one legacy users row, so a person may hold no second membership anywhere.
-- +goose StatementBegin
CREATE FUNCTION synapse_identity_guard_membership_representable()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $membership_representable$
DECLARE
    phase TEXT;
BEGIN
    -- Serialize membership creation per person so two tenants cannot both pass the check.
    PERFORM pg_advisory_xact_lock(hashtext('synapse.identity_person'), hashtext(NEW.person_id));
    SELECT p.cutover_phase INTO phase FROM public.identity_policies p WHERE p.tenant_id = NEW.tenant_id;
    IF COALESCE(phase, 'legacy') <> 'declared' THEN
        IF NEW.last_transition_source <> 'legacy_projection' THEN
            RAISE EXCEPTION 'a native membership is not representable before cutover'
                USING ERRCODE = 'SYN01';
        END IF;
        IF NEW.legacy_user_id IS NULL THEN
            RAISE EXCEPTION 'membership without a legacy user is not representable before cutover'
                USING ERRCODE = 'SYN01';
        END IF;
        IF EXISTS (SELECT 1 FROM public.identity_person_membership_index i
                    WHERE i.person_id = NEW.person_id
                      AND NOT (i.tenant_id = NEW.tenant_id AND i.membership_id = NEW.id)) THEN
            RAISE EXCEPTION 'a second membership for one person is not representable before cutover'
                USING ERRCODE = 'SYN01';
        END IF;
    END IF;
    RETURN NEW;
END;
$membership_representable$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_guard_membership_representable() FROM PUBLIC;
CREATE TRIGGER identity_memberships_representable BEFORE INSERT ON identity_memberships
    FOR EACH ROW EXECUTE FUNCTION synapse_identity_guard_membership_representable();

-- Approved authenticators. (tenant_id, connection_id, protocol_subject) is the canonical key.
CREATE TABLE identity_authenticators (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) CHECK (tenant_id <> ''),
    id TEXT NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    connection_id TEXT NOT NULL,
    protocol_subject TEXT NOT NULL CHECK (length(protocol_subject) BETWEEN 1 AND 1024 AND btrim(protocol_subject) = protocol_subject),
    membership_id TEXT NOT NULL,
    person_id TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'approved' CHECK (state IN ('approved', 'revoked')),
    approved_by TEXT NOT NULL CHECK (length(approved_by) BETWEEN 1 AND 256),
    source TEXT NOT NULL DEFAULT 'native' CHECK (source IN ('native', 'legacy_link')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, connection_id, protocol_subject),
    CHECK ((state = 'revoked') = (revoked_at IS NOT NULL)),
    FOREIGN KEY (tenant_id, connection_id) REFERENCES identity_connections(tenant_id, id),
    FOREIGN KEY (tenant_id, membership_id, person_id) REFERENCES identity_memberships(tenant_id, id, person_id)
);
CREATE INDEX identity_authenticators_membership ON identity_authenticators(tenant_id, membership_id);
CALL synapse_enable_tenant_rls('identity_authenticators');

-- Before declaration an authenticator must mirror an approved legacy OIDC link.
-- +goose StatementBegin
CREATE FUNCTION synapse_identity_guard_authenticator()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $authenticator_guard$
DECLARE
    phase TEXT;
BEGIN
    IF TG_OP = 'UPDATE' AND (NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id OR
       NEW.connection_id IS DISTINCT FROM OLD.connection_id OR NEW.protocol_subject IS DISTINCT FROM OLD.protocol_subject OR
       NEW.membership_id IS DISTINCT FROM OLD.membership_id OR NEW.person_id IS DISTINCT FROM OLD.person_id) THEN
        RAISE EXCEPTION 'identity authenticator binding is immutable' USING ERRCODE = 'SYN02';
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.state = 'revoked' AND NEW.state <> 'revoked' THEN
        RAISE EXCEPTION 'authenticator revocation is terminal' USING ERRCODE = 'SYN02';
    END IF;
    SELECT p.cutover_phase INTO phase FROM public.identity_policies p WHERE p.tenant_id = NEW.tenant_id;
    IF COALESCE(phase, 'legacy') <> 'declared' AND NEW.source <> 'legacy_link' THEN
        RAISE EXCEPTION 'a native authenticator is not representable before cutover' USING ERRCODE = 'SYN01';
    END IF;
    RETURN NEW;
END;
$authenticator_guard$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_guard_authenticator() FROM PUBLIC;
CREATE TRIGGER identity_authenticators_guard BEFORE INSERT OR UPDATE ON identity_authenticators
    FOR EACH ROW EXECUTE FUNCTION synapse_identity_guard_authenticator();

-- Credentials. The kind set is closed. Legacy projections mirror users.api_key_hash and are
-- written only inside the users write transaction.
CREATE TABLE identity_credentials (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) CHECK (tenant_id <> ''),
    id TEXT NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    kind TEXT NOT NULL CHECK (kind IN ('api_key', 'browser_session', 'break_glass')),
    digest TEXT NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    membership_id TEXT NOT NULL,
    person_id TEXT NOT NULL,
    legacy_user_id TEXT,
    source TEXT NOT NULL CHECK (source IN ('legacy_projection', 'native')),
    -- For a legacy projection: true when the digest came from key issuance (create or rotate),
    -- false when a disable replaced it with an unusable value. The credential is active only
    -- while the user is enabled and the digest is issued, so re-enable restores nothing.
    legacy_key_issued BOOLEAN NOT NULL DEFAULT false,
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, id, membership_id, person_id),
    CHECK ((state = 'revoked') = (revoked_at IS NOT NULL)),
    CHECK (source <> 'legacy_projection' OR (kind = 'api_key' AND legacy_user_id IS NOT NULL)),
    CHECK (state <> 'active' OR source <> 'legacy_projection' OR legacy_key_issued),
    FOREIGN KEY (tenant_id, membership_id, person_id) REFERENCES identity_memberships(tenant_id, id, person_id),
    FOREIGN KEY (tenant_id, legacy_user_id) REFERENCES users(ownership_tenant_id, id)
);
CREATE UNIQUE INDEX identity_credentials_legacy_projection ON identity_credentials(tenant_id, legacy_user_id)
    WHERE source = 'legacy_projection';
CREATE INDEX identity_credentials_membership ON identity_credentials(tenant_id, membership_id);
CALL synapse_enable_tenant_rls('identity_credentials');

-- +goose StatementBegin
CREATE FUNCTION synapse_identity_guard_credential()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $credential_guard$
DECLARE
    phase TEXT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT p.cutover_phase INTO phase FROM public.identity_policies p WHERE p.tenant_id = NEW.tenant_id;
        IF COALESCE(phase, 'legacy') <> 'declared' AND NEW.source <> 'legacy_projection' THEN
            RAISE EXCEPTION 'a native credential is not representable before cutover' USING ERRCODE = 'SYN01';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id OR
       NEW.kind IS DISTINCT FROM OLD.kind OR NEW.membership_id IS DISTINCT FROM OLD.membership_id OR
       NEW.person_id IS DISTINCT FROM OLD.person_id OR NEW.legacy_user_id IS DISTINCT FROM OLD.legacy_user_id OR
       NEW.source IS DISTINCT FROM OLD.source OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'identity credential ownership is immutable' USING ERRCODE = 'SYN02';
    END IF;
    -- A legacy projection mirrors users.api_key_hash and users.disabled exactly, because users is
    -- the writer of record. A native credential is immutable and its revocation is terminal.
    IF NEW.source = 'native' THEN
        IF NEW.digest IS DISTINCT FROM OLD.digest THEN
            RAISE EXCEPTION 'a native credential digest is immutable' USING ERRCODE = 'SYN02';
        END IF;
        IF OLD.state = 'revoked' AND NEW.state = 'active' THEN
            RAISE EXCEPTION 'native credential revocation is terminal' USING ERRCODE = 'SYN02';
        END IF;
    END IF;
    RETURN NEW;
END;
$credential_guard$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_guard_credential() FROM PUBLIC;
CREATE TRIGGER identity_credentials_guard BEFORE INSERT OR UPDATE ON identity_credentials
    FOR EACH ROW EXECUTE FUNCTION synapse_identity_guard_credential();

-- Global exact-digest routing index, derived only from active credentials by trigger.
CREATE TABLE identity_credential_digests (
    digest TEXT PRIMARY KEY CHECK (digest ~ '^[0-9a-f]{64}$'),
    tenant_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('api_key', 'browser_session', 'break_glass')),
    credential_id TEXT NOT NULL,
    person_id TEXT NOT NULL,
    UNIQUE (tenant_id, credential_id)
);
CALL synapse_enable_owner_only_rls('identity_credential_digests');

-- +goose StatementBegin
CREATE FUNCTION synapse_identity_index_credential()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $credential_index$
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        DELETE FROM public.identity_credential_digests
         WHERE tenant_id = OLD.tenant_id AND credential_id = OLD.id;
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') AND NEW.state = 'active' THEN
        INSERT INTO public.identity_credential_digests(digest, tenant_id, kind, credential_id, person_id)
        VALUES (NEW.digest, NEW.tenant_id, NEW.kind, NEW.id, NEW.person_id);
    END IF;
    RETURN NULL;
END;
$credential_index$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_index_credential() FROM PUBLIC;
CREATE TRIGGER identity_credentials_index AFTER INSERT OR UPDATE OR DELETE ON identity_credentials
    FOR EACH ROW EXECUTE FUNCTION synapse_identity_index_credential();

-- Invitations. The code is stored only as a digest.
CREATE TABLE identity_invitations (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) CHECK (tenant_id <> ''),
    id TEXT NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    code_digest TEXT NOT NULL CHECK (code_digest ~ '^[0-9a-f]{64}$'),
    recipient TEXT NOT NULL CHECK (length(btrim(recipient)) BETWEEN 1 AND 320),
    role TEXT NOT NULL CHECK (role IN ('admin', 'consultant', 'reviewer', 'readonly', 'member', 'integration_admin')),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'accepted', 'revoked', 'expired')),
    created_by TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 256),
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_membership_id TEXT,
    accepted_person_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (code_digest),
    CHECK (expires_at > created_at),
    CHECK ((state = 'accepted') = (accepted_membership_id IS NOT NULL AND accepted_person_id IS NOT NULL)),
    FOREIGN KEY (tenant_id, accepted_membership_id, accepted_person_id) REFERENCES identity_memberships(tenant_id, id, person_id)
);
CALL synapse_enable_tenant_rls('identity_invitations');

-- Sessions reference a browser_session credential for routing and pin the epochs they were
-- issued under; a moved epoch invalidates them.
CREATE TABLE identity_sessions (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) CHECK (tenant_id <> ''),
    id TEXT NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    credential_id TEXT NOT NULL,
    membership_id TEXT NOT NULL,
    person_id TEXT NOT NULL,
    connection_id TEXT,
    lineage_id TEXT NOT NULL CHECK (length(lineage_id) BETWEEN 1 AND 128),
    rotated_from_session_id TEXT,
    authenticated_at TIMESTAMPTZ NOT NULL,
    origin_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    person_epoch BIGINT NOT NULL CHECK (person_epoch > 0),
    membership_epoch BIGINT NOT NULL CHECK (membership_epoch > 0),
    connection_epoch BIGINT CHECK (connection_epoch IS NULL OR connection_epoch > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, credential_id),
    CHECK (expires_at > created_at),
    CHECK (origin_at <= created_at AND authenticated_at <= created_at),
    CHECK ((connection_id IS NULL) = (connection_epoch IS NULL)),
    FOREIGN KEY (tenant_id, credential_id, membership_id, person_id)
        REFERENCES identity_credentials(tenant_id, id, membership_id, person_id),
    FOREIGN KEY (tenant_id, membership_id, person_id) REFERENCES identity_memberships(tenant_id, id, person_id),
    FOREIGN KEY (tenant_id, connection_id) REFERENCES identity_connections(tenant_id, id),
    FOREIGN KEY (tenant_id, rotated_from_session_id) REFERENCES identity_sessions(tenant_id, id)
);
CALL synapse_enable_tenant_rls('identity_sessions');

-- One-use protocol transaction records (state/nonce/PKCE binding) for login, linking,
-- switching, step-up and invitation acceptance.
CREATE TABLE identity_transactions (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) CHECK (tenant_id <> ''),
    id TEXT NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    purpose TEXT NOT NULL CHECK (purpose IN ('login', 'link', 'switch', 'step_up', 'invitation')),
    connection_id TEXT NOT NULL,
    connection_revision INT NOT NULL CHECK (connection_revision > 0),
    state_digest TEXT NOT NULL CHECK (state_digest ~ '^[0-9a-f]{64}$'),
    nonce_digest TEXT NOT NULL CHECK (nonce_digest ~ '^[0-9a-f]{64}$'),
    pkce_verifier_sealed TEXT NOT NULL CHECK (length(pkce_verifier_sealed) BETWEEN 1 AND 4096),
    session_id TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (state_digest),
    CHECK (expires_at > created_at),
    FOREIGN KEY (tenant_id, connection_id, connection_revision) REFERENCES identity_connection_revisions(tenant_id, connection_id, revision),
    FOREIGN KEY (tenant_id, session_id) REFERENCES identity_sessions(tenant_id, id)
);
CALL synapse_enable_tenant_rls('identity_transactions');

-- Immutable per-tenant delivery obligations for person-global audit. Only delivery progress
-- may change, and attempts are bounded.
CREATE TABLE identity_person_audit_deliveries (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) CHECK (tenant_id <> ''),
    id BIGINT NOT NULL REFERENCES identity_person_audit(id),
    person_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    reason TEXT NOT NULL,
    audit_hash TEXT NOT NULL CHECK (audit_hash ~ '^[0-9a-f]{64}$'),
    occurred_at TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'delivered', 'exhausted')),
    attempts INT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts INT NOT NULL DEFAULT 8 CHECK (max_attempts BETWEEN 1 AND 32),
    last_error TEXT NOT NULL DEFAULT '' CHECK (length(last_error) <= 512),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_attempt_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    CHECK (attempts <= max_attempts),
    CHECK ((state = 'delivered') = (delivered_at IS NOT NULL))
);
CREATE INDEX identity_person_audit_deliveries_due ON identity_person_audit_deliveries(tenant_id, next_attempt_at)
    WHERE state = 'pending';
CALL synapse_enable_tenant_rls('identity_person_audit_deliveries');

-- +goose StatementBegin
CREATE FUNCTION synapse_identity_guard_delivery()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $delivery_guard$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'person audit delivery obligations are immutable' USING ERRCODE = 'SYN02';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id OR
       NEW.person_id IS DISTINCT FROM OLD.person_id OR NEW.actor IS DISTINCT FROM OLD.actor OR
       NEW.action IS DISTINCT FROM OLD.action OR NEW.reason IS DISTINCT FROM OLD.reason OR
       NEW.audit_hash IS DISTINCT FROM OLD.audit_hash OR NEW.occurred_at IS DISTINCT FROM OLD.occurred_at OR
       NEW.max_attempts IS DISTINCT FROM OLD.max_attempts OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'person audit delivery obligations are immutable' USING ERRCODE = 'SYN02';
    END IF;
    IF OLD.state <> 'pending' THEN
        RAISE EXCEPTION 'person audit delivery is already final' USING ERRCODE = 'SYN02';
    END IF;
    IF NEW.attempts < OLD.attempts OR NEW.attempts > OLD.attempts + 1 THEN
        RAISE EXCEPTION 'person audit delivery attempts advance by one' USING ERRCODE = 'SYN02';
    END IF;
    RETURN NEW;
END;
$delivery_guard$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_guard_delivery() FROM PUBLIC;
CREATE TRIGGER identity_person_audit_deliveries_guard BEFORE UPDATE OR DELETE ON identity_person_audit_deliveries
    FOR EACH ROW EXECUTE FUNCTION synapse_identity_guard_delivery();

-- Backfill fencing, checkpoints and per-user classification.
CREATE TABLE identity_backfill_fences (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) CHECK (tenant_id <> ''),
    id TEXT NOT NULL CHECK (id <> ''),
    fence_token BIGINT NOT NULL DEFAULT 0 CHECK (fence_token >= 0),
    run_id TEXT NOT NULL DEFAULT '',
    -- While true, every users write in the tenant projects atomically into the identity rows.
    -- The rollback drill clears it together with the derived rows.
    projection_enabled BOOLEAN NOT NULL DEFAULT false,
    -- Last committed users.id of the current pass; a new run resumes after it.
    checkpoint_user_id TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id)
);
CALL synapse_enable_tenant_rls('identity_backfill_fences');

CREATE TABLE identity_backfill_runs (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) CHECK (tenant_id <> ''),
    id TEXT NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    fence_token BIGINT NOT NULL CHECK (fence_token > 0),
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 256),
    state TEXT NOT NULL DEFAULT 'running' CHECK (state IN ('running', 'completed', 'failed')),
    batch_size INT NOT NULL CHECK (batch_size BETWEEN 1 AND 1000),
    processed INT NOT NULL DEFAULT 0 CHECK (processed >= 0),
    batches INT NOT NULL DEFAULT 0 CHECK (batches >= 0),
    checkpoint_user_id TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '' CHECK (length(last_error) <= 512),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, fence_token)
);
CALL synapse_enable_tenant_rls('identity_backfill_runs');

CREATE TABLE identity_backfill_items (
    tenant_id TEXT NOT NULL CHECK (tenant_id <> ''),
    id TEXT NOT NULL,
    classification TEXT NOT NULL CHECK (classification IN
        ('migrated', 'suspended', 'bootstrap_skipped', 'ambiguous_duplicate', 'ambiguous_corrupt',
         'ambiguous_foreign_link', 'ambiguous_unproven_key')),
    credential_class TEXT NOT NULL CHECK (credential_class IN
        ('real', 'placeholder', 'disabled', 'ambiguous', 'none')),
    person_id TEXT,
    membership_id TEXT,
    -- SHA-256 of the legacy api_key_hash value, so corrupt values are still fingerprinted.
    source_fingerprint TEXT NOT NULL CHECK (source_fingerprint ~ '^[0-9a-f]{64}$'),
    -- NULL when the users write path itself projected the row (a user created after projection
    -- was enabled) rather than a backfill run.
    run_id TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, id) REFERENCES users(ownership_tenant_id, id),
    FOREIGN KEY (tenant_id, run_id) REFERENCES identity_backfill_runs(tenant_id, id)
);
CALL synapse_enable_tenant_rls('identity_backfill_items');

-- Append-only shadow parity evidence. The report never repairs the legacy source.
CREATE TABLE identity_shadow_reports (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) CHECK (tenant_id <> ''),
    id TEXT NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    run_id TEXT,
    legacy_users INT NOT NULL CHECK (legacy_users >= 0),
    bootstrap_skipped INT NOT NULL CHECK (bootstrap_skipped >= 0),
    memberships INT NOT NULL CHECK (memberships >= 0),
    missing_memberships INT NOT NULL CHECK (missing_memberships >= 0),
    credentials_expected INT NOT NULL CHECK (credentials_expected >= 0),
    credentials_matched INT NOT NULL CHECK (credentials_matched >= 0),
    authenticators_expected INT NOT NULL CHECK (authenticators_expected >= 0),
    authenticators_matched INT NOT NULL CHECK (authenticators_matched >= 0),
    authenticator_mismatches INT NOT NULL CHECK (authenticator_mismatches >= 0),
    digest_mismatches INT NOT NULL CHECK (digest_mismatches >= 0),
    routing_mismatches INT NOT NULL CHECK (routing_mismatches >= 0),
    role_drift INT NOT NULL CHECK (role_drift >= 0),
    state_drift INT NOT NULL CHECK (state_drift >= 0),
    placeholders INT NOT NULL CHECK (placeholders >= 0),
    ambiguous INT NOT NULL CHECK (ambiguous >= 0),
    drift_total INT NOT NULL CHECK (drift_total >= 0),
    max_drift INT NOT NULL CHECK (max_drift >= 0),
    aborted BOOLEAN NOT NULL,
    ready BOOLEAN NOT NULL,
    rollback_prepared BOOLEAN NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    CHECK (NOT (ready AND (aborted OR drift_total > 0 OR ambiguous > 0 OR missing_memberships > 0)))
);
CALL synapse_enable_tenant_rls('identity_shadow_reports');
CREATE TRIGGER identity_shadow_reports_append_only BEFORE UPDATE OR DELETE ON identity_shadow_reports
    FOR EACH ROW EXECUTE FUNCTION synapse_identity_append_only();

-- Exact-digest credential routing. Returns only (tenant_id, kind) for one exact, well-formed
-- digest of an active credential; every later read binds that tenant through RLS.
-- +goose StatementBegin
CREATE FUNCTION synapse_identity_route_credential(p_digest TEXT)
RETURNS TABLE(tenant_id TEXT, kind TEXT)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $route_credential$
    SELECT d.tenant_id, d.kind FROM public.identity_credential_digests d
    WHERE p_digest ~ '^[0-9a-f]{64}$' AND d.digest = p_digest
    LIMIT 1
$route_credential$;
-- +goose StatementEnd

-- Exact-authenticated-person membership projection. The caller proves possession of an active
-- credential digest bound to the named person; only that person's active memberships and
-- picker labels are returned. A suspended person gets nothing.
-- +goose StatementBegin
CREATE FUNCTION synapse_identity_person_memberships(p_digest TEXT, p_person_id TEXT)
RETURNS TABLE(tenant_id TEXT, membership_id TEXT, tenant_label TEXT, role TEXT)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $person_memberships$
    SELECT i.tenant_id, i.membership_id, t.name, i.role
      FROM public.identity_credential_digests d
      JOIN public.identity_persons p ON p.id = d.person_id AND p.state = 'active'
      JOIN public.identity_person_membership_index i ON i.person_id = p.id AND i.state = 'active'
      JOIN public.tenants t ON t.id = i.tenant_id
     WHERE p_digest ~ '^[0-9a-f]{64}$' AND d.digest = p_digest AND d.person_id = p_person_id
     ORDER BY t.name, i.tenant_id
     LIMIT 100
$person_memberships$;
-- +goose StatementEnd

-- Current person epoch for the same credential-bound person; NULL when absent or suspended.
-- +goose StatementBegin
CREATE FUNCTION synapse_identity_person_epoch(p_digest TEXT, p_person_id TEXT)
RETURNS BIGINT
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $person_epoch$
    SELECT p.epoch
      FROM public.identity_credential_digests d
      JOIN public.identity_persons p ON p.id = d.person_id AND p.state = 'active'
     WHERE p_digest ~ '^[0-9a-f]{64}$' AND d.digest = p_digest AND d.person_id = p_person_id
     LIMIT 1
$person_epoch$;
-- +goose StatementEnd

-- Deliberately platform-owned person command. It mutates one exact person, appends the chained
-- platform audit, and inserts one immutable delivery obligation per tenant holding a membership
-- of that person, all in the caller's transaction. The caller's tenant binding is restored. The
-- runtime role holds no EXECUTE on it: suspend, reactivate and session revocation, and any choice
-- of audit actor, belong to platform operators connected as the owner.
-- +goose StatementBegin
CREATE FUNCTION synapse_identity_person_command(p_person_id TEXT, p_action TEXT, p_actor TEXT, p_reason TEXT)
RETURNS TABLE(person_epoch BIGINT, audit_id BIGINT, obligations INT)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $person_command$
DECLARE
    p public.identity_persons%ROWTYPE;
    inserted BOOLEAN := false;
    prev_hash TEXT;
    new_hash TEXT;
    new_audit_id BIGINT;
    now_at TIMESTAMPTZ := clock_timestamp();
    caller_tenant TEXT := current_setting('app.current_tenant', true);
    target_tenant TEXT;
    fanned INT := 0;
BEGIN
    IF p_person_id IS NULL OR p_person_id = '' OR length(p_person_id) > 128 OR btrim(p_person_id) <> p_person_id THEN
        RAISE EXCEPTION 'person id is invalid' USING ERRCODE = '22023';
    END IF;
    IF p_actor IS NULL OR length(p_actor) NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'person command actor is required' USING ERRCODE = '22023';
    END IF;
    IF p_reason IS NULL OR length(p_reason) > 512 THEN
        RAISE EXCEPTION 'person command reason is too long' USING ERRCODE = '22023';
    END IF;
    IF p_action = 'person.created' THEN
        INSERT INTO public.identity_persons(id, created_at, updated_at) VALUES (p_person_id, now_at, now_at)
        ON CONFLICT (id) DO NOTHING;
        inserted := FOUND;
        SELECT * INTO p FROM public.identity_persons WHERE id = p_person_id;
        IF NOT inserted THEN
            -- Idempotent create: no second audit row and no fan-out.
            RETURN QUERY SELECT p.epoch, 0::BIGINT, 0;
            RETURN;
        END IF;
    ELSE
        SELECT * INTO p FROM public.identity_persons WHERE id = p_person_id FOR UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'person not found' USING ERRCODE = 'P0002';
        END IF;
        IF p_action = 'person.sessions_revoked' THEN
            UPDATE public.identity_persons SET epoch = epoch + 1, updated_at = GREATEST(now_at, created_at)
             WHERE id = p_person_id RETURNING * INTO p;
        ELSIF p_action = 'person.suspended' THEN
            IF p.state = 'suspended' THEN
                RAISE EXCEPTION 'person is already suspended' USING ERRCODE = 'SYN02';
            END IF;
            UPDATE public.identity_persons SET state = 'suspended', epoch = epoch + 1, updated_at = GREATEST(now_at, created_at)
             WHERE id = p_person_id RETURNING * INTO p;
        ELSIF p_action = 'person.reactivated' THEN
            IF p.state = 'active' THEN
                RAISE EXCEPTION 'person is already active' USING ERRCODE = 'SYN02';
            END IF;
            UPDATE public.identity_persons SET state = 'active', updated_at = GREATEST(now_at, created_at)
             WHERE id = p_person_id RETURNING * INTO p;
        ELSE
            RAISE EXCEPTION 'unknown person command' USING ERRCODE = '22023';
        END IF;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext('synapse.identity_person_audit'));
    SELECT a.hash INTO prev_hash FROM public.identity_person_audit a ORDER BY a.id DESC LIMIT 1;
    prev_hash := COALESCE(prev_hash, '');
    new_hash := encode(sha256(convert_to(concat_ws(E'\x1f', prev_hash, p_person_id, p_actor, p_action,
        p_reason, p.epoch::text, to_char(now_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')), 'UTF8')), 'hex');
    INSERT INTO public.identity_person_audit(person_id, actor, action, reason, person_epoch, created_at, previous_hash, hash)
    VALUES (p_person_id, p_actor, p_action, p_reason, p.epoch, now_at, prev_hash, new_hash)
    RETURNING id INTO new_audit_id;

    FOR target_tenant IN
        SELECT DISTINCT i.tenant_id FROM public.identity_person_membership_index i
         WHERE i.person_id = p_person_id ORDER BY i.tenant_id
    LOOP
        PERFORM set_config('app.current_tenant', target_tenant, true);
        INSERT INTO public.identity_person_audit_deliveries(tenant_id, id, person_id, actor, action, reason, audit_hash, occurred_at)
        VALUES (target_tenant, new_audit_id, p_person_id, p_actor, p_action, p_reason, new_hash, now_at);
        fanned := fanned + 1;
    END LOOP;
    PERFORM set_config('app.current_tenant', COALESCE(caller_tenant, ''), true);
    RETURN QUERY SELECT p.epoch, new_audit_id, fanned;
END;
$person_command$;
-- +goose StatementEnd

-- The only person command the runtime role may run: idempotent creation of one exact person for
-- the legacy projection. The action and the audit actor are fixed here, so a runtime caller can
-- neither change a person's state nor write an actor of its choosing into the chained audit.
-- +goose StatementBegin
CREATE FUNCTION synapse_identity_create_person(p_person_id TEXT, p_reason TEXT)
RETURNS TABLE(person_epoch BIGINT, audit_id BIGINT, obligations INT)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $create_person$
    SELECT c.person_epoch, c.audit_id, c.obligations
      FROM public.synapse_identity_person_command(p_person_id, 'person.created', 'system:identity-projection', p_reason) c
$create_person$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION synapse_identity_route_credential(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION synapse_identity_person_memberships(TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION synapse_identity_person_epoch(TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION synapse_identity_person_command(TEXT, TEXT, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION synapse_identity_create_person(TEXT, TEXT) FROM PUBLIC;
-- GrantRuntimePrivileges grants EXECUTE on the routing, projection, epoch and create-person
-- functions to the runtime role, never on synapse_identity_person_command, and revokes its table
-- privileges on the owner-only platform tables.

-- +goose Down
-- The person audit and shadow reports are append-only evidence. Refuse to drop them while they
-- hold rows: archive that evidence and roll every API, worker and MCP replica back to a binary
-- without the identity foundation first. FORCE RLS is lifted so the check sees every tenant's rows;
-- a refused Down rolls back with the rest of its transaction.
ALTER TABLE identity_person_audit NO FORCE ROW LEVEL SECURITY;
ALTER TABLE identity_shadow_reports NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $evidence_guard$
BEGIN
    IF EXISTS (SELECT 1 FROM identity_person_audit) OR EXISTS (SELECT 1 FROM identity_shadow_reports) THEN
        RAISE EXCEPTION 'identity_person_audit or identity_shadow_reports holds evidence rows; archive them and roll binaries back before reverting migration 0206'
            USING ERRCODE = 'SYN02';
    END IF;
END;
$evidence_guard$;
-- +goose StatementEnd
DROP FUNCTION IF EXISTS synapse_identity_create_person(TEXT, TEXT);
DROP FUNCTION IF EXISTS synapse_identity_person_command(TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS synapse_identity_person_epoch(TEXT, TEXT);
DROP FUNCTION IF EXISTS synapse_identity_person_memberships(TEXT, TEXT);
DROP FUNCTION IF EXISTS synapse_identity_route_credential(TEXT);
DROP TABLE IF EXISTS identity_shadow_reports;
DROP TABLE IF EXISTS identity_backfill_items;
DROP TABLE IF EXISTS identity_backfill_runs;
DROP TABLE IF EXISTS identity_backfill_fences;
DROP TABLE IF EXISTS identity_person_audit_deliveries;
DROP FUNCTION IF EXISTS synapse_identity_guard_delivery();
DROP TABLE IF EXISTS identity_transactions;
DROP TABLE IF EXISTS identity_sessions;
DROP TABLE IF EXISTS identity_invitations;
DROP TABLE IF EXISTS identity_credential_digests;
DROP TABLE IF EXISTS identity_credentials;
DROP FUNCTION IF EXISTS synapse_identity_index_credential();
DROP FUNCTION IF EXISTS synapse_identity_guard_credential();
DROP TABLE IF EXISTS identity_authenticators;
DROP FUNCTION IF EXISTS synapse_identity_guard_authenticator();
DROP TABLE IF EXISTS identity_person_membership_index;
DROP TABLE IF EXISTS identity_memberships;
DROP FUNCTION IF EXISTS synapse_identity_guard_membership_representable();
DROP FUNCTION IF EXISTS synapse_identity_index_membership();
DROP FUNCTION IF EXISTS synapse_identity_guard_membership();
DROP TABLE IF EXISTS identity_connection_revisions;
DROP TABLE IF EXISTS identity_connections;
DROP FUNCTION IF EXISTS synapse_identity_guard_connection();
DROP TABLE IF EXISTS identity_policies;
DROP FUNCTION IF EXISTS synapse_identity_guard_policy();
DROP TABLE IF EXISTS identity_person_audit;
DROP FUNCTION IF EXISTS synapse_identity_append_only();
DROP TABLE IF EXISTS identity_persons;
DROP PROCEDURE IF EXISTS synapse_enable_owner_only_rls(text);
