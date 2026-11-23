-- +goose Up
-- A declared tenant may be born without a legacy user. This durable operation is the narrowly
-- scoped authority for its first OIDC connection and its first administrator invitation. It is
-- deliberately tenant-local: the source bootstrap principal remains in its original tenant.
CREATE TABLE identity_initial_provisioning (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) CHECK (tenant_id <> ''),
    id TEXT NOT NULL UNIQUE CHECK (length(id) BETWEEN 1 AND 128),
    connection_id TEXT NOT NULL CHECK (length(connection_id) BETWEEN 1 AND 128),
    invitation_id TEXT NOT NULL CHECK (length(invitation_id) BETWEEN 1 AND 128),
    actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 256),
    source_tenant_id TEXT NOT NULL CHECK (source_tenant_id <> ''),
    credential_id TEXT NOT NULL CHECK (length(credential_id) BETWEEN 1 AND 256),
    recipient TEXT NOT NULL CHECK (length(btrim(recipient)) BETWEEN 1 AND 320),
    state TEXT NOT NULL CHECK (state IN ('open', 'draft', 'tested', 'active', 'invited', 'closed')),
    invitation_code_sealed TEXT,
    version INT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    closed_at TIMESTAMPTZ,
    UNIQUE (tenant_id, connection_id),
    UNIQUE (tenant_id, invitation_id),
    CHECK (updated_at >= created_at),
    CHECK ((state = 'closed') = (closed_at IS NOT NULL)),
    CHECK ((state = 'invited' AND invitation_code_sealed IS NOT NULL) OR
           (state <> 'invited' AND invitation_code_sealed IS NULL))
);
CALL synapse_enable_tenant_rls('identity_initial_provisioning');

-- +goose StatementBegin
CREATE FUNCTION synapse_identity_guard_initial_provisioning()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $initial_provisioning_guard$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'initial identity provisioning provenance cannot be deleted' USING ERRCODE = 'SYN02';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'open' OR NEW.version <> 1 OR NEW.closed_at IS NOT NULL OR NEW.invitation_code_sealed IS NOT NULL THEN
            RAISE EXCEPTION 'initial identity provisioning must begin open' USING ERRCODE = 'SYN02';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id OR
       NEW.connection_id IS DISTINCT FROM OLD.connection_id OR NEW.invitation_id IS DISTINCT FROM OLD.invitation_id OR
       NEW.actor_id IS DISTINCT FROM OLD.actor_id OR NEW.source_tenant_id IS DISTINCT FROM OLD.source_tenant_id OR
       NEW.recipient IS DISTINCT FROM OLD.recipient OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'initial identity provisioning binding is immutable' USING ERRCODE = 'SYN02';
    END IF;
    IF OLD.state = 'closed' THEN
        RAISE EXCEPTION 'initial identity provisioning is terminal' USING ERRCODE = 'SYN02';
    END IF;
    IF NEW.version <> OLD.version + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'initial identity provisioning update requires a next version' USING ERRCODE = 'SYN02';
    END IF;
    -- A current bootstrap credential can replace its generation only via Begin. It carries no
    -- broader authority and immediately invalidates previously sealed scoped proofs.
    IF NEW.credential_id IS DISTINCT FROM OLD.credential_id AND NEW.state IS DISTINCT FROM OLD.state THEN
        RAISE EXCEPTION 'credential rebind cannot change provisioning state' USING ERRCODE = 'SYN02';
    END IF;
    IF NEW.state = 'closed' THEN
        IF NEW.invitation_code_sealed IS NOT NULL THEN
            RAISE EXCEPTION 'closed provisioning cannot retain invitation retry material' USING ERRCODE = 'SYN02';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.credential_id IS DISTINCT FROM OLD.credential_id THEN
        RETURN NEW;
    END IF;
    IF NOT ((OLD.state = 'open' AND NEW.state = 'draft') OR
            (OLD.state = 'draft' AND NEW.state IN ('draft', 'tested')) OR
            (OLD.state = 'tested' AND NEW.state IN ('draft', 'tested', 'active')) OR
            (OLD.state = 'active' AND NEW.state IN ('active', 'invited')) OR
            (OLD.state = 'invited' AND NEW.state = 'invited')) THEN
        RAISE EXCEPTION 'initial identity provisioning state transition is not allowed' USING ERRCODE = 'SYN02';
    END IF;
    RETURN NEW;
END;
$initial_provisioning_guard$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_guard_initial_provisioning() FROM PUBLIC;
CREATE TRIGGER identity_initial_provisioning_guard
    BEFORE INSERT OR UPDATE OR DELETE ON identity_initial_provisioning
    FOR EACH ROW EXECUTE FUNCTION synapse_identity_guard_initial_provisioning();

-- Native and older binaries both write memberships. The first one permanently closes the
-- operation in the same transaction, which denies a delayed callback or retry after admission.
-- +goose StatementBegin
CREATE FUNCTION synapse_identity_close_initial_provisioning()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $close_initial_provisioning$
DECLARE
    close_at TIMESTAMPTZ := GREATEST(NEW.created_at, clock_timestamp());
BEGIN
    PERFORM 1 FROM public.identity_policies WHERE tenant_id = NEW.tenant_id FOR UPDATE;
    UPDATE public.identity_initial_provisioning
       SET state = 'closed', invitation_code_sealed = NULL,
           closed_at = GREATEST(close_at, updated_at),
           updated_at = GREATEST(close_at, updated_at), version = version + 1
     WHERE tenant_id = NEW.tenant_id AND state <> 'closed';
    RETURN NULL;
END;
$close_initial_provisioning$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_close_initial_provisioning() FROM PUBLIC;
CREATE TRIGGER identity_memberships_close_initial_provisioning
    AFTER INSERT ON identity_memberships
    FOR EACH ROW EXECUTE FUNCTION synapse_identity_close_initial_provisioning();

-- +goose Down
ALTER TABLE identity_initial_provisioning NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM identity_initial_provisioning) THEN
        RAISE EXCEPTION 'initial identity provisioning provenance requires a forward fix';
    END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER identity_memberships_close_initial_provisioning ON identity_memberships;
DROP FUNCTION synapse_identity_close_initial_provisioning();
DROP TRIGGER identity_initial_provisioning_guard ON identity_initial_provisioning;
DROP FUNCTION synapse_identity_guard_initial_provisioning();
DROP TABLE identity_initial_provisioning;
