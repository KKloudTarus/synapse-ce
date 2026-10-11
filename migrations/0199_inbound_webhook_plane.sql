-- +goose Up
-- WS10 / #1434. Global routing is limited to one privileged public-ID-to-
-- tenant lookup; the app reads sealed secrets only inside a tenant-bound RLS
-- transaction. FORCE RLS protects the registry from unscoped runtime reads.
CREATE TABLE inbound_webhook_endpoints (
    public_id TEXT PRIMARY KEY CHECK (length(public_id) BETWEEN 32 AND 64 AND public_id ~ '^[A-Za-z0-9_-]+$'),
    tenant_id TEXT NOT NULL REFERENCES tenants(id) CHECK (tenant_id <> ''),
    owner_kind TEXT NOT NULL CHECK (owner_kind = 'integration'),
    owner_id TEXT NOT NULL CHECK (btrim(owner_id) <> ''),
    enabled BOOLEAN NOT NULL DEFAULT false,
    current_version INT NOT NULL CHECK (current_version > 0),
    current_sealed TEXT NOT NULL CHECK (btrim(current_sealed) <> '' AND octet_length(current_sealed) <= 8192),
    previous_sealed TEXT NOT NULL DEFAULT '' CHECK (octet_length(previous_sealed) <= 8192),
    previous_expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    rate_per_minute INT NOT NULL DEFAULT 60 CHECK (rate_per_minute BETWEEN 1 AND 600),
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT '-infinity'::timestamptz,
    window_count INT NOT NULL DEFAULT 0 CHECK (window_count >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT inbound_owner_fk FOREIGN KEY (tenant_id, owner_id) REFERENCES integrations(tenant_id,id) ON DELETE CASCADE,
    CONSTRAINT inbound_previous_pair CHECK (
        (previous_sealed = '' AND previous_expires_at IS NULL)
        OR (previous_sealed <> '' AND previous_expires_at IS NOT NULL
            AND previous_expires_at <= updated_at + INTERVAL '24 hours')
    )
);
CREATE INDEX inbound_webhook_owner ON inbound_webhook_endpoints (tenant_id, owner_kind, owner_id);
ALTER TABLE inbound_webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE inbound_webhook_endpoints FORCE ROW LEVEL SECURITY;
-- SECURITY DEFINER changes current_user to the table/function owner. No API
-- role owns the table: an ordinary role therefore cannot read any row even
-- if a future grant accidentally restores a direct SELECT privilege.
CREATE POLICY inbound_webhook_owner_all ON inbound_webhook_endpoints
    FOR ALL TO PUBLIC
    USING (
        current_user = pg_get_userbyid(
            (SELECT relowner FROM pg_class WHERE oid='public.inbound_webhook_endpoints'::regclass))
    )
    WITH CHECK (
        current_user = pg_get_userbyid(
            (SELECT relowner FROM pg_class WHERE oid='public.inbound_webhook_endpoints'::regclass))
    );
-- Tenant runtime gets SELECT-only row visibility. Even if a future privilege
-- change accidentally restores UPDATE/DELETE, RLS still refuses tenant DML.
CREATE POLICY inbound_webhook_tenant_select ON inbound_webhook_endpoints
    FOR SELECT TO PUBLIC
    USING (tenant_id = synapse_current_tenant());
REVOKE ALL ON TABLE inbound_webhook_endpoints FROM PUBLIC;

-- This privileged global function returns ONLY a tenant ID for one exact
-- unguessable endpoint. Owner identity, secrets, status and quotas MUST be
-- read through tenant-scoped RLS separately.
-- +goose StatementBegin
CREATE FUNCTION synapse_lookup_inbound_webhook(p_public_id TEXT)
RETURNS TABLE(tenant_id TEXT)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $inbound_lookup$
    SELECT e.tenant_id FROM public.inbound_webhook_endpoints e
    WHERE e.public_id = p_public_id
    LIMIT 1
$inbound_lookup$;
-- +goose StatementEnd

-- Version changes are mandatory for secret rotation, tenant and owner bindings
-- are immutable, and shortening/revoking the previous key is always permitted.
-- +goose StatementBegin
CREATE FUNCTION synapse_guard_inbound_webhook_update()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $inbound_update_guard$
BEGIN
    IF NEW.public_id IS DISTINCT FROM OLD.public_id OR
       NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
       NEW.owner_kind IS DISTINCT FROM OLD.owner_kind OR
       NEW.owner_id IS DISTINCT FROM OLD.owner_id THEN
        RAISE EXCEPTION 'inbound webhook routing identity is immutable';
    END IF;
    IF NEW.current_version < OLD.current_version THEN
        RAISE EXCEPTION 'inbound webhook key version cannot decrease';
    END IF;
    IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        RAISE EXCEPTION 'inbound webhook revocation is terminal';
    END IF;
    IF NEW.current_sealed IS DISTINCT FROM OLD.current_sealed OR
       (NEW.previous_sealed IS DISTINCT FROM OLD.previous_sealed AND NEW.previous_sealed <> '') THEN
        IF NEW.current_version <> OLD.current_version + 1 THEN
            RAISE EXCEPTION 'inbound webhook key rotation requires next key version';
        END IF;
        IF NEW.current_sealed IS NOT DISTINCT FROM OLD.current_sealed THEN
            RAISE EXCEPTION 'inbound webhook key rotation requires a new active key';
        END IF;
        IF NEW.previous_sealed <> '' AND NEW.previous_sealed <> OLD.current_sealed THEN
            RAISE EXCEPTION 'previous webhook key must be the former active key';
        END IF;
        IF NEW.previous_sealed <> '' AND
           (NEW.previous_expires_at IS NULL OR
            NEW.previous_expires_at > clock_timestamp() + INTERVAL '24 hours') THEN
            RAISE EXCEPTION 'inbound webhook key rotation overlap exceeds 24 hours';
        END IF;
        NEW.updated_at := clock_timestamp();
    ELSIF NEW.current_version <> OLD.current_version THEN
        RAISE EXCEPTION 'webhook key version cannot change without rotation';
    ELSIF NEW.previous_expires_at IS NOT NULL AND
           (OLD.previous_expires_at IS NULL OR NEW.previous_expires_at > OLD.previous_expires_at) THEN
        RAISE EXCEPTION 'webhook rotation overlap cannot be extended';
    END IF;
    RETURN NEW;
END;
$inbound_update_guard$;
-- +goose StatementEnd
CREATE TRIGGER inbound_webhook_update_guard
BEFORE UPDATE ON inbound_webhook_endpoints
FOR EACH ROW EXECUTE FUNCTION synapse_guard_inbound_webhook_update();
REVOKE ALL ON FUNCTION synapse_guard_inbound_webhook_update() FROM PUBLIC;

-- Global per-endpoint fixed-window admission is serialized by a row lock and
-- survives multiple API replicas. The expected tenant/owner/version must
-- match the earlier authentication snapshot: a replacement row, rotation or
-- revocation cannot be accepted by a stale reader.
-- +goose StatementBegin
CREATE FUNCTION synapse_admit_inbound_webhook(
    p_public_id TEXT, p_tenant_id TEXT, p_owner_kind TEXT, p_owner_id TEXT, p_version INT,
    p_used_previous BOOLEAN
) RETURNS INT
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $inbound_admit$
DECLARE
    e RECORD;
    now_at TIMESTAMPTZ := clock_timestamp();
BEGIN
    -- SECURITY DEFINER may be owned by a migration role that bypasses RLS.
    -- Bind the privileged mutation to the caller's tenant GUC explicitly,
    -- rather than relying on the function owner's RLS behavior.
    IF p_tenant_id IS NULL OR
       p_tenant_id IS DISTINCT FROM public.synapse_current_tenant() THEN
        RETURN -1;
    END IF;
    SELECT * INTO e FROM public.inbound_webhook_endpoints
     WHERE public_id = p_public_id FOR UPDATE;
    IF NOT FOUND THEN RETURN -1; END IF;
    IF e.tenant_id IS DISTINCT FROM p_tenant_id OR
       e.owner_kind IS DISTINCT FROM p_owner_kind OR
       e.owner_id IS DISTINCT FROM p_owner_id OR
       e.current_version IS DISTINCT FROM p_version OR
       NOT e.enabled OR e.revoked_at IS NOT NULL THEN
        RETURN -1;
    END IF;
    -- Defense in depth: the repository locks this owner row before calling
    -- admission, but the privileged function also refuses a disabled/archived
    -- integration if it is ever invoked directly. FORCE RLS on integrations
    -- requires the caller's transaction to be bound to the same tenant.
    IF NOT EXISTS (
        SELECT 1 FROM public.integrations i
         WHERE i.tenant_id = e.tenant_id AND i.id = e.owner_id
           AND i.enabled AND NOT i.archived
    ) THEN
        RETURN -1;
    END IF;
    -- A key may expire or be revoked between MAC verification and the locked
    -- admission: never admit a previous-key signature after its overlap ends.
    IF p_used_previous AND (e.previous_sealed = '' OR
        e.previous_expires_at IS NULL OR e.previous_expires_at <= now_at) THEN
        RETURN -1;
    END IF;
    IF e.window_started_at > now_at - INTERVAL '1 minute'
       AND e.window_count >= e.rate_per_minute THEN
        RETURN 0;
    END IF;
    UPDATE public.inbound_webhook_endpoints
       SET window_started_at = CASE WHEN e.window_started_at > now_at - INTERVAL '1 minute'
                                    THEN e.window_started_at ELSE now_at END,
           window_count = CASE WHEN e.window_started_at > now_at - INTERVAL '1 minute'
                               THEN e.window_count + 1 ELSE 1 END
     WHERE public_id = p_public_id;
    RETURN 1;
END;
$inbound_admit$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_lookup_inbound_webhook(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION synapse_admit_inbound_webhook(TEXT,TEXT,TEXT,TEXT,INT,BOOLEAN) FROM PUBLIC;
-- Production migrator grants EXECUTE on only these functions plus tenant-
-- scoped SELECT to the separate runtime role. Runtime direct DML is revoked;
-- without a bound tenant, even a direct SELECT returns zero rows.

-- +goose Down
DROP FUNCTION IF EXISTS synapse_admit_inbound_webhook(TEXT,TEXT,TEXT,TEXT,INT,BOOLEAN);
DROP TRIGGER IF EXISTS inbound_webhook_update_guard ON inbound_webhook_endpoints;
DROP FUNCTION IF EXISTS synapse_guard_inbound_webhook_update();
DROP FUNCTION IF EXISTS synapse_lookup_inbound_webhook(TEXT);
DROP TABLE inbound_webhook_endpoints;
