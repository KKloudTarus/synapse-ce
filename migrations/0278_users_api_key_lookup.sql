-- +goose Up
-- Expand release for users row-level security (#1697). Every users query binds a tenant except the
-- authentication lookup, which cannot: the tenant is unknown until the presented key resolves. Under
-- a tenant policy that lookup would see nothing, so it moves behind this function, which runs as the
-- table owner. The contract release enables forced RLS on users with a tenant policy on
-- ownership_tenant_id and an owner policy for this function; this release only adds the function, so
-- a binary from before it keeps working.
--
-- The function answers one question, by exact digest, and returns the one row that matches. The key
-- is the SHA-256 digest of a 192-bit random secret, so the argument cannot be enumerated.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION synapse_user_by_api_key_hash(p_hash TEXT)
RETURNS TABLE (id TEXT, name TEXT, role TEXT, api_key_hash TEXT, disabled BOOLEAN,
               created_at TIMESTAMPTZ, updated_at TIMESTAMPTZ, tenant_id TEXT)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    -- plpgsql, not sql: a SECURITY DEFINER sql function is not inlined and is planned on every call,
    -- and this runs on every authenticated request (measured 107-150 µs against 48 µs).
    IF p_hash IS NULL OR p_hash = '' THEN
        RETURN;
    END IF;
    RETURN QUERY
        SELECT u.id, u.name, u.role, u.api_key_hash, u.disabled, u.created_at, u.updated_at, u.tenant_id
          FROM public.users u
         WHERE u.api_key_hash = p_hash;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_user_by_api_key_hash(TEXT) FROM PUBLIC;

-- +goose Down
DROP FUNCTION IF EXISTS synapse_user_by_api_key_hash(TEXT);
