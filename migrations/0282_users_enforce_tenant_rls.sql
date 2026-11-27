-- +goose Up
-- Contract release for users (#1697). 0278 moved the API-key lookup behind an owner function, and every
-- other users statement in v0.3.0 binds a tenant, so this release enables forced row-level security.
--
-- The tenant policy keys on ownership_tenant_id, the generated column every ownership foreign key already
-- references: default-tenant users are stored with tenant_id '' (which the tenant policy reads as DENY)
-- and resolve to 'default' there, so no backfill of tenant_id is needed.
--
-- Some reads must cross tenants: the authentication lookup (synapse_user_by_api_key_hash, 0278), the
-- identity projection writer (synapse_identity_project_member_user, 0213), and the identity backfill's
-- API-key uniqueness count (below). They are SECURITY DEFINER functions owned by the migration owner, and
-- forced RLS applies to the owner too, so a second policy lets the table owner through. The runtime role
-- never owns an RLS table (CheckRLSRuntimeRole refuses one that does), so that policy never applies to it.
-- The runtime role needs EXECUTE on the new count function: synapse-migrate and synapse-api grant it after
-- migrating; run one of them before the identity backfill when the worker applied this migration.
SET LOCAL lock_timeout = '5s';

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION synapse_users_api_key_hash_counts(p_hashes TEXT[])
RETURNS TABLE (api_key_hash TEXT, holders BIGINT)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    -- users.api_key_hash is unique across every tenant. The identity backfill checks that the digests it
    -- is about to move are held by exactly one row anywhere; it sees only its own tenant's rows, so the
    -- count runs as the owner. It answers for exact digests the caller already holds and returns counts
    -- only, never another tenant's row.
    SELECT u.api_key_hash, count(*)
      FROM public.users u
     WHERE u.api_key_hash = ANY(p_hashes)
     GROUP BY u.api_key_hash;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_users_api_key_hash_counts(TEXT[]) FROM PUBLIC;

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
CREATE POLICY users_tenant_isolation ON users
    USING (ownership_tenant_id = synapse_current_tenant())
    WITH CHECK (ownership_tenant_id = synapse_current_tenant());
-- The owner policy names the table's current owner rather than the role that ran this migration, so a
-- later change of owner (REASSIGN OWNED) moves the definer functions and this policy together.
CREATE POLICY users_owner_definer ON users
    USING (current_user = pg_catalog.pg_get_userbyid((SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid = 'public.users'::regclass)))
    WITH CHECK (current_user = pg_catalog.pg_get_userbyid((SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid = 'public.users'::regclass)));

-- +goose Down
SET LOCAL lock_timeout = '5s';
DROP POLICY IF EXISTS users_owner_definer ON users;
DROP POLICY IF EXISTS users_tenant_isolation ON users;
ALTER TABLE users NO FORCE ROW LEVEL SECURITY;
ALTER TABLE users DISABLE ROW LEVEL SECURITY;
DROP FUNCTION IF EXISTS synapse_users_api_key_hash_counts(TEXT[]);
