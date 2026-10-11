-- +goose Up
-- These indexes match the exact tenant-scoped locks used by logout and bounded retry cleanup.
CREATE INDEX identity_credentials_tenant_digest ON identity_credentials(tenant_id,digest);
CREATE INDEX identity_session_switch_retries_tenant_expiry_key
    ON identity_session_switch_retries(tenant_id,expires_at,retry_key);

-- Replay must know both organizations before it locks either policy row. The global route remains
-- exact-key only; it still contains no response material or principal data.
ALTER TABLE identity_session_switch_retry_routes ADD COLUMN destination_tenant_id TEXT;
-- Existing retry rows predate the destination locator. Goose runs this migration as the
-- non-superuser migration owner, so temporarily lift FORCE while the migration's exclusive DDL
-- lock permits the owner to backfill every tenant; the policy is restored before commit.
ALTER TABLE identity_session_switch_retries NO FORCE ROW LEVEL SECURITY;
ALTER TABLE identity_session_switch_retry_routes NO FORCE ROW LEVEL SECURITY;
UPDATE identity_session_switch_retry_routes route
SET destination_tenant_id=retry.destination_tenant_id
FROM identity_session_switch_retries retry
WHERE route.source_digest=retry.source_digest
  AND route.retry_key=retry.retry_key
  AND route.payload_hash=retry.payload_hash;
ALTER TABLE identity_session_switch_retry_routes FORCE ROW LEVEL SECURITY;
ALTER TABLE identity_session_switch_retries FORCE ROW LEVEL SECURITY;

-- +goose StatementBegin
CREATE FUNCTION synapse_identity_index_session_switch_retry_destination()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $destination_route$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    UPDATE public.identity_session_switch_retry_routes
       SET destination_tenant_id=NEW.destination_tenant_id
     WHERE source_digest=NEW.source_digest AND retry_key=NEW.retry_key AND payload_hash=NEW.payload_hash;
    RETURN NEW;
END;
$destination_route$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_index_session_switch_retry_destination() FROM PUBLIC;
-- PostgreSQL executes same-event triggers alphabetically. The zz prefix ensures the route exists
-- before this trigger fills the destination added by this migration.
CREATE TRIGGER identity_session_switch_retries_zz_destination_route
AFTER INSERT OR UPDATE ON identity_session_switch_retries
FOR EACH ROW EXECUTE FUNCTION synapse_identity_index_session_switch_retry_destination();

-- +goose StatementBegin
CREATE FUNCTION synapse_identity_switch_retry_destination_tenant(p_source_digest TEXT, p_retry_key TEXT, p_payload_hash TEXT)
RETURNS TEXT LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $locator$
 SELECT r.destination_tenant_id FROM public.identity_session_switch_retry_routes r
 WHERE p_source_digest ~ '^[0-9a-f]{64}$' AND r.source_digest=p_source_digest
   AND r.retry_key=p_retry_key AND r.payload_hash=p_payload_hash AND r.active
 LIMIT 1
$locator$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_switch_retry_destination_tenant(TEXT,TEXT,TEXT) FROM PUBLIC;

-- +goose Down
DROP FUNCTION IF EXISTS synapse_identity_switch_retry_destination_tenant(TEXT,TEXT,TEXT);
DROP TRIGGER IF EXISTS identity_session_switch_retries_zz_destination_route ON identity_session_switch_retries;
DROP FUNCTION IF EXISTS synapse_identity_index_session_switch_retry_destination();
ALTER TABLE identity_session_switch_retry_routes DROP COLUMN IF EXISTS destination_tenant_id;
DROP INDEX IF EXISTS identity_session_switch_retries_tenant_expiry_key;
DROP INDEX IF EXISTS identity_credentials_tenant_digest;
