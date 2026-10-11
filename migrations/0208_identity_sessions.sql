-- +goose Up
-- Enterprise browser sessions retain only hashes. Switch recovery keeps a short authenticated-
-- encrypted response keyed by an exact idempotency locator and is invalidated by source revoke.
ALTER TABLE identity_sessions ADD COLUMN kind TEXT NOT NULL DEFAULT 'browser_session'
    CHECK (kind IN ('browser_session', 'break_glass'));
ALTER TABLE identity_sessions ADD COLUMN csrf_token_hash TEXT NOT NULL DEFAULT repeat('0', 64)
    CHECK (csrf_token_hash ~ '^[0-9a-f]{64}$');
CREATE INDEX identity_sessions_active_membership ON identity_sessions(tenant_id, membership_id)
    WHERE revoked_at IS NULL;

CREATE TABLE identity_session_switch_retries (
    retry_key TEXT PRIMARY KEY CHECK (length(retry_key) BETWEEN 1 AND 256),
    payload_hash TEXT NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
    tenant_id TEXT NOT NULL REFERENCES tenants(id) CHECK (tenant_id <> ''),
    source_credential_id TEXT NOT NULL,
    source_digest TEXT NOT NULL CHECK (source_digest ~ '^[0-9a-f]{64}$'),
    destination_tenant_id TEXT NOT NULL,
    destination_session_id TEXT NOT NULL,
    response_ciphertext TEXT NOT NULL CHECK (length(response_ciphertext) BETWEEN 1 AND 16384),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (expires_at > created_at),
    FOREIGN KEY (tenant_id, source_credential_id) REFERENCES identity_credentials(tenant_id, id),
    FOREIGN KEY (destination_tenant_id, destination_session_id) REFERENCES identity_sessions(tenant_id, id)
);
CALL synapse_enable_tenant_rls('identity_session_switch_retries');
CREATE INDEX identity_session_switch_retries_expiry ON identity_session_switch_retries(expires_at) WHERE revoked_at IS NULL;

-- The only global retry surface is a derived exact locator. It contains no response material,
-- principal, membership, or listable tenant data; FORCE RLS remains enabled on retry records.
CREATE TABLE identity_session_switch_retry_routes (
    source_digest TEXT NOT NULL CHECK (source_digest ~ '^[0-9a-f]{64}$'),
    retry_key TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    active BOOLEAN NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (source_digest, retry_key, payload_hash)
);
CALL synapse_enable_owner_only_rls('identity_session_switch_retry_routes');
-- +goose StatementBegin
CREATE FUNCTION synapse_identity_index_session_switch_retry()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $index$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM public.identity_session_switch_retry_routes
         WHERE source_digest=OLD.source_digest AND retry_key=OLD.retry_key AND payload_hash=OLD.payload_hash;
        RETURN OLD;
    END IF;
    INSERT INTO public.identity_session_switch_retry_routes(source_digest,retry_key,payload_hash,tenant_id,active,expires_at)
    VALUES(NEW.source_digest,NEW.retry_key,NEW.payload_hash,NEW.tenant_id,NEW.revoked_at IS NULL,NEW.expires_at)
    ON CONFLICT(source_digest,retry_key,payload_hash) DO UPDATE SET tenant_id=EXCLUDED.tenant_id,active=EXCLUDED.active,expires_at=EXCLUDED.expires_at;
    RETURN NEW;
END;
$index$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_index_session_switch_retry() FROM PUBLIC;
CREATE TRIGGER identity_session_switch_retries_route AFTER INSERT OR UPDATE OR DELETE ON identity_session_switch_retries
 FOR EACH ROW EXECUTE FUNCTION synapse_identity_index_session_switch_retry();

-- The locator exposes a tenant only after all three exact opaque values match. It enables a
-- response-loss retry after the source credential was terminally revoked without exposing a
-- principal, ciphertext, or list/prefix lookup.
-- +goose StatementBegin
CREATE FUNCTION synapse_identity_switch_retry_tenant(p_source_digest TEXT, p_retry_key TEXT, p_payload_hash TEXT)
RETURNS TEXT LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $locator$
 SELECT r.tenant_id FROM public.identity_session_switch_retry_routes r
 WHERE p_source_digest ~ '^[0-9a-f]{64}$' AND r.source_digest=p_source_digest
   AND r.retry_key=p_retry_key AND r.payload_hash=p_payload_hash AND r.active
 LIMIT 1
$locator$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_switch_retry_tenant(TEXT,TEXT,TEXT) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION synapse_identity_lock_person_epoch(p_digest TEXT,p_person_id TEXT)
RETURNS BIGINT LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $person_lock$
 SELECT p.epoch FROM public.identity_credential_digests d
 JOIN public.identity_persons p ON p.id=d.person_id AND p.state='active'
 WHERE p_digest ~ '^[0-9a-f]{64}$' AND d.digest=p_digest AND d.person_id=p_person_id
 LIMIT 1 FOR UPDATE OF p
$person_lock$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_lock_person_epoch(TEXT,TEXT) FROM PUBLIC;

-- +goose Down
-- The migration owner must see every tenant while checking destructive rollback.
-- Goose rolls back these DDL changes too if the guard refuses the migration.
ALTER TABLE identity_sessions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE identity_session_switch_retries NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM identity_sessions) OR EXISTS(SELECT 1 FROM identity_session_switch_retries) THEN
  RAISE EXCEPTION 'enterprise session data requires forward recovery; rollback is refused';
 END IF;
END;
$guard$;
-- +goose StatementEnd
DROP FUNCTION IF EXISTS synapse_identity_lock_person_epoch(TEXT,TEXT);
DROP FUNCTION IF EXISTS synapse_identity_switch_retry_tenant(TEXT,TEXT,TEXT);
DROP TABLE IF EXISTS identity_session_switch_retry_routes;
DROP TRIGGER IF EXISTS identity_session_switch_retries_route ON identity_session_switch_retries;
DROP FUNCTION IF EXISTS synapse_identity_index_session_switch_retry();
DROP TABLE IF EXISTS identity_session_switch_retries;
DROP INDEX IF EXISTS identity_sessions_active_membership;
ALTER TABLE identity_sessions DROP COLUMN IF EXISTS csrf_token_hash;
ALTER TABLE identity_sessions DROP COLUMN IF EXISTS kind;
ALTER TABLE identity_sessions FORCE ROW LEVEL SECURITY;
