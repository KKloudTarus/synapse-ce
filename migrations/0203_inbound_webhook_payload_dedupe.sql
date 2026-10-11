-- +goose Up
-- Only signed body bytes are trusted for replay protection. A provider delivery
-- header can change without invalidating the HMAC. Null preserves legacy rows.
ALTER TABLE inbound_webhook_events ADD COLUMN payload_sha256 TEXT
    CHECK (payload_sha256 IS NULL OR payload_sha256 ~ '^[0-9a-f]{64}$');
CREATE UNIQUE INDEX inbound_webhook_events_payload_unique
    ON inbound_webhook_events(tenant_id,public_id,provider,payload_sha256)
    WHERE payload_sha256 IS NOT NULL;

-- Runtime endpoint DML remains revoked. Locking the authenticated endpoint
-- until enqueue commits therefore uses a narrow, tenant-bound definer function.
-- +goose StatementBegin
CREATE FUNCTION synapse_lock_inbound_webhook_event(
    p_tenant_id TEXT, p_public_id TEXT, p_owner_kind TEXT,
    p_owner_id TEXT, p_provider TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $lock_event$
DECLARE active BOOLEAN;
BEGIN
    IF p_tenant_id IS NULL OR p_tenant_id IS DISTINCT FROM public.synapse_current_tenant()
       OR p_owner_kind IS DISTINCT FROM 'integration' THEN
        RETURN FALSE;
    END IF;
    SELECT e.enabled AND e.revoked_at IS NULL AND i.enabled AND NOT i.archived
      INTO active
      FROM public.inbound_webhook_endpoints e
      JOIN public.integrations i ON i.tenant_id=e.tenant_id AND i.id=e.owner_id
     WHERE e.tenant_id=p_tenant_id AND e.public_id=p_public_id
       AND e.owner_kind=p_owner_kind AND e.owner_id=p_owner_id AND i.provider=p_provider
     FOR SHARE OF e,i;
    RETURN COALESCE(active,FALSE);
END;
$lock_event$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_lock_inbound_webhook_event(TEXT,TEXT,TEXT,TEXT,TEXT) FROM PUBLIC;

-- +goose Down
DROP FUNCTION synapse_lock_inbound_webhook_event(TEXT,TEXT,TEXT,TEXT,TEXT);
DROP INDEX inbound_webhook_events_payload_unique;
ALTER TABLE inbound_webhook_events DROP COLUMN payload_sha256;
