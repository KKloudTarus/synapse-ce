-- +goose Up
-- #1453. Append after the shipped identity 0218, scan engine outcomes 0219 and chat channels 0220.
-- Tenant-authorized endpoint lifecycle. Runtime direct DML remains revoked:
-- these SECURITY DEFINER functions bind every mutation to the caller's tenant
-- GUC and to an existing Bitbucket integration.
-- +goose StatementBegin
CREATE FUNCTION synapse_provision_bitbucket_inbound_webhook(
    p_tenant_id TEXT,
    p_public_id TEXT,
    p_owner_id TEXT,
    p_current_sealed TEXT,
    p_rate_per_minute INT
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $bitbucket_hook_provision$
DECLARE
    affected INT := 0;
BEGIN
    IF p_tenant_id IS NULL OR p_tenant_id IS DISTINCT FROM public.synapse_current_tenant() THEN
        RETURN FALSE;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.integrations i
        WHERE i.tenant_id = p_tenant_id AND i.id = p_owner_id
          AND i.provider = 'bitbucket' AND NOT i.archived
    ) THEN
        RETURN FALSE;
    END IF;
    INSERT INTO public.inbound_webhook_endpoints(
        public_id, tenant_id, owner_kind, owner_id, enabled,
        current_version, current_sealed, rate_per_minute
    ) VALUES (
        p_public_id, p_tenant_id, 'integration', p_owner_id, TRUE,
        1, p_current_sealed, p_rate_per_minute
    )
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS affected = ROW_COUNT;
    RETURN affected = 1;
END;
$bitbucket_hook_provision$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION synapse_rotate_bitbucket_inbound_webhook(
    p_tenant_id TEXT,
    p_public_id TEXT,
    p_owner_id TEXT,
    p_expected_version INT,
    p_current_sealed TEXT,
    p_previous_expires_at TIMESTAMPTZ
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $bitbucket_hook_rotate$
DECLARE
    affected INT := 0;
    now_at TIMESTAMPTZ := clock_timestamp();
BEGIN
    IF p_tenant_id IS NULL OR p_tenant_id IS DISTINCT FROM public.synapse_current_tenant() OR
       p_expected_version < 1 OR p_previous_expires_at <= now_at OR
       p_previous_expires_at > now_at + INTERVAL '24 hours' THEN
        RETURN FALSE;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.integrations i
        WHERE i.tenant_id = p_tenant_id AND i.id = p_owner_id
          AND i.provider = 'bitbucket' AND NOT i.archived
    ) THEN
        RETURN FALSE;
    END IF;
    UPDATE public.inbound_webhook_endpoints
       SET current_version = current_version + 1,
           previous_sealed = current_sealed,
           previous_expires_at = p_previous_expires_at,
           current_sealed = p_current_sealed,
           enabled = TRUE,
           window_started_at = '-infinity'::timestamptz,
           window_count = 0
     WHERE tenant_id = p_tenant_id
       AND public_id = p_public_id
       AND owner_kind = 'integration'
       AND owner_id = p_owner_id
       AND current_version = p_expected_version
       AND revoked_at IS NULL;
    GET DIAGNOSTICS affected = ROW_COUNT;
    RETURN affected = 1;
END;
$bitbucket_hook_rotate$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION synapse_provision_bitbucket_inbound_webhook(TEXT,TEXT,TEXT,TEXT,INT) FROM PUBLIC;
REVOKE ALL ON FUNCTION synapse_rotate_bitbucket_inbound_webhook(TEXT,TEXT,TEXT,INT,TEXT,TIMESTAMPTZ) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION synapse_lock_bitbucket_inbound_webhook(p_tenant_id TEXT, p_public_id TEXT, p_owner_id TEXT)
RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $bitbucket_lock$
DECLARE active BOOLEAN;
BEGIN
 IF p_tenant_id IS NULL OR p_tenant_id IS DISTINCT FROM public.synapse_current_tenant() THEN RETURN FALSE; END IF;
 SELECT TRUE INTO active FROM public.inbound_webhook_endpoints e
 JOIN public.integrations i ON i.tenant_id=e.tenant_id AND i.id=e.owner_id
 WHERE e.tenant_id=p_tenant_id AND e.public_id=p_public_id AND e.owner_kind='integration' AND e.owner_id=p_owner_id
 AND i.provider='bitbucket' AND i.enabled AND NOT i.archived AND e.enabled AND e.revoked_at IS NULL
 FOR SHARE OF e,i;
 RETURN COALESCE(active,FALSE);
END;
$bitbucket_lock$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_lock_bitbucket_inbound_webhook(TEXT,TEXT,TEXT) FROM PUBLIC;

-- +goose Down
DROP FUNCTION synapse_lock_bitbucket_inbound_webhook(TEXT,TEXT,TEXT);
DROP FUNCTION synapse_rotate_bitbucket_inbound_webhook(TEXT,TEXT,TEXT,INT,TEXT,TIMESTAMPTZ);
DROP FUNCTION synapse_provision_bitbucket_inbound_webhook(TEXT,TEXT,TEXT,TEXT,INT);
