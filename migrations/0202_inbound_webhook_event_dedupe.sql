-- +goose Up
-- #1451. Provider event IDs are claimed only after webhook authentication.
-- The composite endpoint key prevents a privileged row mix-up from attaching
-- an event claim to another tenant's opaque endpoint.
ALTER TABLE inbound_webhook_endpoints
    ADD CONSTRAINT inbound_webhook_tenant_public_unique UNIQUE (tenant_id, public_id),
    ADD CONSTRAINT inbound_webhook_owner_unique UNIQUE (tenant_id, owner_kind, owner_id);

CREATE TABLE inbound_webhook_events (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) CHECK (tenant_id <> ''),
    public_id TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    event_id TEXT NOT NULL CHECK (length(event_id) BETWEEN 1 AND 128),
    received_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, public_id, provider, event_id),
    CONSTRAINT inbound_webhook_event_endpoint_fk
        FOREIGN KEY (tenant_id, public_id)
        REFERENCES inbound_webhook_endpoints(tenant_id, public_id)
        ON DELETE CASCADE
);

CREATE INDEX inbound_webhook_events_received
    ON inbound_webhook_events (tenant_id, received_at DESC);

ALTER TABLE inbound_webhook_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE inbound_webhook_events FORCE ROW LEVEL SECURITY;
CREATE POLICY inbound_webhook_events_tenant_all ON inbound_webhook_events
    FOR ALL TO PUBLIC
    USING (tenant_id = synapse_current_tenant())
    WITH CHECK (tenant_id = synapse_current_tenant());

-- Tenant-authorized endpoint lifecycle. Runtime direct DML remains revoked:
-- these SECURITY DEFINER functions bind every mutation to the caller's tenant
-- GUC and to an existing GitHub integration.
-- +goose StatementBegin
CREATE FUNCTION synapse_provision_github_inbound_webhook(
    p_tenant_id TEXT,
    p_public_id TEXT,
    p_owner_id TEXT,
    p_current_sealed TEXT,
    p_rate_per_minute INT
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $github_hook_provision$
DECLARE
    affected INT := 0;
BEGIN
    IF p_tenant_id IS NULL OR p_tenant_id IS DISTINCT FROM public.synapse_current_tenant() THEN
        RETURN FALSE;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.integrations i
        WHERE i.tenant_id = p_tenant_id AND i.id = p_owner_id
          AND i.provider = 'github' AND NOT i.archived
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
$github_hook_provision$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION synapse_rotate_github_inbound_webhook(
    p_tenant_id TEXT,
    p_public_id TEXT,
    p_owner_id TEXT,
    p_expected_version INT,
    p_current_sealed TEXT,
    p_previous_expires_at TIMESTAMPTZ
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $github_hook_rotate$
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
          AND i.provider = 'github' AND NOT i.archived
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
$github_hook_rotate$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION synapse_provision_github_inbound_webhook(TEXT,TEXT,TEXT,TEXT,INT) FROM PUBLIC;
REVOKE ALL ON FUNCTION synapse_rotate_github_inbound_webhook(TEXT,TEXT,TEXT,INT,TEXT,TIMESTAMPTZ) FROM PUBLIC;

-- +goose Down
DROP FUNCTION IF EXISTS synapse_rotate_github_inbound_webhook(TEXT,TEXT,TEXT,INT,TEXT,TIMESTAMPTZ);
DROP FUNCTION IF EXISTS synapse_provision_github_inbound_webhook(TEXT,TEXT,TEXT,TEXT,INT);
DROP TABLE inbound_webhook_events;
ALTER TABLE inbound_webhook_endpoints
    DROP CONSTRAINT inbound_webhook_owner_unique,
    DROP CONSTRAINT inbound_webhook_tenant_public_unique;
