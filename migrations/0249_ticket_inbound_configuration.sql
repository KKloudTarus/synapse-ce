-- +goose Up
CREATE TABLE ticket_inbound_config (
 tenant_id TEXT NOT NULL REFERENCES tenants(id),
 integration_id TEXT NOT NULL,
 enabled BOOLEAN NOT NULL DEFAULT FALSE,
 integration_author TEXT NOT NULL CHECK (length(integration_author) BETWEEN 1 AND 255),
 connection_revision INT NOT NULL CHECK (connection_revision>0),
 credential_revision INT NOT NULL CHECK (credential_revision>=0),
 version INT NOT NULL CHECK (version>0),
 updated_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY(tenant_id,integration_id),
 FOREIGN KEY(tenant_id,integration_id) REFERENCES integrations(tenant_id,id)
);
CALL synapse_enable_tenant_rls('ticket_inbound_config');

-- +goose StatementBegin
CREATE FUNCTION synapse_provision_jira_inbound_webhook(
    p_tenant_id TEXT,
    p_public_id TEXT,
    p_owner_id TEXT,
    p_current_sealed TEXT,
    p_rate_per_minute INT
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $jira_hook_provision$
DECLARE
    affected INT := 0;
BEGIN
    IF p_tenant_id IS NULL OR p_tenant_id IS DISTINCT FROM public.synapse_current_tenant() THEN
        RETURN FALSE;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.integrations i
        WHERE i.tenant_id = p_tenant_id AND i.id = p_owner_id
          AND i.provider IN ('jira-cloud','jira-dc') AND i.enabled AND NOT i.archived
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
$jira_hook_provision$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION synapse_rotate_jira_inbound_webhook(
    p_tenant_id TEXT,
    p_public_id TEXT,
    p_owner_id TEXT,
    p_expected_version INT,
    p_current_sealed TEXT,
    p_previous_expires_at TIMESTAMPTZ
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $jira_hook_rotate$
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
          AND i.provider IN ('jira-cloud','jira-dc') AND i.enabled AND NOT i.archived
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
$jira_hook_rotate$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION synapse_provision_jira_inbound_webhook(TEXT,TEXT,TEXT,TEXT,INT) FROM PUBLIC;
REVOKE ALL ON FUNCTION synapse_rotate_jira_inbound_webhook(TEXT,TEXT,TEXT,INT,TEXT,TIMESTAMPTZ) FROM PUBLIC;


-- +goose Down
LOCK TABLE ticket_inbound_config IN ACCESS EXCLUSIVE MODE;
ALTER TABLE ticket_inbound_config NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM ticket_inbound_config) THEN
   RAISE EXCEPTION 'cannot roll back Jira inbound configuration while data exists' USING ERRCODE='55000';
 END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE ticket_inbound_config FORCE ROW LEVEL SECURITY;
DROP FUNCTION synapse_rotate_jira_inbound_webhook(TEXT,TEXT,TEXT,INT,TEXT,TIMESTAMPTZ);
DROP FUNCTION synapse_provision_jira_inbound_webhook(TEXT,TEXT,TEXT,TEXT,INT);
DROP TABLE ticket_inbound_config;
