-- +goose Up
-- Repair the closure trigger added in 0264 without rewriting an applied migration. Legacy
-- membership inserts have no provisioning operation to close and must not upgrade the policy
-- row after their compatibility projection already holds FOR SHARE.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION synapse_identity_close_initial_provisioning()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $close_initial_provisioning$
DECLARE
    close_at TIMESTAMPTZ := GREATEST(NEW.created_at, clock_timestamp());
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM public.identity_initial_provisioning
         WHERE tenant_id = NEW.tenant_id AND state <> 'closed'
    ) THEN
        RETURN NULL;
    END IF;
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

-- +goose Down
-- A populated provenance table must stay on the forward-fixed closure semantics.
ALTER TABLE identity_initial_provisioning NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM identity_initial_provisioning) THEN
        RAISE EXCEPTION 'initial identity provisioning closure requires a forward fix';
    END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE identity_initial_provisioning FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION synapse_identity_close_initial_provisioning()
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
