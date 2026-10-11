-- +goose Up
ALTER TABLE identity_invitation_challenges DROP COLUMN challenge_sealed;

-- The invitation table is FORCE RLS, so global exact-code routing uses a deliberately minimal
-- owner-only index. It contains only the digest and the tenant-bound invitation identity.
CREATE TABLE identity_invitation_code_routes (
    code_digest TEXT PRIMARY KEY CHECK (code_digest ~ '^[0-9a-f]{64}$'),
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    invitation_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (tenant_id, invitation_id) REFERENCES identity_invitations(tenant_id, id)
);
CALL synapse_enable_owner_only_rls('identity_invitation_code_routes');
INSERT INTO identity_invitation_code_routes(code_digest,tenant_id,invitation_id,expires_at)
SELECT code_digest,tenant_id,id,expires_at FROM identity_invitations WHERE state='pending';

-- +goose StatementBegin
CREATE FUNCTION synapse_identity_index_invitation_route()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    DELETE FROM public.identity_invitation_code_routes WHERE code_digest=OLD.code_digest;
    RETURN OLD;
  END IF;
  IF NEW.state='pending' THEN
    INSERT INTO public.identity_invitation_code_routes(code_digest,tenant_id,invitation_id,expires_at)
    VALUES(NEW.code_digest,NEW.tenant_id,NEW.id,NEW.expires_at)
    ON CONFLICT(code_digest) DO UPDATE SET tenant_id=EXCLUDED.tenant_id,invitation_id=EXCLUDED.invitation_id,expires_at=EXCLUDED.expires_at;
  ELSE
    DELETE FROM public.identity_invitation_code_routes WHERE code_digest=NEW.code_digest;
  END IF;
  RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_index_invitation_route() FROM PUBLIC;
CREATE TRIGGER identity_invitations_route AFTER INSERT OR UPDATE OR DELETE ON identity_invitations
 FOR EACH ROW EXECUTE FUNCTION synapse_identity_index_invitation_route();

-- The exact code digest is globally unique. This owner-only locator reveals no invitation metadata.
-- +goose StatementBegin
CREATE FUNCTION synapse_identity_invitation_tenant(p_code_digest TEXT)
RETURNS TABLE(tenant_id TEXT, invitation_id TEXT) LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT r.tenant_id,r.invitation_id FROM public.identity_invitation_code_routes r
 WHERE p_code_digest ~ '^[0-9a-f]{64}$' AND r.code_digest=p_code_digest
   AND r.expires_at>clock_timestamp()
 LIMIT 1
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_invitation_tenant(TEXT) FROM PUBLIC;

-- +goose Down
DROP FUNCTION synapse_identity_invitation_tenant(TEXT);
DROP TRIGGER identity_invitations_route ON identity_invitations;
DROP FUNCTION synapse_identity_index_invitation_route();
DROP TABLE identity_invitation_code_routes;
ALTER TABLE identity_invitation_challenges ADD COLUMN challenge_sealed TEXT NOT NULL DEFAULT '' CHECK (length(challenge_sealed) <= 4096);
