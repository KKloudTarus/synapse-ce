-- +goose Up
-- These helpers are the only cross-tenant admission path. They derive the source tenant from an
-- exact credential digest, bind it only while inspecting that one source session, and restore the
-- caller's destination binding before returning.
-- +goose StatementBegin
CREATE FUNCTION synapse_identity_admission_source(p_digest TEXT,p_session_id TEXT,p_person_id TEXT,p_at TIMESTAMPTZ)
RETURNS TABLE(source_tenant TEXT,credential_id TEXT,lineage_id TEXT,origin_at TIMESTAMPTZ) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE source_tenant_id TEXT; destination_tenant TEXT; first_tenant TEXT; second_tenant TEXT; current_person_epoch BIGINT;
BEGIN
  IF p_digest !~ '^[0-9a-f]{64}$' OR p_session_id='' OR p_person_id='' OR p_at IS NULL THEN RETURN; END IF;
  destination_tenant:=current_setting('app.current_tenant',true);
  IF destination_tenant IS NULL OR destination_tenant='' THEN RETURN; END IF;
  SELECT d.tenant_id INTO source_tenant_id FROM public.identity_credential_digests d WHERE d.digest=p_digest AND d.person_id=p_person_id;
  IF source_tenant_id IS NULL THEN RETURN; END IF;
  first_tenant:=LEAST(source_tenant_id,destination_tenant); second_tenant:=GREATEST(source_tenant_id,destination_tenant);
  PERFORM set_config('app.current_tenant',first_tenant,true);
  PERFORM 1 FROM public.identity_policies WHERE tenant_id=first_tenant FOR UPDATE;
  IF NOT FOUND THEN PERFORM set_config('app.current_tenant',destination_tenant,true); RETURN; END IF;
  IF second_tenant<>first_tenant THEN
    PERFORM set_config('app.current_tenant',second_tenant,true);
    PERFORM 1 FROM public.identity_policies WHERE tenant_id=second_tenant FOR UPDATE;
    IF NOT FOUND THEN PERFORM set_config('app.current_tenant',destination_tenant,true); RETURN; END IF;
  END IF;
  PERFORM set_config('app.current_tenant',source_tenant_id,true);
  SELECT p.epoch INTO current_person_epoch FROM public.identity_persons p WHERE p.id=p_person_id AND p.state='active' FOR UPDATE;
  IF current_person_epoch IS NULL THEN PERFORM set_config('app.current_tenant',destination_tenant,true); RETURN; END IF;
  RETURN QUERY SELECT s.tenant_id,s.credential_id,s.lineage_id,s.origin_at
    FROM public.identity_sessions s
    JOIN public.identity_credentials c ON c.tenant_id=s.tenant_id AND c.id=s.credential_id AND c.digest=p_digest AND c.state='active'
    JOIN public.identity_memberships m ON m.tenant_id=s.tenant_id AND m.id=s.membership_id AND m.person_id=s.person_id AND m.state='active' AND m.epoch=s.membership_epoch
    JOIN public.identity_connections x ON x.tenant_id=s.tenant_id AND x.id=s.connection_id AND x.enabled AND x.epoch=s.connection_epoch
   WHERE s.tenant_id=source_tenant_id AND s.id=p_session_id AND s.person_id=p_person_id AND s.kind='browser_session'
     AND s.revoked_at IS NULL AND s.expires_at>p_at AND s.authenticated_at+interval '15 minutes'>p_at AND s.person_epoch=current_person_epoch
   FOR UPDATE OF s,c,m,x;
  PERFORM set_config('app.current_tenant',destination_tenant,true);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_admission_source(TEXT,TEXT,TEXT,TIMESTAMPTZ) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION synapse_identity_revoke_admission_source(p_digest TEXT,p_session_id TEXT,p_person_id TEXT,p_at TIMESTAMPTZ)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE source_tenant_id TEXT; destination_tenant TEXT; source_credential_id TEXT;
BEGIN
  destination_tenant:=current_setting('app.current_tenant',true);
  IF p_digest !~ '^[0-9a-f]{64}$' OR p_session_id='' OR p_person_id='' OR p_at IS NULL OR destination_tenant IS NULL OR destination_tenant='' THEN RETURN false; END IF;
  SELECT d.tenant_id INTO source_tenant_id FROM public.identity_credential_digests d WHERE d.digest=p_digest AND d.person_id=p_person_id;
  IF source_tenant_id IS NULL THEN RETURN false; END IF;
  PERFORM set_config('app.current_tenant',source_tenant_id,true);
  SELECT s.credential_id INTO source_credential_id FROM public.identity_sessions s
   JOIN public.identity_credentials c ON c.tenant_id=s.tenant_id AND c.id=s.credential_id AND c.digest=p_digest AND c.state='active'
   JOIN public.identity_memberships m ON m.tenant_id=s.tenant_id AND m.id=s.membership_id AND m.person_id=s.person_id AND m.state='active' AND m.epoch=s.membership_epoch
   JOIN public.identity_connections x ON x.tenant_id=s.tenant_id AND x.id=s.connection_id AND x.enabled AND x.epoch=s.connection_epoch
   JOIN public.identity_persons p ON p.id=s.person_id AND p.state='active' AND p.epoch=s.person_epoch
   WHERE s.tenant_id=source_tenant_id AND s.id=p_session_id AND s.person_id=p_person_id AND s.kind='browser_session' AND s.revoked_at IS NULL AND s.expires_at>p_at AND s.authenticated_at+interval '15 minutes'>p_at
   FOR UPDATE OF s,c,m,x;
  IF source_credential_id IS NULL THEN PERFORM set_config('app.current_tenant',destination_tenant,true); RETURN false; END IF;
  UPDATE public.identity_sessions SET revoked_at=p_at WHERE tenant_id=source_tenant_id AND id=p_session_id AND revoked_at IS NULL;
  UPDATE public.identity_credentials SET state='revoked',revoked_at=p_at,updated_at=p_at WHERE tenant_id=source_tenant_id AND id=source_credential_id AND state='active';
  PERFORM set_config('app.current_tenant',destination_tenant,true);
  RETURN true;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_revoke_admission_source(TEXT,TEXT,TEXT,TIMESTAMPTZ) FROM PUBLIC;

-- +goose Down
DROP FUNCTION synapse_identity_revoke_admission_source(TEXT,TEXT,TEXT,TIMESTAMPTZ);
DROP FUNCTION synapse_identity_admission_source(TEXT,TEXT,TEXT,TIMESTAMPTZ);
