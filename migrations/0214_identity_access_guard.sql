-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION synapse_identity_usable_admin_access(requested_tenant TEXT, excluded_connection TEXT, at_time TIMESTAMPTZ)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
DECLARE candidate RECORD;
BEGIN
  IF requested_tenant IS NULL OR requested_tenant='' OR requested_tenant IS DISTINCT FROM current_setting('app.current_tenant',true) THEN
    RAISE EXCEPTION 'identity access guard requires bound tenant' USING ERRCODE='42501';
  END IF;
  FOR candidate IN
    SELECT m.id FROM identity_memberships m
    JOIN identity_persons p ON p.id=m.person_id AND p.state='active'
    JOIN identity_authenticators a ON a.tenant_id=m.tenant_id AND a.membership_id=m.id AND a.person_id=m.person_id AND a.state='approved'
    JOIN identity_connections c ON c.tenant_id=a.tenant_id AND c.id=a.connection_id AND c.enabled
    WHERE m.tenant_id=requested_tenant AND m.state='active' AND m.role='admin'
      AND (excluded_connection IS NULL OR c.id<>excluded_connection)
      AND COALESCE((SELECT t.state='passed' FROM identity_connection_tests t WHERE t.tenant_id=c.tenant_id AND t.connection_id=c.id AND t.revision=c.revision ORDER BY t.tested_at DESC,t.id DESC LIMIT 1),false)
    ORDER BY m.person_id,m.id,c.id,a.id
    FOR SHARE OF m,p,a,c
  LOOP
    RETURN true;
  END LOOP;
  RETURN false;
END $$;
REVOKE ALL ON FUNCTION synapse_identity_usable_admin_access(TEXT,TEXT,TIMESTAMPTZ) FROM PUBLIC;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION synapse_identity_usable_admin_access(TEXT,TEXT,TIMESTAMPTZ);
