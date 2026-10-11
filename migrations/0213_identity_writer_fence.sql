-- +goose Up
-- Native membership commands retain tenant-local compatibility user rows. Only narrowly
-- granted owner functions can write that projection after the legacy writer is retired.
-- +goose StatementBegin
CREATE FUNCTION synapse_identity_guard_legacy_user()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path=pg_catalog,public,pg_temp
AS $guard$
DECLARE
 target TEXT;
 prior TEXT;
 phase TEXT;
 owner_name TEXT;
BEGIN
 target:=COALESCE(NULLIF(CASE WHEN TG_OP='DELETE' THEN OLD.tenant_id ELSE NEW.tenant_id END,''),'default');
 IF TG_OP='UPDATE' THEN prior:=COALESCE(NULLIF(OLD.tenant_id,''),'default'); ELSE prior:=target; END IF;
 -- The deployment operator has no person or membership and remains independently managed.
 IF TG_OP<>'DELETE' AND NEW.id='operator' AND target='default' AND (TG_OP='INSERT' OR OLD.id='operator' AND prior='default') THEN RETURN NEW; END IF;
 SELECT pg_get_userbyid(p.proowner) INTO owner_name FROM pg_proc p
 WHERE p.oid='public.synapse_identity_project_member_user(text,text,text,text,text,timestamptz)'::regprocedure;
 -- SECURITY DEFINER projection inherits the migration owner's unspoofable execution role.
 -- Runtime identities are never members of that role. The guard itself remains INVOKER.
 IF current_user=owner_name THEN
  IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
 END IF;
 IF current_setting('app.current_tenant',true) IS DISTINCT FROM target OR prior<>target THEN
  RAISE EXCEPTION 'legacy user writer lacks tenant binding' USING ERRCODE='SYN01';
 END IF;
 SELECT cutover_phase INTO phase FROM public.identity_policies WHERE tenant_id=target FOR SHARE;
 IF phase='declared' THEN RAISE EXCEPTION 'legacy identity writer is retired' USING ERRCODE='SYN01'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$guard$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_guard_legacy_user() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION synapse_identity_project_member_user(p_tenant TEXT,p_id TEXT,p_name TEXT,p_role TEXT,p_unusable_hash TEXT,p_at TIMESTAMPTZ)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public,pg_temp
AS $project$
DECLARE phase TEXT;
BEGIN
 IF p_tenant IS DISTINCT FROM current_setting('app.current_tenant',true) OR p_id='operator' OR length(p_id)=0 OR length(p_name)=0 OR length(p_name)>256 OR p_role NOT IN ('admin','consultant','member','reviewer','readonly','integration_admin') OR p_unusable_hash !~ '^[0-9a-f]{64}$' OR p_at IS NULL THEN
  RAISE EXCEPTION 'invalid member user projection' USING ERRCODE='22023';
 END IF;
 SELECT cutover_phase INTO phase FROM public.identity_policies WHERE tenant_id=p_tenant FOR SHARE;
 IF phase IS DISTINCT FROM 'declared' THEN RAISE EXCEPTION 'member projection requires declared authority' USING ERRCODE='SYN01'; END IF;
 INSERT INTO public.users(id,name,role,api_key_hash,disabled,created_at,updated_at,tenant_id)
 VALUES(p_id,p_name,p_role,p_unusable_hash,false,p_at,p_at,p_tenant);
END;
$project$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_project_member_user(TEXT,TEXT,TEXT,TEXT,TEXT,TIMESTAMPTZ) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION synapse_identity_mirror_member_user(p_tenant TEXT,p_membership TEXT,p_at TIMESTAMPTZ)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public,pg_temp
AS $mirror$
DECLARE phase TEXT;
BEGIN
 IF p_tenant IS DISTINCT FROM current_setting('app.current_tenant',true) OR p_at IS NULL THEN RAISE EXCEPTION 'invalid member mirror binding' USING ERRCODE='22023'; END IF;
 SELECT cutover_phase INTO phase FROM public.identity_policies WHERE tenant_id=p_tenant FOR SHARE;
 IF phase IS DISTINCT FROM 'declared' THEN RAISE EXCEPTION 'member mirror requires declared authority' USING ERRCODE='SYN01'; END IF;
 UPDATE public.users u SET role=m.role,disabled=(m.state<>'active'),updated_at=p_at
 FROM public.identity_memberships m WHERE m.tenant_id=p_tenant AND m.id=p_membership
 AND u.ownership_tenant_id=m.tenant_id AND u.id=m.legacy_user_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'member user projection is missing' USING ERRCODE='P0002'; END IF;
END;
$mirror$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_mirror_member_user(TEXT,TEXT,TIMESTAMPTZ) FROM PUBLIC;
CREATE TRIGGER users_identity_writer_fence BEFORE INSERT OR UPDATE OR DELETE ON users
FOR EACH ROW EXECUTE FUNCTION synapse_identity_guard_legacy_user();

-- +goose Down
ALTER TABLE identity_cutover_ledger NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM identity_cutover_ledger WHERE action='declared') THEN
  RAISE EXCEPTION 'declared identity authority requires forward recovery; writer fence rollback refused';
 END IF;
END;
$guard$;
-- +goose StatementEnd
ALTER TABLE identity_cutover_ledger FORCE ROW LEVEL SECURITY;
DROP TRIGGER users_identity_writer_fence ON users;
DROP FUNCTION synapse_identity_guard_legacy_user();
DROP FUNCTION synapse_identity_project_member_user(TEXT,TEXT,TEXT,TEXT,TEXT,TIMESTAMPTZ);
DROP FUNCTION synapse_identity_mirror_member_user(TEXT,TEXT,TIMESTAMPTZ);
