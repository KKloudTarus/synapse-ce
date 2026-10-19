-- +goose Up
-- An unbound runtime session receives a boolean refusal, never SQL NULL.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION synapse_can_release_document(p_tenant TEXT,p_actor TEXT,p_membership TEXT,p_person TEXT)
RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $authority$
 SELECT COALESCE((p_tenant <> '' AND p_tenant = public.synapse_current_tenant() AND p_actor <> '' AND
 CASE WHEN EXISTS(SELECT 1 FROM public.identity_cutover_ledger l WHERE l.tenant_id=p_tenant AND l.action IN ('declared','contracted'))
 OR EXISTS(SELECT 1 FROM public.identity_policies i WHERE i.tenant_id=p_tenant AND i.cutover_phase='declared') THEN
 EXISTS(SELECT 1 FROM public.identity_memberships m JOIN public.identity_persons p ON p.id=m.person_id
 WHERE m.tenant_id=p_tenant AND m.id=p_membership AND m.person_id=p_person
 AND COALESCE(m.legacy_user_id,m.id)=p_actor AND m.state='active' AND p.state='active' AND m.role IN ('admin','reviewer'))
 ELSE EXISTS(SELECT 1 FROM public.users u WHERE COALESCE(NULLIF(u.tenant_id,''),'default')=p_tenant AND u.id=p_actor
 AND NOT u.disabled AND u.role IN ('admin','reviewer')) END), false)
$authority$;
-- +goose StatementEnd

-- +goose Down
-- Keep the fail-closed boolean contract when rolling application binaries back.
SELECT 1;
