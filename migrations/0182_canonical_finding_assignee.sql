-- +goose Up
-- Personal routing reads this reference, not the free-text label. Nullable is
-- essential for old rows with ambiguous or unmatched names.
ALTER TABLE findings ADD COLUMN assignee_user_id TEXT;
ALTER TABLE findings ADD CONSTRAINT findings_assignee_user_fk
 FOREIGN KEY (tenant_id,assignee_user_id) REFERENCES users(ownership_tenant_id,id);
CREATE INDEX findings_assignee_user ON findings(tenant_id,assignee_user_id,id) WHERE assignee_user_id IS NOT NULL;

CREATE TABLE finding_assignee_backfill_review (
 tenant_id TEXT NOT NULL,
 engagement_id TEXT NOT NULL,
 finding_id TEXT NOT NULL,
 legacy_assignee TEXT NOT NULL,
 reason TEXT NOT NULL CHECK(reason IN ('ambiguous','unmatched','legacy_label')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,engagement_id,finding_id),
 FOREIGN KEY(tenant_id,engagement_id,finding_id) REFERENCES findings(tenant_id,engagement_id,id) ON DELETE CASCADE
);
CALL synapse_enable_tenant_rls('finding_assignee_backfill_review');
CREATE INDEX finding_assignee_backfill_review_reason ON finding_assignee_backfill_review(tenant_id,reason,finding_id);

-- Findings and the review table both FORCE RLS, including against the migration
-- owner. Iterate explicit tenant scopes inside the goose transaction; a global
-- UPDATE would silently touch zero rows and falsely report a successful backfill.
-- +goose StatementBegin
DO $$
DECLARE current_tenant TEXT;
BEGIN
 FOR current_tenant IN SELECT id FROM tenants WHERE id<>'' LOOP
  PERFORM set_config('app.current_tenant',current_tenant,true);
  -- First, exact IDs already written by the ownership endpoint.
  UPDATE findings f SET assignee_user_id=u.id FROM users u
   WHERE f.tenant_id=current_tenant AND f.assignee<>''
    AND u.ownership_tenant_id=f.tenant_id AND u.id=f.assignee;
  -- Then only unique, case-sensitive names within this tenant. Preserve the
  -- legacy label and manual protection rather than rewriting it to an ID.
  WITH unique_names AS (
   SELECT name,min(id) AS user_id FROM users
   WHERE ownership_tenant_id=current_tenant GROUP BY name HAVING count(*)=1
  )
  UPDATE findings f SET assignee_user_id=n.user_id FROM unique_names n
   WHERE f.tenant_id=current_tenant AND f.assignee_user_id IS NULL
    AND f.assignee<>'' AND n.name=f.assignee;
  INSERT INTO finding_assignee_backfill_review(tenant_id,engagement_id,finding_id,legacy_assignee,reason)
   SELECT f.tenant_id,f.engagement_id,f.id,f.assignee,
    CASE WHEN EXISTS(SELECT 1 FROM users u WHERE u.ownership_tenant_id=f.tenant_id AND u.name=f.assignee)
    THEN 'ambiguous' ELSE 'unmatched' END
   FROM findings f WHERE f.tenant_id=current_tenant AND f.assignee<>'' AND f.assignee_user_id IS NULL;
 END LOOP;
 PERFORM set_config('app.current_tenant','',true);
END $$;
-- +goose StatementEnd

-- A rolling deployment may keep writing the legacy string. Changing it clears
-- an old canonical binding, or binds an exact enabled same-tenant user ID.
-- +goose StatementBegin
CREATE FUNCTION synapse_bridge_finding_assignee() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' OR NEW.assignee IS DISTINCT FROM OLD.assignee THEN
  NEW.assignee_user_id := (
   SELECT u.id FROM users u WHERE u.ownership_tenant_id=NEW.tenant_id
    AND u.id=NEW.assignee AND NOT u.disabled
    AND u.role IN ('admin','consultant','reviewer','member') LIMIT 1
  );
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER findings_assignee_identity_bridge BEFORE INSERT OR UPDATE OF assignee ON findings
 FOR EACH ROW EXECUTE FUNCTION synapse_bridge_finding_assignee();

-- Keep the bounded admin review queue accurate after old binaries change a
-- label or a triager resolves it to a canonical user.
-- +goose StatementBegin
CREATE FUNCTION synapse_track_assignee_review() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' AND NEW.assignee='' THEN RETURN NULL; END IF;
 IF NEW.assignee<>'' AND NEW.assignee_user_id IS NULL THEN
  INSERT INTO finding_assignee_backfill_review(tenant_id,engagement_id,finding_id,legacy_assignee,reason)
   VALUES(NEW.tenant_id,NEW.engagement_id,NEW.id,NEW.assignee,
    CASE WHEN (SELECT count(*) FROM users u WHERE u.ownership_tenant_id=NEW.tenant_id AND u.name=NEW.assignee)>1 THEN 'ambiguous'
    WHEN EXISTS(SELECT 1 FROM users u WHERE u.ownership_tenant_id=NEW.tenant_id AND u.name=NEW.assignee) THEN 'legacy_label'
    ELSE 'unmatched' END)
   ON CONFLICT(tenant_id,engagement_id,finding_id) DO UPDATE SET
    legacy_assignee=EXCLUDED.legacy_assignee,reason=EXCLUDED.reason,created_at=now();
 ELSE
  DELETE FROM finding_assignee_backfill_review
   WHERE tenant_id=NEW.tenant_id AND engagement_id=NEW.engagement_id AND finding_id=NEW.id;
 END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE TRIGGER findings_assignee_review_track AFTER INSERT OR UPDATE OF assignee,assignee_user_id ON findings
 FOR EACH ROW EXECUTE FUNCTION synapse_track_assignee_review();

-- +goose Down
DROP TRIGGER findings_assignee_review_track ON findings;
DROP FUNCTION synapse_track_assignee_review();
DROP TRIGGER findings_assignee_identity_bridge ON findings;
DROP FUNCTION synapse_bridge_finding_assignee();
DROP TABLE finding_assignee_backfill_review;
DROP INDEX findings_assignee_user;
ALTER TABLE findings DROP CONSTRAINT findings_assignee_user_fk;
ALTER TABLE findings DROP COLUMN assignee_user_id;
