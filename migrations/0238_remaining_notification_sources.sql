-- +goose Up
CREATE INDEX idx_engagement_notification_window_start ON engagements(tenant_id,authorized_from,id)
 WHERE project_id IS NULL AND host_asset_id IS NULL AND status IN ('draft','active') AND authorized_from IS NOT NULL;
CREATE INDEX idx_engagement_notification_window_end ON engagements(tenant_id,authorized_to,id)
 WHERE project_id IS NULL AND host_asset_id IS NULL AND status IN ('draft','active') AND authorized_to IS NOT NULL;

ALTER TABLE notification_rules DROP CONSTRAINT notification_rules_recipient_roles_check;
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_recipient_roles_check CHECK (
 jsonb_typeof(recipient_roles)='array' AND recipient_roles <@ '["assignee","team_member","engagement_lead","mentioned_user","approver"]'::jsonb
);

ALTER TABLE user_notifications ADD COLUMN recipient_roles JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (
 jsonb_typeof(recipient_roles)='array' AND recipient_roles <@ '["assignee","team_member","engagement_lead","mentioned_user","approver","tenant_admin"]'::jsonb
);

-- +goose StatementBegin
CREATE FUNCTION user_notification_recipient_roles_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.recipient_roles IS DISTINCT FROM OLD.recipient_roles THEN
  RAISE EXCEPTION 'personal notification recipient roles are immutable' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER user_notification_recipient_roles_immutable BEFORE UPDATE ON user_notifications
 FOR EACH ROW EXECUTE FUNCTION user_notification_recipient_roles_guard();

ALTER TABLE finding_comments ADD CONSTRAINT finding_comments_tenant_identity UNIQUE(tenant_id,id);
CREATE TABLE finding_comment_mentions (
 tenant_id TEXT NOT NULL REFERENCES tenants(id),
 comment_id TEXT NOT NULL,
 user_id TEXT NOT NULL,
 PRIMARY KEY(tenant_id,comment_id,user_id),
 FOREIGN KEY(tenant_id,comment_id) REFERENCES finding_comments(tenant_id,id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES users(ownership_tenant_id,id)
);
CALL synapse_enable_tenant_rls('finding_comment_mentions');

-- +goose StatementBegin
CREATE FUNCTION finding_comment_mentions_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP <> 'INSERT' THEN
  RAISE EXCEPTION 'comment mentions are immutable' USING ERRCODE='55000';
 END IF;
 PERFORM id FROM finding_comments WHERE tenant_id=NEW.tenant_id AND id=NEW.comment_id FOR UPDATE;
 IF EXISTS(SELECT 1 FROM finding_comment_mentions WHERE tenant_id=NEW.tenant_id AND comment_id=NEW.comment_id AND user_id=NEW.user_id) THEN RETURN NEW; END IF;
 IF (SELECT count(*) FROM finding_comment_mentions WHERE tenant_id=NEW.tenant_id AND comment_id=NEW.comment_id)>=10 THEN
  RAISE EXCEPTION 'comment mention limit exceeded' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER finding_comment_mentions_immutable BEFORE INSERT OR UPDATE OR DELETE ON finding_comment_mentions
 FOR EACH ROW EXECUTE FUNCTION finding_comment_mentions_guard();

CREATE TABLE notification_approval_recipients (
 tenant_id TEXT NOT NULL REFERENCES tenants(id),
 source_kind TEXT NOT NULL,
 source_id TEXT NOT NULL,
 user_id TEXT NOT NULL,
 PRIMARY KEY(tenant_id,source_kind,source_id,user_id),
 FOREIGN KEY(tenant_id,source_kind,source_id) REFERENCES notification_source_records(tenant_id,source_kind,source_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES users(ownership_tenant_id,id)
);
CALL synapse_enable_tenant_rls('notification_approval_recipients');

-- +goose StatementBegin
CREATE FUNCTION notification_approval_recipients_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE expected_count INTEGER;
DECLARE current_count INTEGER;
BEGIN
 IF TG_OP <> 'INSERT' THEN
  RAISE EXCEPTION 'approval notification recipients are immutable' USING ERRCODE='55000';
 END IF;
 SELECT (data->>'approver_count')::INTEGER INTO expected_count
  FROM notification_source_records
  WHERE tenant_id=NEW.tenant_id AND source_kind=NEW.source_kind AND source_id=NEW.source_id
   AND event_type IN ('approval.requested','approval.decided','approval.timed_out')
  FOR UPDATE;
 IF expected_count IS NULL OR expected_count<0 THEN
  RAISE EXCEPTION 'approval notification recipient snapshot count is required' USING ERRCODE='23514';
 END IF;
 SELECT count(*) INTO current_count FROM notification_approval_recipients
  WHERE tenant_id=NEW.tenant_id AND source_kind=NEW.source_kind AND source_id=NEW.source_id;
 IF current_count>=expected_count THEN
  RAISE EXCEPTION 'approval notification recipient snapshot is complete' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER notification_approval_recipients_immutable BEFORE INSERT OR UPDATE OR DELETE ON notification_approval_recipients
 FOR EACH ROW EXECUTE FUNCTION notification_approval_recipients_guard();

-- +goose Down
-- +goose StatementBegin
-- Freeze guarded writers before checking; a concurrent commit must be visible
-- to the refusal guard before any immutable relation or column is removed.
LOCK TABLE tenants, finding_comments, notification_source_records,
 notification_events, notification_rules, notification_deliveries, user_notifications,
 finding_comment_mentions, notification_approval_recipients IN ACCESS EXCLUSIVE MODE;
DO $$
DECLARE tenant_row RECORD;
BEGIN
 FOR tenant_row IN SELECT id FROM tenants WHERE id<>'' LOOP
  PERFORM set_config('app.current_tenant',tenant_row.id,true);
  IF EXISTS(SELECT 1 FROM finding_comment_mentions WHERE tenant_id=tenant_row.id) OR
     EXISTS(SELECT 1 FROM notification_approval_recipients WHERE tenant_id=tenant_row.id) OR
     EXISTS(SELECT 1 FROM notification_rules WHERE tenant_id=tenant_row.id AND recipient_roles ?| ARRAY['mentioned_user','approver']) OR
     EXISTS(SELECT 1 FROM user_notifications WHERE tenant_id=tenant_row.id AND recipient_roles<>'[]'::jsonb AND event_type IN ('engagement.created','engagement.status_changed','engagement.window_starting','engagement.window_ending','finding.commented','finding.mentioned','approval.requested','approval.decided','approval.timed_out','incident.updated','response.finished','evidence.chain_broken')) OR
     EXISTS(SELECT 1 FROM notification_deliveries d JOIN notification_events e ON e.tenant_id=d.tenant_id AND e.id=d.event_id WHERE d.tenant_id=tenant_row.id AND d.state IN ('pending','retrying') AND e.event_type IN ('engagement.created','engagement.status_changed','engagement.window_starting','engagement.window_ending','finding.commented','finding.mentioned','approval.requested','approval.decided','approval.timed_out','incident.updated','response.finished','evidence.chain_broken')) OR
     EXISTS(SELECT 1 FROM notification_source_records WHERE tenant_id=tenant_row.id AND processed_at IS NULL AND event_type IN (
      'engagement.created','engagement.status_changed','engagement.window_starting','engagement.window_ending',
      'finding.commented','finding.mentioned','approval.requested','approval.decided','approval.timed_out',
      'incident.updated','response.finished','evidence.chain_broken')) THEN
   RAISE EXCEPTION 'retain migration until remaining event captures, role rules and immutable mentions are drained' USING ERRCODE='55000';
  END IF;
 END LOOP;
END;
$$;
-- +goose StatementEnd
DROP TRIGGER user_notification_recipient_roles_immutable ON user_notifications;
DROP FUNCTION user_notification_recipient_roles_guard();
ALTER TABLE user_notifications DROP COLUMN recipient_roles;
DROP TRIGGER notification_approval_recipients_immutable ON notification_approval_recipients;
DROP FUNCTION notification_approval_recipients_guard();
DROP TABLE notification_approval_recipients;
DROP TABLE finding_comment_mentions;
DROP FUNCTION finding_comment_mentions_guard();
ALTER TABLE finding_comments DROP CONSTRAINT finding_comments_tenant_identity;
ALTER TABLE notification_rules DROP CONSTRAINT notification_rules_recipient_roles_check;
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_recipient_roles_check CHECK (
 jsonb_typeof(recipient_roles)='array' AND recipient_roles <@ '["assignee","team_member","engagement_lead"]'::jsonb
);
DROP INDEX idx_engagement_notification_window_end;
DROP INDEX idx_engagement_notification_window_start;
