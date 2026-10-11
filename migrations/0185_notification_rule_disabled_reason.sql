-- +goose Up
-- quality_gate.failed and fleet.agent.offline events never carry an engagement, so a rule scoped
-- to engagements for either type could never match (EPIC #1327 B.3). The EventSpec catalog now
-- rejects such rules on save. Disable the ones already stored and record why, keeping their
-- engagement list so an administrator can see what was intended before re-enabling.
ALTER TABLE notification_rules ADD COLUMN disabled_reason TEXT NOT NULL DEFAULT '';

-- Migrations run as the table owner with no app.current_tenant set, and notification_rules has
-- FORCE ROW LEVEL SECURITY, so the update would silently touch nothing. Lift FORCE for this
-- transaction and restore it in the same block; a failure rolls both back (the 0129 pattern).
-- +goose StatementBegin
DO $$
BEGIN
    EXECUTE 'ALTER TABLE notification_rules NO FORCE ROW LEVEL SECURITY';
    UPDATE notification_rules
       SET enabled = false,
           disabled_reason = 'engagement_filter_unsupported',
           revision = revision + 1,
           updated_at = now()
     WHERE event_type IN ('quality_gate.failed', 'fleet.agent.offline')
       AND jsonb_array_length(engagement_ids) > 0;
    EXECUTE 'ALTER TABLE notification_rules FORCE ROW LEVEL SECURITY';
END $$;
-- +goose StatementEnd

-- +goose Down
-- Disabled rules stay disabled; their engagement lists were never removed.
ALTER TABLE notification_rules DROP COLUMN disabled_reason;
