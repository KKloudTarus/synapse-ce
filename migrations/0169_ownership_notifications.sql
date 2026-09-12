-- +goose Up
-- Extend the shipped notification framework without rewriting migration 0163.
ALTER TABLE notification_rules DROP CONSTRAINT notification_rules_event_type_check;
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_event_type_check
    CHECK (event_type IN ('vulnerability_action.created','scan.completed','quality_gate.failed',
    'sla.approaching_deadline','fleet.agent.offline','incident.created','finding.ownership_changed'));
ALTER TABLE notification_rules ADD COLUMN all_teams BOOLEAN NOT NULL DEFAULT false
    CHECK (NOT all_teams OR event_type = 'finding.ownership_changed');

CREATE TABLE notification_rule_teams (
    tenant_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id,rule_id,team_id),
    FOREIGN KEY (tenant_id,rule_id) REFERENCES notification_rules(tenant_id,id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,team_id) REFERENCES ownership_teams(tenant_id,id)
);
CREATE INDEX notification_rule_teams_team ON notification_rule_teams(tenant_id,team_id,rule_id);
CALL synapse_enable_tenant_rls('notification_rule_teams');

-- +goose Down
-- Refuse to discard subscriptions silently during downgrade. Delete the
-- new rules explicitly before rolling back; immutable event/delivery history stays.
ALTER TABLE notification_rules DROP CONSTRAINT notification_rules_event_type_check;
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_event_type_check
    CHECK (event_type IN ('vulnerability_action.created','scan.completed','quality_gate.failed',
    'sla.approaching_deadline','fleet.agent.offline','incident.created'));
DROP TABLE notification_rule_teams;
ALTER TABLE notification_rules DROP COLUMN all_teams;
