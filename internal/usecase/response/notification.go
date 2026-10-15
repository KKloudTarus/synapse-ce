package response

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// transitionWithAuditAndNotification keeps the response projection, its durable
// audit obligation, and the v3 source snapshot in one short tenant transaction.
// Callers deliver the audit obligation after this function returns so external
// audit delivery never holds an execution or database transaction open.
func (s *Service) transitionWithAuditAndNotification(ctx context.Context, record Record, from State, intent ports.ResponseAuditIntent, outcome, actor string) (bool, ports.ResponseAuditIntent, error) {
	if s.notifications == nil {
		return s.store.TransitionWithAudit(ctx, record, from, intent)
	}
	if record.TenantID.IsZero() || record.EngagementID.IsZero() {
		return false, ports.ResponseAuditIntent{}, fmt.Errorf("%w: response notification requires tenant and engagement", shared.ErrValidation)
	}
	var (
		transitioned bool
		committed    ports.ResponseAuditIntent
	)
	err := s.notificationTx.Run(ctx, record.TenantID, func(txCtx context.Context) error {
		var err error
		transitioned, committed, err = s.store.TransitionWithAudit(txCtx, record, from, intent)
		if err != nil || !transitioned {
			return err
		}
		return s.appendResponseFinished(txCtx, record, outcome, actor)
	})
	return transitioned, committed, err
}

func (s *Service) appendResponseFinished(ctx context.Context, record Record, outcome, actor string) error {
	if !isResponseFinishedOutcome(outcome) {
		return nil
	}
	facts, err := s.notificationFacts.SnapshotNotificationLifecycleFacts(ctx, record.TenantID, record.EngagementID, actor)
	if err != nil {
		return fmt.Errorf("snapshot response notification facts: %w", err)
	}
	safe := func(value string) string {
		return privacy.ScrubURLCredentials(notification.ScrubPersonalText(strings.TrimSpace(value), 500))
	}
	actorName := safe(facts.ActorName)
	target := safeResponseTarget(record.AuthorizationTarget.Value)
	data := map[string]any{
		"title": "Response finished", "summary": "A governed response finished.",
		"response_id": record.ID, "engagement_id": record.EngagementID, "lead_user_id": facts.LeadUserID.String(),
		"outcome": outcome, "action_kind": record.Action.Kind, "target": target, "actor": actorName,
	}
	if !facts.ActorUserID.IsZero() {
		data["actor_user_id"] = facts.ActorUserID
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode response notification data: %w", err)
	}
	occurredAt := s.clock.Now().UTC()
	recordSource, err := notification.SnapshotSourceRecord(notification.SourceRecord{
		TenantID: record.TenantID, SourceKind: "response_finished", SourceID: record.ID.String() + ":" + outcome,
		EventType: notification.EventResponseFinished, EngagementID: record.EngagementID, OccurredAt: occurredAt,
		Data: raw, SubjectKind: "response", SubjectID: record.ID.String(),
	}, map[string]string{"outcome": outcome, "action_kind": string(record.Action.Kind), "target": target, "actor": actorName, "engagement_name": safe(facts.EngagementName)})
	if err != nil {
		return fmt.Errorf("snapshot response notification: %w", err)
	}
	if err := s.notifications.Append(ctx, recordSource); err != nil {
		return fmt.Errorf("append response notification: %w", err)
	}
	return nil
}

func isResponseFinishedOutcome(outcome string) bool {
	switch outcome {
	case "applied", "verified", "reverted", "halted", "failed":
		return true
	default:
		return false
	}
}

// safeResponseTarget reduces a URL target to its stable routing identity before
// it enters immutable event data or template context. Query parameters and
// fragments commonly carry credentials or ephemeral command details.
func safeResponseTarget(value string) string {
	value = strings.TrimSpace(value)
	if parsed, err := url.Parse(value); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.ForceQuery = false
		parsed.Fragment = ""
		value = parsed.String()
	}
	return privacy.ScrubURLCredentials(notification.ScrubPersonalText(value, 500))
}
