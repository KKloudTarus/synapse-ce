// Package incidenttriage is the Phase C analyst triage loop (#594, C5 #679): the human-driven mutations
// on an incident — take ownership, comment, change workflow status, and set a disposition — each recorded
// as an attributable incident.IncidentEvent on the append-only log (C7) and mirrored to the tamper-evident
// audit log. State, Disposition, and risk stay independent: a disposition never mutates the risk score.
// RBAC is enforced at the HTTP edge; this usecase requires an attributable actor and audits every
// mutation.
package incidenttriage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// IncidentAppender is the consumer-side view of the incident store this usecase needs: read the current
// projection (for its revision) and append events under optimistic concurrency with projectability
// validation. incidentuc.Service satisfies it; defined here so triage does not import a sibling usecase.
type IncidentAppender interface {
	Get(ctx context.Context, id shared.ID) (incident.Incident, error)
	Append(ctx context.Context, id shared.ID, expectedRevision int, events []incident.IncidentEvent) (incident.Incident, error)
}

// Service performs analyst triage mutations on incidents.
type Service struct {
	incidents         IncidentAppender
	audit             ports.AuditLogger
	now               func() time.Time
	notificationTx    ports.TenantTransactionRunner
	notifications     ports.NotificationOutbox
	notificationFacts ports.NotificationLifecycleFactsReader
}

// NewService constructs the triage service. now supplies event timestamps (injected for determinism).
func NewService(incidents IncidentAppender, audit ports.AuditLogger, now func() time.Time) (*Service, error) {
	if incidents == nil {
		return nil, fmt.Errorf("%w: triage service requires an incident store", shared.ErrValidation)
	}
	if audit == nil {
		return nil, fmt.Errorf("%w: triage service requires an audit logger", shared.ErrValidation)
	}
	if now == nil {
		return nil, fmt.Errorf("%w: triage service requires a clock", shared.ErrValidation)
	}
	return &Service{incidents: incidents, audit: audit, now: now}, nil
}

// SetNotifications enables transactional incident-update capture. The incident revision,
// audit entry, and source snapshot share the provided tenant transaction.
func (s *Service) SetNotifications(tx ports.TenantTransactionRunner, outbox ports.NotificationOutbox, facts ports.NotificationLifecycleFactsReader) error {
	if tx == nil || outbox == nil || facts == nil {
		return fmt.Errorf("%w: incident notification dependencies are required", shared.ErrValidation)
	}
	s.notificationTx, s.notifications, s.notificationFacts = tx, outbox, facts
	return nil
}

// AssignOwner sets the incident's owner. actor is the authenticated principal responsible (it MUST be the
// server-side principal, never a request-body field) and follows ctx to keep it away from the other string
// params.
func (s *Service) AssignOwner(ctx context.Context, actor string, id shared.ID, owner string) (incident.Incident, error) {
	if owner == "" {
		return incident.Incident{}, fmt.Errorf("%w: owner is required", shared.ErrValidation)
	}
	return s.apply(ctx, actor, id, "incident.owner_changed",
		func(at time.Time) incident.IncidentEvent {
			return incident.IncidentEvent{IncidentID: id, Kind: incident.EventOwnerChanged, At: at, Actor: actor, Owner: owner}
		}, map[string]string{"owner": owner})
}

// Comment records an analyst note.
func (s *Service) Comment(ctx context.Context, actor string, id shared.ID, text string) (incident.Incident, error) {
	if text == "" {
		return incident.Incident{}, fmt.Errorf("%w: comment text is required", shared.ErrValidation)
	}
	return s.apply(ctx, actor, id, "incident.commented",
		func(at time.Time) incident.IncidentEvent {
			return incident.IncidentEvent{IncidentID: id, Kind: incident.EventAnalystCommented, At: at, Actor: actor, Comment: text}
		}, nil)
}

// ChangeStatus moves the incident to a new workflow state (the append rejects an illegal transition).
func (s *Service) ChangeStatus(ctx context.Context, actor string, id shared.ID, to incident.State) (incident.Incident, error) {
	if !to.Valid() {
		return incident.Incident{}, fmt.Errorf("%w: unknown target state %q", shared.ErrValidation, to)
	}
	return s.apply(ctx, actor, id, "incident.status_changed",
		func(at time.Time) incident.IncidentEvent {
			return incident.IncidentEvent{IncidentID: id, Kind: incident.EventStatusChanged, At: at, Actor: actor, To: to}
		}, map[string]string{"to": string(to)})
}

// SetDisposition records the analyst's verdict (independent of state and risk).
func (s *Service) SetDisposition(ctx context.Context, actor string, id shared.ID, disposition incident.Disposition) (incident.Incident, error) {
	if !disposition.Valid() {
		return incident.Incident{}, fmt.Errorf("%w: unknown disposition %q", shared.ErrValidation, disposition)
	}
	return s.apply(ctx, actor, id, "incident.disposition_set",
		func(at time.Time) incident.IncidentEvent {
			return incident.IncidentEvent{IncidentID: id, Kind: incident.EventDispositionSet, At: at, Actor: actor, Disposition: disposition}
		}, map[string]string{"disposition": string(disposition)})
}

// apply is the shared mutation path: require an actor, load the current revision, append the built event
// under optimistic concurrency, then audit. The append validates projectability (e.g. a legal transition)
// and fails closed before anything is recorded.
//
// Ordering rationale (attribution, golden rule 6): the PRIMARY attributable record IS the incident event
// itself — it carries the Actor and lives on the append-only, tamper-evident incident log (C7). The
// ports.AuditLogger is a SECONDARY, cross-cutting trail. Auditing AFTER a successful append means a failed
// append never leaves a false audit record for a mutation that did not happen.
//
// Without notification capture, an audit-failure error means the incident event is already committed and
// callers must treat it as committed-but-unaudited. With capture enabled, the incident event, source
// snapshot, and audit record share the tenant transaction and roll back together on any write failure.
func (s *Service) apply(ctx context.Context, actor string, id shared.ID, action string, build func(time.Time) incident.IncidentEvent, meta map[string]string) (incident.Incident, error) {
	if id.IsZero() {
		return incident.Incident{}, fmt.Errorf("%w: incident id is required", shared.ErrValidation)
	}
	if actor == "" {
		return incident.Incident{}, fmt.Errorf("%w: triage mutation requires an actor", shared.ErrValidation)
	}
	var updated incident.Incident
	write := func(writeCtx context.Context, tenant shared.ID) error {
		cur, err := s.incidents.Get(writeCtx, id)
		if err != nil {
			return err
		}
		at := s.now().UTC()
		updated, err = s.incidents.Append(writeCtx, cur.ID, cur.Revision, []incident.IncidentEvent{build(at)})
		if err != nil {
			return err
		}
		if s.notifications != nil && action != "incident.commented" && !updated.EngagementID.IsZero() {
			if err := s.appendIncidentUpdated(writeCtx, tenant, updated, incidentUpdateKind(action), actor, at); err != nil {
				return err
			}
		}
		entry := ports.AuditEntry{Actor: actor, Action: action, Target: updated.ID.String(), At: at, Metadata: map[string]string{}}
		for k, v := range meta {
			entry.Metadata[k] = v
		}
		if err := s.audit.Record(writeCtx, entry); err != nil {
			return fmt.Errorf("audit %s: %w", action, err)
		}
		return nil
	}
	if s.notifications == nil {
		if err := write(ctx, ""); err != nil {
			return incident.Incident{}, err
		}
		return updated, nil
	}
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() {
		return incident.Incident{}, fmt.Errorf("%w: incident notification requires a tenant", shared.ErrValidation)
	}
	if err := s.notificationTx.Run(ctx, tenant, func(txCtx context.Context) error { return write(txCtx, tenant) }); err != nil {
		return incident.Incident{}, err
	}
	return updated, nil
}

func incidentUpdateKind(action string) string {
	switch action {
	case "incident.owner_changed":
		return "owner"
	case "incident.status_changed":
		return "status"
	case "incident.disposition_set":
		return "disposition"
	default:
		return "updated"
	}
}

func (s *Service) appendIncidentUpdated(ctx context.Context, tenant shared.ID, item incident.Incident, updateKind, actor string, occurredAt time.Time) error {
	if item.ID.IsZero() || item.EngagementID.IsZero() {
		return fmt.Errorf("%w: incident notification requires canonical incident engagement", shared.ErrValidation)
	}
	facts, err := s.notificationFacts.SnapshotNotificationLifecycleFacts(ctx, tenant, item.EngagementID, actor)
	if err != nil {
		return fmt.Errorf("snapshot incident notification facts: %w", err)
	}
	safe := func(value string) string {
		return privacy.ScrubURLCredentials(notification.ScrubPersonalText(strings.TrimSpace(value), 500))
	}
	actorName := safe(facts.ActorName)
	data := map[string]any{
		"title": "Incident updated", "summary": "An incident was updated.",
		"incident_id": item.ID, "engagement_id": item.EngagementID, "lead_user_id": facts.LeadUserID.String(),
		"severity": item.Severity, "update_kind": updateKind, "status": item.State, "disposition": item.Disposition,
		"actor": actorName, "incident_title": safe(item.Title), "owner": safe(item.OwnerID),
	}
	if !facts.ActorUserID.IsZero() {
		data["actor_user_id"] = facts.ActorUserID
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode incident notification data: %w", err)
	}
	vars := map[string]string{
		"severity": string(item.Severity), "update_kind": updateKind, "status": string(item.State),
		"disposition": string(item.Disposition), "actor": actorName, "incident_title": safe(item.Title), "owner": safe(item.OwnerID),
	}
	record, err := notification.SnapshotSourceRecord(notification.SourceRecord{
		TenantID: tenant, SourceKind: "incident_update", SourceID: item.ID.String() + ":" + fmt.Sprint(item.Revision),
		EventType: notification.EventIncidentUpdated, EngagementID: item.EngagementID, Severity: item.Severity,
		OccurredAt: occurredAt, Data: raw, SubjectKind: "incident", SubjectID: item.ID.String(),
	}, vars)
	if err != nil {
		return fmt.Errorf("snapshot incident notification: %w", err)
	}
	if err := s.notifications.Append(ctx, record); err != nil {
		return fmt.Errorf("append incident notification: %w", err)
	}
	return nil
}
