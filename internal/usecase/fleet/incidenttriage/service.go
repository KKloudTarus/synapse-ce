// Package incidenttriage is the Phase C analyst triage loop (#594, C5 #679): the human-driven mutations
// on an incident — take ownership, comment, change workflow status, and set a disposition — each recorded
// as an attributable incident.IncidentEvent on the append-only log (C7) and mirrored to the tamper-evident
// audit log. State, Disposition, and risk stay independent: a disposition never mutates the risk score.
// RBAC is enforced at the HTTP edge; this usecase requires an attributable actor and audits every
// mutation.
package incidenttriage

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
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
	incidents IncidentAppender
	audit     ports.AuditLogger
	now       func() time.Time
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
// Caller contract on an audit-failure error: the mutation IS already committed (the incident event is
// durable and carries the attribution) — the error signals only that the secondary audit trail has a gap.
// The caller MUST NOT blindly retry (the stores are not transactional and the append is not idempotent, so
// a retry would append a DUPLICATE event); treat it as committed-but-unaudited and reconcile/alert.
func (s *Service) apply(ctx context.Context, actor string, id shared.ID, action string, build func(time.Time) incident.IncidentEvent, meta map[string]string) (incident.Incident, error) {
	if id.IsZero() {
		return incident.Incident{}, fmt.Errorf("%w: incident id is required", shared.ErrValidation)
	}
	if actor == "" {
		return incident.Incident{}, fmt.Errorf("%w: triage mutation requires an actor", shared.ErrValidation)
	}
	cur, err := s.incidents.Get(ctx, id)
	if err != nil {
		return incident.Incident{}, err
	}
	at := s.now().UTC()
	updated, err := s.incidents.Append(ctx, id, cur.Revision, []incident.IncidentEvent{build(at)})
	if err != nil {
		return incident.Incident{}, err
	}
	entry := ports.AuditEntry{Actor: actor, Action: action, Target: id.String(), At: at, Metadata: map[string]string{}}
	for k, v := range meta {
		entry.Metadata[k] = v
	}
	if err := s.audit.Record(ctx, entry); err != nil {
		return incident.Incident{}, fmt.Errorf("audit %s: %w", action, err)
	}
	return updated, nil
}
