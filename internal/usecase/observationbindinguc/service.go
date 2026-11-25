// Package observationbindinguc records the human decision that an external observation and a canonical
// finding describe one issue.
//
// The decision used to be implicit. A SARIF result landing on the same file and line as a first-party
// finding had its FindingID set by the deduplicator, and every reader treated that as a management
// decision, so a coincidence of location merged two remediation workflows with nobody asked. This service
// is the other half: a candidate stays a candidate until a person adopts it, with a reason.
package observationbindinguc

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/observationbinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// engagementReader resolves an engagement inside the CALLER's tenant. The service does this itself rather
// than trusting the HTTP layer, for the same reason the SARIF ingest does: the value that authorizes the
// write and the value that stamps it must be the same one.
type engagementReader interface {
	GetByIDInTenant(ctx context.Context, tenantID, id shared.ID) (*engagement.Engagement, error)
}

// findingReader is the narrow read needed to prove the canonical finding is in this engagement. The
// PostgreSQL store also refuses a cross-engagement reference through a composite foreign key; this check
// makes the in-memory adapter behave the same and turns a constraint violation into a clear refusal.
type findingReader interface {
	ListByEngagement(ctx context.Context, engagementID shared.ID) ([]finding.Finding, error)
}

// Service records and reads approved bindings.
type Service struct {
	bindings     ports.ObservationBindingStore
	observations ports.ImportedFindingStore
	findings     findingReader
	engagements  engagementReader
	audit        ports.AuditLogger
	clock        ports.Clock
	ids          ports.IDGenerator
}

// NewService validates and returns the binding service.
func NewService(bindings ports.ObservationBindingStore, observations ports.ImportedFindingStore,
	findings findingReader, engagements engagementReader, audit ports.AuditLogger,
	clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if bindings == nil || observations == nil || findings == nil || engagements == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: observation binding needs a binding store, an observation store, a finding reader, an engagement reader, an audit log, a clock and an id generator", shared.ErrValidation)
	}
	return &Service{bindings: bindings, observations: observations, findings: findings,
		engagements: engagements, audit: audit, clock: clock, ids: ids}, nil
}

// DecideRequest is one person's decision about one observation.
type DecideRequest struct {
	TenantID      shared.ID
	EngagementID  shared.ID
	ObservationID shared.ID
	FindingID     shared.ID
	Actor         shared.ID
	Reason        string
	// ExpectedVersion is zero for a first adoption and the version being replaced for a change. A change
	// that names the wrong version is refused, so a decision made against a stale view cannot overwrite
	// one made in between.
	ExpectedVersion int
}

// Decide adopts an observation onto a finding, or supersedes the binding in force.
//
// Adoption is idempotent for the same finding, so a retried request cannot mint a second version.
// Adopting a DIFFERENT finding while one is in force is a conflict and requires an explicit supersede:
// changing which workflow owns an observation is a decision in its own right, not a side effect of the
// second request to arrive.
func (s *Service) Decide(ctx context.Context, req DecideRequest) (observationbinding.Binding, error) {
	if req.Actor.IsZero() {
		return observationbinding.Binding{}, fmt.Errorf("%w: an observation binding needs the actor who decided it", shared.ErrValidation)
	}
	if strings.TrimSpace(req.Reason) == "" {
		return observationbinding.Binding{}, fmt.Errorf("%w: an observation binding needs a reason", shared.ErrValidation)
	}
	if req.EngagementID.IsZero() || req.ObservationID.IsZero() || req.FindingID.IsZero() {
		return observationbinding.Binding{}, fmt.Errorf("%w: an observation binding needs an engagement, an observation and a finding", shared.ErrValidation)
	}
	if req.ExpectedVersion < 0 {
		// Falling through to Adopt here would answer 200 with the binding already in force and silently
		// drop the caller's new reason, so a client that meant to change a decision would be told it
		// succeeded while nothing changed.
		return observationbinding.Binding{}, fmt.Errorf("%w: an observation binding version starts at 1; omit expected_version to adopt", shared.ErrValidation)
	}

	eng, err := s.engagements.GetByIDInTenant(ctx, req.TenantID, req.EngagementID)
	if err != nil {
		return observationbinding.Binding{}, fmt.Errorf("load engagement: %w", err)
	}
	tenantID := shared.TenantOrDefault(eng.TenantID)

	observation, err := s.observation(ctx, tenantID, req.EngagementID, req.ObservationID)
	if err != nil {
		return observationbinding.Binding{}, err
	}
	identity := observationbinding.Identity{
		Scope:            observation.BindingScope(),
		ExternalIdentity: observation.BindingExternalIdentity(),
	}
	if err := identity.Validate(); err != nil {
		// A result carrying neither a fingerprint nor a rule has no identity that survives a re-import, so
		// there is nothing a decision could be attached to.
		return observationbinding.Binding{}, fmt.Errorf("%w: this observation carries no identity that survives a re-import, so it cannot be bound", shared.ErrValidation)
	}
	if err := s.requireFinding(ctx, req.EngagementID, req.FindingID); err != nil {
		return observationbinding.Binding{}, err
	}

	now := s.clock.Now().UTC()
	binding := observationbinding.Binding{
		ID:               s.ids.NewID(),
		TenantID:         tenantID,
		EngagementID:     req.EngagementID,
		Scope:            identity.Scope,
		ExternalIdentity: identity.ExternalIdentity,
		FindingID:        req.FindingID,
		ObservationID:    observation.ID,
		Version:          1,
		DecidedBy:        req.Actor,
		Reason:           strings.TrimSpace(req.Reason),
		DecidedAt:        now,
	}

	var persisted observationbinding.Binding
	action := "finding.observation.bound"
	if req.ExpectedVersion > 0 {
		binding.Version = req.ExpectedVersion + 1
		action = "finding.observation.rebound"
		persisted, err = s.bindings.Supersede(ctx, tenantID, req.ExpectedVersion, binding)
	} else {
		persisted, err = s.bindings.Adopt(ctx, tenantID, binding)
	}
	if err != nil {
		return observationbinding.Binding{}, err
	}
	if persisted.ID != binding.ID {
		// Adopt resolved to the binding already in force: this request decided nothing. Recording it as
		// a decision would credit this actor with one they did not make, and an auditor could not tell a
		// retried request from a second person agreeing.
		action = "finding.observation.bind.repeated"
	}

	if auditErr := s.audit.Record(ctx, ports.AuditEntry{
		Actor:  req.Actor.String(),
		Action: action,
		Target: req.EngagementID.String(),
		Metadata: map[string]string{
			"binding":           persisted.ID.String(),
			"scope":             persisted.Scope,
			"external_identity": persisted.ExternalIdentity,
			"finding":           persisted.FindingID.String(),
			"observation":       persisted.ObservationID.String(),
			"version":           fmt.Sprintf("%d", persisted.Version),
		},
		At: now,
	}); auditErr != nil {
		// The decision is already durable. Reporting only "audit failed" would leave the caller believing
		// nothing was recorded, so the error states both facts.
		return observationbinding.Binding{}, fmt.Errorf("observation binding %s was recorded but could not be audited: %w", persisted.ID, auditErr)
	}
	return persisted, nil
}

// Current returns the bindings in force in an engagement, keyed by scoped identity, for a read surface
// that has to tell an approved link from a candidate match.
func (s *Service) Current(ctx context.Context, tenantID, engagementID shared.ID) (map[observationbinding.Identity]observationbinding.Binding, error) {
	all, err := s.bindings.CurrentByEngagement(ctx, shared.TenantOrDefault(tenantID), engagementID)
	if err != nil {
		return nil, err
	}
	out := make(map[observationbinding.Identity]observationbinding.Binding, len(all))
	for _, binding := range all {
		out[binding.Key()] = binding
	}
	return out, nil
}

// List returns every version in the engagement, newest decision first. Superseded versions are kept on
// purpose: a decision that turned out to be wrong is only auditable if what it replaced is still there.
func (s *Service) List(ctx context.Context, tenantID, engagementID shared.ID) ([]observationbinding.Binding, error) {
	return s.bindings.ListByEngagement(ctx, shared.TenantOrDefault(tenantID), engagementID)
}

// observation finds the imported finding inside the engagement.
//
// The store exposes no single-row read, and widening the port for one human-driven action would add a
// method every adapter has to implement for no other caller. An engagement's imported findings are
// already listed by the console on the same screen this decision is made from.
func (s *Service) observation(ctx context.Context, tenantID, engagementID, observationID shared.ID) (importedfinding.ImportedFinding, error) {
	all, err := s.observations.ListByEngagement(ctx, tenantID, engagementID)
	if err != nil {
		return importedfinding.ImportedFinding{}, fmt.Errorf("list imported findings: %w", err)
	}
	for _, candidate := range all {
		if candidate.ID == observationID {
			return candidate, nil
		}
	}
	return importedfinding.ImportedFinding{}, fmt.Errorf("%w: observation %s is not in this engagement", shared.ErrNotFound, observationID)
}

// requireFinding refuses a binding onto a finding that is not in this engagement.
func (s *Service) requireFinding(ctx context.Context, engagementID, findingID shared.ID) error {
	all, err := s.findings.ListByEngagement(ctx, engagementID)
	if err != nil {
		return fmt.Errorf("list engagement findings: %w", err)
	}
	for _, item := range all {
		if item.ID == findingID {
			return nil
		}
	}
	return fmt.Errorf("%w: finding %s is not in this engagement", shared.ErrNotFound, findingID)
}

// ErrNotFound is re-exported for callers that branch on a missing binding without importing shared.
var ErrNotFound = shared.ErrNotFound
