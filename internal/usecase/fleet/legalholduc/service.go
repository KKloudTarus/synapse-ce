// Package legalholduc is the application service for legal holds (#635): an operator places/releases a
// hold on an engagement's data, and it exposes the IsHeld guard the retention deletion consults. Every
// placement + release is audited. A hold SUSPENDS retention expiry — held data survives its retention
// window until the hold is released — the mechanism a legal/regulatory preservation obligation needs.
package legalholduc

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/legalhold"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type Service struct {
	store ports.LegalHoldStore
	audit ports.AuditLogger
	now   func() time.Time
}

func NewService(store ports.LegalHoldStore, audit ports.AuditLogger, now func() time.Time) (*Service, error) {
	if store == nil || audit == nil || now == nil {
		return nil, fmt.Errorf("%w: legal-hold service is missing a dependency", shared.ErrValidation)
	}
	return &Service{store: store, audit: audit, now: now}, nil
}

// Place puts an active legal hold on the engagement (idempotent). actor is the operator; reason is
// mandatory. Audited as fleet.legal_hold.placed.
func (s *Service) Place(ctx context.Context, actor string, engagementID shared.ID, reason string) (legalhold.Hold, error) {
	if actor == "" {
		return legalhold.Hold{}, fmt.Errorf("%w: placing a legal hold requires an actor", shared.ErrValidation)
	}
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() {
		return legalhold.Hold{}, fmt.Errorf("%w: legal hold requires a tenant in context", shared.ErrValidation)
	}
	at := s.now().UTC()
	hold := legalhold.Hold{TenantID: tenant, EngagementID: engagementID, Reason: reason, PlacedBy: actor, PlacedAt: at}
	placed, err := s.store.Place(ctx, hold)
	if err != nil {
		return legalhold.Hold{}, err
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor, Action: "fleet.legal_hold.placed", Target: engagementID.String(), At: at,
		Metadata: map[string]string{"engagement": engagementID.String(), "reason": reason},
	}); err != nil {
		return legalhold.Hold{}, fmt.Errorf("audit legal-hold placement: %w", err)
	}
	return placed, nil
}

// Release closes the active hold on the engagement (no-op if none). Audited as fleet.legal_hold.released.
func (s *Service) Release(ctx context.Context, actor string, engagementID shared.ID) error {
	if actor == "" {
		return fmt.Errorf("%w: releasing a legal hold requires an actor", shared.ErrValidation)
	}
	at := s.now().UTC()
	if err := s.store.Release(ctx, engagementID, actor, at); err != nil {
		return err
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor, Action: "fleet.legal_hold.released", Target: engagementID.String(), At: at,
		Metadata: map[string]string{"engagement": engagementID.String()},
	}); err != nil {
		return fmt.Errorf("audit legal-hold release: %w", err)
	}
	return nil
}

// IsHeld is the retention guard: reports whether the engagement is under an active hold.
func (s *Service) IsHeld(ctx context.Context, engagementID shared.ID) (bool, error) {
	return s.store.IsHeld(ctx, engagementID)
}

// ListActive returns the tenant's active holds.
func (s *Service) ListActive(ctx context.Context) ([]legalhold.Hold, error) {
	return s.store.ListActive(ctx)
}
