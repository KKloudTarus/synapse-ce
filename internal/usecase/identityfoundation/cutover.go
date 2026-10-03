package identityfoundation

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// CutoverService coordinates the guarded, per-tenant authority transition. It never turns a
// feature flag into authority: only the durable declaration ledger can do that.
type CutoverService struct {
	store ports.IdentityCutoverStore
	clock ports.Clock
}

func NewCutoverService(store ports.IdentityCutoverStore, clock ports.Clock) (*CutoverService, error) {
	if store == nil || clock == nil {
		return nil, fmt.Errorf("%w: cutover store and clock are required", shared.ErrValidation)
	}
	return &CutoverService{store: store, clock: clock}, nil
}

func (s *CutoverService) State(ctx context.Context, tenantID shared.ID) (ports.IdentityCutoverState, error) {
	return s.store.CutoverState(ctx, tenantID)
}
func (s *CutoverService) Prepare(ctx context.Context, tenantID shared.ID, expectedVersion int, actor string) (ports.IdentityCutoverState, error) {
	return s.store.PrepareCutover(ctx, tenantID, expectedVersion, actor, s.clock.Now().UTC())
}
func (s *CutoverService) Canary(ctx context.Context, tenantID shared.ID) (ports.IdentityShadowReport, error) {
	return s.store.CanaryCutover(ctx, tenantID)
}
func (s *CutoverService) Declare(ctx context.Context, tenantID shared.ID, expectedVersion int, evidence ports.IdentityCutoverEvidence, actor string) (ports.IdentityCutoverState, error) {
	return s.store.DeclareCutover(ctx, tenantID, expectedVersion, evidence, actor, s.clock.Now().UTC())
}
func (s *CutoverService) Contract(ctx context.Context, tenantID shared.ID, expectedVersion int, actor string) (ports.IdentityCutoverState, error) {
	return s.store.ContractCutover(ctx, tenantID, expectedVersion, actor, s.clock.Now().UTC())
}
func (s *CutoverService) Abort(ctx context.Context, tenantID shared.ID, expectedVersion int, actor string) (ports.IdentityCutoverState, error) {
	return s.store.AbortCutover(ctx, tenantID, expectedVersion, actor, s.clock.Now().UTC())
}
