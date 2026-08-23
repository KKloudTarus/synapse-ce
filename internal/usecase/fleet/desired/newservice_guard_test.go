package fleetdesired_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	desireduc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/desired"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Self-contained minimal fakes so this guard test does not couple to the other test files' helpers.
type guardAssets struct{}

func (guardAssets) GetAssetByID(context.Context, shared.ID, shared.ID) (*asset.Asset, error) {
	return nil, shared.ErrNotFound
}

type guardBindings struct{}

func (guardBindings) ListCurrentBindings(context.Context, shared.ID) ([]desireduc.CurrentBinding, error) {
	return nil, nil
}

type guardAgents struct{}

func (guardAgents) ListAgents(context.Context, shared.ID) ([]*fleetagent.Agent, error) {
	return nil, nil
}

type guardAudit struct{}

func (guardAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type guardClock struct{}

func (guardClock) Now() time.Time { return time.Unix(0, 0).UTC() }

type guardIDs struct{}

func (guardIDs) NewID() shared.ID { return "id" }

func newGuardService(stale time.Duration) (*desireduc.Service, error) {
	return desireduc.NewService(
		memory.NewFleetDesiredStore(), guardAssets{}, guardBindings{}, guardAgents{},
		guardAudit{}, guardClock{}, guardIDs{}, stale,
	)
}

// TestNewServiceRejectsNonPositiveStaleAfter locks in the fail-closed guard: a non-positive stale window
// would make fleetcoverage.AgentStateFrom treat a long-idle agent as "never stale" (Healthy/covered) — a
// coverage fail-open the constructor must refuse.
func TestNewServiceRejectsNonPositiveStaleAfter(t *testing.T) {
	for _, stale := range []time.Duration{0, -time.Second, -time.Hour} {
		if _, err := newGuardService(stale); err == nil {
			t.Errorf("NewService(staleAfter=%s) must fail closed", stale)
		} else if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("NewService(staleAfter=%s) error must wrap ErrValidation, got %v", stale, err)
		}
	}
	if _, err := newGuardService(time.Minute); err != nil {
		t.Fatalf("a positive stale window must construct: %v", err)
	}
}
