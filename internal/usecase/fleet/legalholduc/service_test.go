package legalholduc

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeAudit struct{ actions []string }

func (f *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	f.actions = append(f.actions, e.Action)
	return nil
}

func ctxT() context.Context { return shared.WithTenant(context.Background(), "tenant-a") }

func newSvc(t *testing.T) (*Service, *fakeAudit) {
	t.Helper()
	audit := &fakeAudit{}
	svc, err := NewService(memory.NewLegalHoldStore(), audit, func() time.Time { return time.Unix(0, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	return svc, audit
}

func TestPlaceHoldSuspendsAndReleaseLifts(t *testing.T) {
	svc, audit := newSvc(t)
	ctx := ctxT()

	if held, _ := svc.IsHeld(ctx, "eng-1"); held {
		t.Fatal("engagement must not be held initially")
	}
	if _, err := svc.Place(ctx, "operator", "eng-1", "litigation JIRA-123"); err != nil {
		t.Fatal(err)
	}
	if held, _ := svc.IsHeld(ctx, "eng-1"); !held {
		t.Fatal("engagement must be held after Place")
	}
	// Idempotent re-place.
	if _, err := svc.Place(ctx, "operator", "eng-1", "again"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Release(ctx, "operator", "eng-1"); err != nil {
		t.Fatal(err)
	}
	if held, _ := svc.IsHeld(ctx, "eng-1"); held {
		t.Fatal("engagement must not be held after Release")
	}
	// Placement + release both audited.
	var placed, released int
	for _, a := range audit.actions {
		if a == "fleet.legal_hold.placed" {
			placed++
		}
		if a == "fleet.legal_hold.released" {
			released++
		}
	}
	if placed < 1 || released < 1 {
		t.Fatalf("place + release must be audited: %v", audit.actions)
	}
}

func TestPlaceRequiresReason(t *testing.T) {
	svc, _ := newSvc(t)
	if _, err := svc.Place(ctxT(), "operator", "eng-1", ""); err == nil {
		t.Fatal("a legal hold without a reason must be rejected")
	}
}

func TestActiveHoldTenantScoped(t *testing.T) {
	svc, _ := newSvc(t)
	if _, err := svc.Place(ctxT(), "operator", "eng-1", "hold"); err != nil {
		t.Fatal(err)
	}
	// A different tenant does not see the hold.
	other := shared.WithTenant(context.Background(), "tenant-b")
	if held, _ := svc.IsHeld(other, "eng-1"); held {
		t.Fatal("a hold must be tenant-scoped")
	}
}
