package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestWorkOrderAuditRecovery(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := NewWorkOrderStore()
	wo, err := workorder.New("order", "tenant", "asset", "agent", workorder.CapabilityResponseProcess, "auth", "idem", now.Add(time.Hour), 1, now)
	if err != nil {
		t.Fatal(err)
	}
	wo.ResponseCommand = &fleetagent.ResponseCommand{HaltGeneration: 0}
	if _, err := store.Issue(ctx, wo); err != nil {
		t.Fatal(err)
	}
	var running []ports.FleetAuditIntent
	for i, lease := range []string{"first", "second"} {
		at := now.Add(time.Duration(i) * 2 * time.Minute)
		orders, _, err := store.ClaimWithAudit(ctx, "tenant", "agent", 1, at, lease, at.Add(time.Minute), "operator")
		if err != nil || len(orders) != 1 {
			t.Fatalf("claim: %v %v", orders, err)
		}
		if i == 1 {
			if _, err := store.TransitionLeasedWithAudit(ctx, "tenant", wo.ID, "first", workorder.StateRunning, "", workorder.StateClaimed, at, "operator"); !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("stale lease: %v", err)
			}
		}
		intent, err := store.TransitionLeasedWithAudit(ctx, "tenant", wo.ID, lease, workorder.StateRunning, "", workorder.StateClaimed, at, "operator")
		if err != nil {
			t.Fatal(err)
		}
		running = append(running, intent)
	}
	if running[0].ID == running[1].ID {
		t.Fatal("running audits share identity")
	}
	count, first, err := store.CancelResponsesBelowGenerationWithAudit(ctx, "tenant", 1, "halt", now.Add(3*time.Minute), "operator")
	if err != nil || count != 1 {
		t.Fatalf("cancel: %d %v", count, err)
	}
	if err := store.AcknowledgeFleetAudit(ctx, first.ID); err != nil {
		t.Fatal(err)
	}
	count, replay, err := store.CancelResponsesBelowGenerationWithAudit(ctx, "tenant", 1, "halt", now.Add(4*time.Minute), "operator")
	if err != nil || count != 1 || !ports.SameFleetAuditIntent(first, replay) {
		t.Fatalf("replay: %d %v %v", count, replay, err)
	}
	if _, _, err := store.CancelResponsesBelowGenerationWithAudit(ctx, "tenant", 1, "different", now.Add(4*time.Minute), "operator"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("changed reason: %v", err)
	}
}
