package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

func TestAgentSessionStore_ListResumable(t *testing.T) {
	ctx := context.Background()
	store := memory.NewAgentSessionStore()
	base := time.Unix(2_000_000, 0).UTC()
	save := func(id string, status agent.Status, updated time.Time) {
		if err := store.SaveSession(ctx, agent.Session{ID: shared.ID(id), EngagementID: "e1", Status: status, UpdatedAt: updated}); err != nil {
			t.Fatal(err)
		}
	}
	// two stranded non-terminal sessions (old), plus a fresh one and a terminal one to exclude.
	save("running-old", agent.StatusRunning, base.Add(-30*time.Minute))
	save("awaiting-old", agent.StatusAwaitingApproval, base.Add(-20*time.Minute))
	save("running-fresh", agent.StatusRunning, base.Add(-1*time.Minute))
	save("done", agent.StatusSucceeded, base.Add(-30*time.Minute))

	got, err := store.ListResumable(ctx, 10*time.Minute, base, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 stranded non-terminal sessions, got %d", len(got))
	}
	// oldest first
	if got[0].ID != "running-old" || got[1].ID != "awaiting-old" {
		t.Fatalf("expected oldest-first [running-old, awaiting-old], got [%s, %s]", got[0].ID, got[1].ID)
	}
	// limit respected
	if lim, _ := store.ListResumable(ctx, 10*time.Minute, base, 1); len(lim) != 1 {
		t.Fatalf("limit not respected, got %d", len(lim))
	}
}

func TestApprovalStore_EngagementsWithPending(t *testing.T) {
	ctx := context.Background()
	store := memory.NewApprovalStore()
	mk := func(id, eng string) agent.ProposedAction {
		return agent.ProposedAction{ID: shared.ID(id), SessionID: "s1", EngagementID: shared.ID(eng), Risk: agent.RiskActive}
	}
	for _, a := range []agent.ProposedAction{mk("a1", "e1"), mk("a2", "e1"), mk("a3", "e2")} {
		if err := store.Enqueue(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	// decide a3 → no longer pending; e2 should drop out.
	if err := store.Decide(ctx, agent.ApprovalDecision{ActionID: "a3", State: agent.ApprovalApproved, DecidedBy: "alice"}); err != nil {
		t.Fatal(err)
	}
	got, err := store.EngagementsWithPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].EngagementID != "e1" {
		t.Fatalf("expected only e1 (distinct, pending-only), got %v", got)
	}
}
