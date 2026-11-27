package keyregistry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

// TestOperatorRoutesNameAnAgentOfTheCallersTenant pins the guard #1702's harness found missing: a
// foreign agent id read as an agent with no keys, an empty success decided by the store's partition.
func TestOperatorRoutesNameAnAgentOfTheCallersTenant(t *testing.T) {
	svc, _, ctx := newHarness(t) // ctx is bound to tenant t1
	agents := memory.NewFleetAgentStore()
	if err := agents.CreateAgent(ctx, &fleetagent.Agent{ID: "agent:1", TenantID: "t1", Name: "own"}); err != nil {
		t.Fatal(err)
	}
	req, _, _ := proofFor(t, "agent:1", fleetagent.PurposeDetectionBatch)
	key, err := svc.Register(ctx, "agent:1", req)
	if err != nil {
		t.Fatal(err)
	}

	// Without a directory the store partition is the only boundary, as before.
	if keys, err := svc.List(shared.WithTenant(ctx, "t2"), "agent:1"); err != nil || len(keys) != 0 {
		t.Fatalf("floorless list from t2 = %d keys, %v", len(keys), err)
	}

	svc.SetAgentDirectory(agents)
	if keys, err := svc.List(ctx, "agent:1"); err != nil || len(keys) != 1 {
		t.Fatalf("own list = %d keys, %v", len(keys), err)
	}
	other := shared.WithTenant(ctx, "t2")
	if _, err := svc.List(other, "agent:1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("t2 listing t1's agent: err = %v, want not found", err)
	}
	if err := svc.Revoke(other, "agent:1", key.KeyID, "op"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("t2 revoking t1's key: err = %v, want not found", err)
	}
	if _, err := svc.List(ctx, "agent:unknown"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("listing an unknown agent: err = %v, want not found", err)
	}
	if err := svc.Revoke(ctx, "agent:1", key.KeyID, "op"); err != nil {
		t.Fatalf("own revoke: %v", err)
	}
}

// TestRevokeRefusesAForeignAgentEvenWhenTheStoreWouldNot pins the revoke guard on its own. The memory store
// partitions by tenant, so a foreign revoke already found nothing there; this plants a key with the same
// agent id inside the caller's own partition, for an agent that exists only in another tenant, so only the
// directory check can refuse it.
func TestRevokeRefusesAForeignAgentEvenWhenTheStoreWouldNot(t *testing.T) {
	store := memory.NewAgentSigningKeyStore()
	svc, err := NewService(store, &fakeAudit{}, fakeClock{t: time.Unix(1_000_000, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	t1 := shared.WithTenant(context.Background(), "t1")
	t2 := shared.WithTenant(context.Background(), "t2")
	agents := memory.NewFleetAgentStore()
	if err := agents.CreateAgent(t1, &fleetagent.Agent{ID: "agent:1", TenantID: "t1", Name: "t1 agent"}); err != nil {
		t.Fatal(err)
	}
	req, _, _ := proofFor(t, "agent:1", fleetagent.PurposeDetectionBatch)
	stray, err := svc.Register(t2, "agent:1", req) // lands in t2's partition
	if err != nil {
		t.Fatal(err)
	}
	svc.SetAgentDirectory(agents)

	if err := svc.Revoke(t2, "agent:1", stray.KeyID, "op"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("t2 revoking under an agent it does not hold: err = %v, want not found", err)
	}
	if _, err := svc.List(t2, "agent:1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("t2 listing an agent it does not hold: err = %v, want not found", err)
	}
	keys, err := store.ListByAgent(t2, "agent:1")
	if err != nil || len(keys) != 1 || !keys[0].RevokedAt.IsZero() {
		t.Fatalf("the stray key changed: %+v %v", keys, err)
	}
}
