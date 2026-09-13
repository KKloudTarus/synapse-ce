package memory

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vex"
)

func TestVEXStatementStoreIdempotentOrderedIsolated(t *testing.T) {
	ctx := context.Background()
	store := NewVEXStatementStore()
	tenant := shared.ID("t1")
	eng := shared.ID("e1")
	t0 := time.Unix(1000, 0).UTC()

	s1 := vex.NewStoredStatement(vex.Statement{Vulnerability: "CVE-1", Products: []string{"a@1"}, Status: "not_affected"}, "alice", t0)
	s2 := vex.NewStoredStatement(vex.Statement{Vulnerability: "CVE-2", Products: []string{"b@2"}, Status: "fixed"}, "alice", t0)

	if err := store.Save(ctx, tenant, eng, []vex.StoredStatement{s1, s2, s1}); err != nil { // s1 twice
		t.Fatalf("save: %v", err)
	}
	if err := store.Save(ctx, tenant, eng, []vex.StoredStatement{s1}); err != nil { // and again
		t.Fatalf("save idempotent: %v", err)
	}

	got, err := store.ListByEngagement(ctx, tenant, eng)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("idempotent by digest: want 2, got %d", len(got))
	}
	// Import order (not clock ties): s1 was inserted before s2, and re-saving s1 keeps its original position.
	if got[0].Advisory != "CVE-1" || got[1].Advisory != "CVE-2" {
		t.Errorf("must replay in insertion order, got %q then %q", got[0].Advisory, got[1].Advisory)
	}

	// A different tenant and a different engagement are both isolated.
	if other, _ := store.ListByEngagement(ctx, shared.ID("t2"), eng); len(other) != 0 {
		t.Errorf("a different tenant must be isolated, got %d", len(other))
	}
	if other, _ := store.ListByEngagement(ctx, tenant, shared.ID("e2")); len(other) != 0 {
		t.Errorf("a different engagement must be isolated, got %d", len(other))
	}
}
