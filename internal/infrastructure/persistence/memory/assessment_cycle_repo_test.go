package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

func TestMemoryAssessmentCycleRepository_CycleCRUD(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewAssessmentCycleRepository()
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	tenantID := shared.ID("tenant-1")

	cycle, err := assessmentcycle.NewAssessmentCycle(
		"cycle-1", tenantID, "Cycle 1",
		assessmentcycle.BoundaryStandalone, "", "",
		"root-1", "alice", now,
	)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Create Cycle
	if err := repo.CreateCycle(ctx, cycle); err != nil {
		t.Fatalf("create cycle: %v", err)
	}

	// 2. Duplicate Create -> ErrConflict
	if err := repo.CreateCycle(ctx, cycle); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate create, got %v", err)
	}

	// 3. Get Cycle
	got, err := repo.GetCycle(ctx, tenantID, "cycle-1")
	if err != nil {
		t.Fatalf("get cycle: %v", err)
	}
	if got.Name != "Cycle 1" || got.Version != 1 {
		t.Fatalf("got cycle %+v", got)
	}

	// 4. Update CAS success
	cycle.Name = "Updated Cycle"
	cycle.Version = 2
	if err := repo.UpdateCycleCAS(ctx, cycle, 1); err != nil {
		t.Fatalf("update cycle CAS: %v", err)
	}

	// 5. Update CAS conflict
	cycle.Version = 3
	if err := repo.UpdateCycleCAS(ctx, cycle, 1); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected ErrConflict on version mismatch, got %v", err)
	}

	// 6. Cross-tenant isolation
	_, err = repo.GetCycle(ctx, "other-tenant", "cycle-1")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for other tenant, got %v", err)
	}
}

func TestMemoryAssessmentCycleRepository_MemberCRUDAndUniqueness(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewAssessmentCycleRepository()
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	tenantID := shared.ID("tenant-1")

	cycle, _ := assessmentcycle.NewAssessmentCycle("c-1", tenantID, "Cycle", assessmentcycle.BoundaryStandalone, "", "", "root-1", "alice", now)
	_ = repo.CreateCycle(ctx, cycle)

	rootMember, _ := assessmentcycle.NewInitialMember(tenantID, "c-1", "root-1", "alice", now)
	retest1, _ := assessmentcycle.NewRetestMember(tenantID, "c-1", "retest-1", "root-1", 1, "alice", now)

	// 1. Create Root Member
	if err := repo.CreateMember(ctx, rootMember); err != nil {
		t.Fatalf("create root member: %v", err)
	}

	// 2. Global uniqueness: cannot add root-1 to another cycle
	cycle2, _ := assessmentcycle.NewAssessmentCycle("c-2", tenantID, "Cycle 2", assessmentcycle.BoundaryStandalone, "", "", "root-1", "alice", now)
	_ = repo.CreateCycle(ctx, cycle2)
	rootMember2, _ := assessmentcycle.NewInitialMember(tenantID, "c-2", "root-1", "alice", now)
	if err := repo.CreateMember(ctx, rootMember2); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected ErrConflict adding assessment to second cycle, got %v", err)
	}

	// 3. Create Retest Member
	if err := repo.CreateMember(ctx, retest1); err != nil {
		t.Fatalf("create retest member: %v", err)
	}

	// 4. GetCycleByAssessment
	foundCycle, err := repo.GetCycleByAssessment(ctx, tenantID, "retest-1")
	if err != nil {
		t.Fatalf("get cycle by assessment: %v", err)
	}
	if foundCycle.ID != "c-1" {
		t.Fatalf("found cycle ID = %v, want c-1", foundCycle.ID)
	}

	// 5. ListMembers determinism
	members, err := repo.ListMembers(ctx, tenantID, "c-1")
	if err != nil {
		t.Fatalf("list members: %v", err)
	}
	if len(members) != 2 || members[0].AssessmentID != "root-1" || members[1].AssessmentID != "retest-1" {
		t.Fatalf("unexpected members list: %+v", members)
	}

	// 6. UpdateMemberCAS
	_ = retest1.Reparent("root-1", retest1.RelationshipVersion)
	if err := repo.UpdateMemberCAS(ctx, retest1, 1); err != nil {
		t.Fatalf("update member CAS: %v", err)
	}
	if err := repo.UpdateMemberCAS(ctx, retest1, 1); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected ErrConflict on version mismatch, got %v", err)
	}
}
