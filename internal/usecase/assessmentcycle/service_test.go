package assessmentcycle_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	uc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type seqIDGen struct {
	next int
}

func (g *seqIDGen) NewID() shared.ID {
	g.next++
	return shared.ID("gen-" + string(rune('0'+g.next)))
}

type recordAudit struct {
	entries []ports.AuditEntry
}

func (a *recordAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

func setupServiceTest(t *testing.T) (*uc.Service, *memory.AssessmentCycleRepository, *memory.EngagementRepository, *recordAudit) {
	t.Helper()
	cycleRepo := memory.NewAssessmentCycleRepository()
	engRepo := memory.NewEngagementRepository()
	txRunner := memory.NewTenantTransactionRunner()
	clock := fixedClock{t: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)}
	idGen := &seqIDGen{}
	audit := &recordAudit{}

	svc, err := uc.NewService(cycleRepo, engRepo, nil, nil, txRunner, idGen, clock, audit)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc, cycleRepo, engRepo, audit
}

func createTestEngagement(t *testing.T, engRepo *memory.EngagementRepository, tenantID, engID shared.ID, assetID, projectID shared.ID) *engagement.Engagement {
	t.Helper()
	eng, err := engagement.New(engID, tenantID, "Eng "+engID.String(), "", time.Now())
	if err != nil {
		t.Fatalf("new engagement: %v", err)
	}
	eng.BusinessAssetID = assetID
	eng.ProjectID = projectID
	if err := engRepo.Create(context.Background(), eng); err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	return eng
}

func TestService_CreateInitialCycle(t *testing.T) {
	svc, _, engRepo, audit := setupServiceTest(t)
	ctx := context.Background()
	tenantID := shared.ID("tenant-1")

	// Regular standalone assessment
	createTestEngagement(t, engRepo, tenantID, "eng-1", "", "")

	t.Run("successful standalone creation", func(t *testing.T) {
		cycle, root, err := svc.CreateInitialCycle(ctx, uc.CreateInitialCycleInput{
			TenantID:         tenantID,
			Name:             "Q3 Web Assessment",
			BoundaryKind:     assessmentcycle.BoundaryStandalone,
			RootAssessmentID: "eng-1",
			Actor:            "alice",
		})
		if err != nil {
			t.Fatalf("create initial cycle: %v", err)
		}
		if cycle.Status != assessmentcycle.StatusOpen {
			t.Errorf("status = %v, want open", cycle.Status)
		}
		if cycle.RootAssessmentID != "eng-1" || cycle.SelectedHeadAssessmentID != "eng-1" {
			t.Errorf("root/head mismatch in cycle: %+v", cycle)
		}
		if root.AssessmentID != "eng-1" || !root.IsRoot() {
			t.Errorf("root member mismatch: %+v", root)
		}
		if len(audit.entries) == 0 || audit.entries[len(audit.entries)-1].Action != "assessment_cycle.created" {
			t.Errorf("expected audit entry for cycle creation")
		}
	})

	t.Run("duplicate assessment rejected", func(t *testing.T) {
		// eng-1 is already in a cycle
		_, _, err := svc.CreateInitialCycle(ctx, uc.CreateInitialCycleInput{
			TenantID:         tenantID,
			Name:             "Another Cycle",
			BoundaryKind:     assessmentcycle.BoundaryStandalone,
			RootAssessmentID: "eng-1",
			Actor:            "alice",
		})
		if !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("expected ErrConflict for duplicate assessment, got %v", err)
		}
	})

	t.Run("hidden project analysis context rejected", func(t *testing.T) {
		// create engagement with ProjectID != "" (hidden project analysis context)
		createTestEngagement(t, engRepo, tenantID, "proj-eng-1", "", "proj-123")
		_, _, err := svc.CreateInitialCycle(ctx, uc.CreateInitialCycleInput{
			TenantID:         tenantID,
			Name:             "Project Context Cycle",
			BoundaryKind:     assessmentcycle.BoundaryStandalone,
			RootAssessmentID: "proj-eng-1",
			Actor:            "alice",
		})
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("expected ErrValidation for hidden project context, got %v", err)
		}
	})
}

func TestService_CreateRetestAndBranching(t *testing.T) {
	svc, _, engRepo, _ := setupServiceTest(t)
	ctx := context.Background()
	tenantID := shared.ID("tenant-1")

	createTestEngagement(t, engRepo, tenantID, "root", "", "")
	createTestEngagement(t, engRepo, tenantID, "retest-1", "", "")
	createTestEngagement(t, engRepo, tenantID, "retest-2", "", "")
	createTestEngagement(t, engRepo, tenantID, "retest-branch", "", "")

	cycle, _, err := svc.CreateInitialCycle(ctx, uc.CreateInitialCycleInput{
		TenantID:         tenantID,
		Name:             "Cycle Alpha",
		BoundaryKind:     assessmentcycle.BoundaryStandalone,
		RootAssessmentID: "root",
		Actor:            "alice",
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Create Retest 1 from Root (which is selected head) -> Advances selected head to retest-1
	m1, err := svc.CreateRetest(ctx, uc.CreateRetestInput{
		TenantID:                tenantID,
		CycleID:                 cycle.ID,
		PredecessorAssessmentID: "root",
		NewAssessmentID:         "retest-1",
		Actor:                   "alice",
	})
	if err != nil {
		t.Fatalf("create retest 1: %v", err)
	}
	if m1.RetestNumber != 1 {
		t.Errorf("retest number = %d, want 1", m1.RetestNumber)
	}

	updatedCycle, _ := svc.GetCycle(ctx, tenantID, cycle.ID)
	if updatedCycle.SelectedHeadAssessmentID != "retest-1" {
		t.Errorf("selected head = %v, want retest-1", updatedCycle.SelectedHeadAssessmentID)
	}

	// 2. Create Retest 2 from Retest 1 (selected head) -> Advances selected head to retest-2
	m2, err := svc.CreateRetest(ctx, uc.CreateRetestInput{
		TenantID:                tenantID,
		CycleID:                 cycle.ID,
		PredecessorAssessmentID: "retest-1",
		NewAssessmentID:         "retest-2",
		Actor:                   "alice",
	})
	if err != nil {
		t.Fatalf("create retest 2: %v", err)
	}
	if m2.RetestNumber != 2 {
		t.Errorf("retest number = %d, want 2", m2.RetestNumber)
	}

	updatedCycle, _ = svc.GetCycle(ctx, tenantID, cycle.ID)
	if updatedCycle.SelectedHeadAssessmentID != "retest-2" {
		t.Errorf("selected head = %v, want retest-2", updatedCycle.SelectedHeadAssessmentID)
	}

	// 3. Create Retest Branch from Retest 1 (BRANCH - predecessor is NOT selected head)
	mBranch, err := svc.CreateRetest(ctx, uc.CreateRetestInput{
		TenantID:                tenantID,
		CycleID:                 cycle.ID,
		PredecessorAssessmentID: "retest-1",
		NewAssessmentID:         "retest-branch",
		Actor:                   "alice",
	})
	if err != nil {
		t.Fatalf("create retest branch: %v", err)
	}
	if mBranch.RetestNumber != 3 {
		t.Errorf("retest number = %d, want 3", mBranch.RetestNumber)
	}

	// Selected head MUST REMAIN retest-2!
	updatedCycle, _ = svc.GetCycle(ctx, tenantID, cycle.ID)
	if updatedCycle.SelectedHeadAssessmentID != "retest-2" {
		t.Fatalf("branch creation improperly changed selected head to %v", updatedCycle.SelectedHeadAssessmentID)
	}

	// 4. Branch heads query should now return [retest-2, retest-branch]
	heads, err := svc.ListBranchHeads(ctx, tenantID, cycle.ID)
	if err != nil {
		t.Fatalf("list branch heads: %v", err)
	}
	if len(heads) != 2 || heads[0].AssessmentID != "retest-2" || heads[1].AssessmentID != "retest-branch" {
		t.Fatalf("branch heads = %+v, want [retest-2, retest-branch]", heads)
	}
}

func TestService_SelectHeadAndReparent(t *testing.T) {
	svc, _, engRepo, _ := setupServiceTest(t)
	ctx := context.Background()
	tenantID := shared.ID("tenant-1")

	createTestEngagement(t, engRepo, tenantID, "root", "", "")
	createTestEngagement(t, engRepo, tenantID, "retest-1", "", "")
	createTestEngagement(t, engRepo, tenantID, "retest-2", "", "")
	createTestEngagement(t, engRepo, tenantID, "retest-branch", "", "")

	cycle, _, _ := svc.CreateInitialCycle(ctx, uc.CreateInitialCycleInput{
		TenantID:         tenantID,
		Name:             "Cycle",
		BoundaryKind:     assessmentcycle.BoundaryStandalone,
		RootAssessmentID: "root",
		Actor:            "alice",
	})

	_, _ = svc.CreateRetest(ctx, uc.CreateRetestInput{TenantID: tenantID, CycleID: cycle.ID, PredecessorAssessmentID: "root", NewAssessmentID: "retest-1", Actor: "alice"})
	_, _ = svc.CreateRetest(ctx, uc.CreateRetestInput{TenantID: tenantID, CycleID: cycle.ID, PredecessorAssessmentID: "retest-1", NewAssessmentID: "retest-2", Actor: "alice"})
	_, _ = svc.CreateRetest(ctx, uc.CreateRetestInput{TenantID: tenantID, CycleID: cycle.ID, PredecessorAssessmentID: "retest-1", NewAssessmentID: "retest-branch", Actor: "alice"})

	t.Run("select branch head explicitly", func(t *testing.T) {
		err := svc.SelectHead(ctx, uc.SelectHeadInput{
			TenantID:           tenantID,
			CycleID:            cycle.ID,
			TargetAssessmentID: "retest-branch",
			Actor:              "alice",
		})
		if err != nil {
			t.Fatalf("select head: %v", err)
		}
		c, _ := svc.GetCycle(ctx, tenantID, cycle.ID)
		if c.SelectedHeadAssessmentID != "retest-branch" {
			t.Errorf("selected head = %v, want retest-branch", c.SelectedHeadAssessmentID)
		}
	})

	t.Run("cannot select internal non-leaf node as head", func(t *testing.T) {
		// retest-1 is an internal node with children retest-2 and retest-branch
		err := svc.SelectHead(ctx, uc.SelectHeadInput{
			TenantID:           tenantID,
			CycleID:            cycle.ID,
			TargetAssessmentID: "retest-1",
			Actor:              "alice",
		})
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("expected ErrValidation selecting internal node as head, got %v", err)
		}
	})

	t.Run("reparent branch under root", func(t *testing.T) {
		err := svc.ReparentWithinCycle(ctx, uc.ReparentInput{
			TenantID:                   tenantID,
			CycleID:                    cycle.ID,
			AssessmentID:               "retest-branch",
			NewPredecessorAssessmentID: "root",
			Actor:                      "alice",
		})
		if err != nil {
			t.Fatalf("reparent: %v", err)
		}
		ancestors, _ := svc.ListAncestors(ctx, tenantID, cycle.ID, "retest-branch")
		if len(ancestors) != 1 || ancestors[0].AssessmentID != "root" {
			t.Fatalf("ancestors after reparent = %+v, want [root]", ancestors)
		}
	})

	t.Run("cannot reparent causing cycle loop", func(t *testing.T) {
		// Attempt to reparent retest-1 under retest-2 (retest-2 is a child of retest-1)
		err := svc.ReparentWithinCycle(ctx, uc.ReparentInput{
			TenantID:                   tenantID,
			CycleID:                    cycle.ID,
			AssessmentID:               "retest-1",
			NewPredecessorAssessmentID: "retest-2",
			Actor:                      "alice",
		})
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("expected ErrValidation reparenting to descendant, got %v", err)
		}
	})
}

func TestService_ArchiveMemberAndReopenCycle(t *testing.T) {
	svc, _, engRepo, _ := setupServiceTest(t)
	ctx := context.Background()
	tenantID := shared.ID("tenant-1")

	createTestEngagement(t, engRepo, tenantID, "root", "", "")
	createTestEngagement(t, engRepo, tenantID, "retest-1", "", "")
	createTestEngagement(t, engRepo, tenantID, "retest-2", "", "")

	cycle, _, _ := svc.CreateInitialCycle(ctx, uc.CreateInitialCycleInput{
		TenantID:         tenantID,
		Name:             "Cycle",
		BoundaryKind:     assessmentcycle.BoundaryStandalone,
		RootAssessmentID: "root",
		Actor:            "alice",
	})
	_, _ = svc.CreateRetest(ctx, uc.CreateRetestInput{TenantID: tenantID, CycleID: cycle.ID, PredecessorAssessmentID: "root", NewAssessmentID: "retest-1", Actor: "alice"})
	_, _ = svc.CreateRetest(ctx, uc.CreateRetestInput{TenantID: tenantID, CycleID: cycle.ID, PredecessorAssessmentID: "retest-1", NewAssessmentID: "retest-2", Actor: "alice"})

	t.Run("cannot archive root member", func(t *testing.T) {
		err := svc.ArchiveMember(ctx, uc.ArchiveMemberInput{
			TenantID:     tenantID,
			CycleID:      cycle.ID,
			AssessmentID: "root",
			Actor:        "alice",
		})
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("expected ErrValidation archiving root, got %v", err)
		}
	})

	t.Run("cannot archive currently selected head", func(t *testing.T) {
		// selected head is retest-2
		err := svc.ArchiveMember(ctx, uc.ArchiveMemberInput{
			TenantID:     tenantID,
			CycleID:      cycle.ID,
			AssessmentID: "retest-2",
			Actor:        "alice",
		})
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("expected ErrValidation archiving selected head, got %v", err)
		}
	})

	t.Run("archive non-head member retest-1", func(t *testing.T) {
		err := svc.ArchiveMember(ctx, uc.ArchiveMemberInput{
			TenantID:     tenantID,
			CycleID:      cycle.ID,
			AssessmentID: "retest-1",
			Actor:        "alice",
		})
		if err != nil {
			t.Fatalf("archive member: %v", err)
		}
	})

	t.Run("archive and reopen cycle", func(t *testing.T) {
		// Archive cycle
		if err := svc.ArchiveCycle(ctx, uc.ArchiveCycleInput{TenantID: tenantID, CycleID: cycle.ID, Actor: "alice"}); err != nil {
			t.Fatalf("archive cycle: %v", err)
		}
		c, _ := svc.GetCycle(ctx, tenantID, cycle.ID)
		if c.Status != assessmentcycle.StatusArchived {
			t.Fatalf("status = %v, want archived", c.Status)
		}

		// Reopen from archived is rejected by state machine
		err := svc.ReopenCycle(ctx, uc.ReopenCycleInput{TenantID: tenantID, CycleID: cycle.ID, Actor: "alice"})
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("expected ErrValidation reopening archived cycle, got %v", err)
		}
	})
}

func TestService_PostgresParity(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres parity test")
	}
	ctx := context.Background()
	if err := postgres.MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := postgres.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	cycleRepo := postgres.NewAssessmentCycleRepository(pool)
	engRepo := postgres.NewEngagementRepository(pool)
	txRunner := postgres.NewTenantTransactionRunner(pool)
	clock := fixedClock{t: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)}
	idGen := &seqIDGen{}
	audit := &recordAudit{}

	svc, err := uc.NewService(cycleRepo, engRepo, nil, nil, txRunner, idGen, clock, audit)
	if err != nil {
		t.Fatalf("new postgres-backed service: %v", err)
	}

	tenantID := shared.ID(fmt.Sprintf("t-parity-%d", time.Now().UnixNano()))
	rootID := shared.ID(fmt.Sprintf("root-p-%d", time.Now().UnixNano()))
	retestID := shared.ID(fmt.Sprintf("ret-p-%d", time.Now().UnixNano()))

	// Ensure tenant & engagements
	_, _ = pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`, tenantID.String(), "Tenant")
	engRoot, _ := engagement.New(rootID, tenantID, "Root Eng", "", time.Now())
	_ = engRepo.Create(ctx, engRoot)
	engRetest, _ := engagement.New(retestID, tenantID, "Retest Eng", "", time.Now())
	_ = engRepo.Create(ctx, engRetest)

	// 1. Create Initial Cycle
	cycle, rootMember, err := svc.CreateInitialCycle(ctx, uc.CreateInitialCycleInput{
		TenantID:         tenantID,
		Name:             "Postgres Parity Cycle",
		BoundaryKind:     assessmentcycle.BoundaryStandalone,
		RootAssessmentID: rootID,
		Actor:            "alice",
	})
	if err != nil {
		t.Fatalf("postgres create initial cycle: %v", err)
	}
	if cycle.Status != assessmentcycle.StatusOpen || rootMember.AssessmentID != rootID {
		t.Fatalf("unexpected cycle/root from postgres: %+v", cycle)
	}

	// 2. Create Retest
	retestMember, err := svc.CreateRetest(ctx, uc.CreateRetestInput{
		TenantID:                tenantID,
		CycleID:                 cycle.ID,
		PredecessorAssessmentID: rootID,
		NewAssessmentID:         retestID,
		Actor:                   "alice",
	})
	if err != nil {
		t.Fatalf("postgres create retest: %v", err)
	}
	if retestMember.RetestNumber != 1 {
		t.Errorf("retest number = %d, want 1", retestMember.RetestNumber)
	}

	// 3. Query branch heads and members
	branchHeads, err := svc.ListBranchHeads(ctx, tenantID, cycle.ID)
	if err != nil {
		t.Fatalf("postgres list branch heads: %v", err)
	}
	if len(branchHeads) != 1 || branchHeads[0].AssessmentID != retestID {
		t.Fatalf("unexpected branch heads: %+v", branchHeads)
	}

	// 4. Query GetCycleByAssessment
	foundCycle, err := svc.GetCycleByAssessment(ctx, tenantID, retestID)
	if err != nil {
		t.Fatalf("postgres get cycle by assessment: %v", err)
	}
	if foundCycle.ID != cycle.ID {
		t.Fatalf("found cycle ID = %v, want %v", foundCycle.ID, cycle.ID)
	}
}
