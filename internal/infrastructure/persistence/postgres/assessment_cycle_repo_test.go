package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func setupTestDB(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return ctx, pool
}

func ensureTestTenantAndEngagement(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, engID shared.ID, assetID, projectID shared.ID) {
	t.Helper()
	tenantID = shared.TenantOrDefault(tenantID)

	// Ensure tenant exists
	_, _ = pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`, tenantID.String(), "Tenant "+tenantID.String())

	// Ensure engagement exists
	engRepo := NewEngagementRepository(pool)
	eng, err := engagement.New(engID, tenantID, "Eng "+engID.String(), "Client", time.Now())
	if err != nil {
		t.Fatalf("new engagement: %v", err)
	}
	eng.BusinessAssetID = assetID
	eng.ProjectID = projectID
	_ = engRepo.Create(ctx, eng)
}

func TestPostgresAssessmentCycleRepository_LifecycleAndCAS(t *testing.T) {
	ctx, pool := setupTestDB(t)
	repo := NewAssessmentCycleRepository(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	tenantID := shared.ID(fmt.Sprintf("t-cycle-%d", time.Now().UnixNano()))

	rootID := shared.ID(fmt.Sprintf("root-%d", time.Now().UnixNano()))
	retestID1 := shared.ID(fmt.Sprintf("ret1-%d", time.Now().UnixNano()))
	retestID2 := shared.ID(fmt.Sprintf("ret2-%d", time.Now().UnixNano()))
	cycleID := shared.ID(fmt.Sprintf("cycle-%d", time.Now().UnixNano()))

	ensureTestTenantAndEngagement(t, ctx, pool, tenantID, rootID, "", "")
	ensureTestTenantAndEngagement(t, ctx, pool, tenantID, retestID1, "", "")
	ensureTestTenantAndEngagement(t, ctx, pool, tenantID, retestID2, "", "")

	// 1. Create Cycle
	cycle, err := assessmentcycle.NewAssessmentCycle(
		cycleID, tenantID, "Postgres Cycle",
		assessmentcycle.BoundaryStandalone, "", "",
		rootID, "alice", now,
	)
	if err != nil {
		t.Fatalf("new cycle: %v", err)
	}

	if err := repo.CreateCycle(ctx, cycle); err != nil {
		t.Fatalf("create cycle: %v", err)
	}

	// 2. Create Root Member
	rootMember, err := assessmentcycle.NewInitialMember(tenantID, cycleID, rootID, "alice", now)
	if err != nil {
		t.Fatalf("new initial member: %v", err)
	}
	if err := repo.CreateMember(ctx, rootMember); err != nil {
		t.Fatalf("create initial member: %v", err)
	}

	// 3. Duplicate Cycle Create -> ErrConflict
	if err := repo.CreateCycle(ctx, cycle); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate create, got %v", err)
	}

	// 4. Get Cycle
	gotCycle, err := repo.GetCycle(ctx, tenantID, cycleID)
	if err != nil {
		t.Fatalf("get cycle: %v", err)
	}
	if gotCycle.Name != "Postgres Cycle" || gotCycle.Status != assessmentcycle.StatusOpen || gotCycle.Version != 1 {
		t.Fatalf("unexpected cycle content: %+v", gotCycle)
	}

	// 5. Update CAS success
	cycle.Name = "Updated Postgres Cycle"
	cycle.Version = 2
	cycle.UpdatedAt = time.Now().UTC()
	if err := repo.UpdateCycleCAS(ctx, cycle, 1); err != nil {
		t.Fatalf("update cycle CAS: %v", err)
	}

	// 6. Update CAS conflict (expected 1, actual 2)
	cycle.Version = 3
	if err := repo.UpdateCycleCAS(ctx, cycle, 1); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected ErrConflict on CAS mismatch, got %v", err)
	}

	// 7. Create Retest Member 1
	retest1, err := assessmentcycle.NewRetestMember(tenantID, cycleID, retestID1, rootID, 1, "alice", now)
	if err != nil {
		t.Fatalf("new retest member 1: %v", err)
	}
	if err := repo.CreateMember(ctx, retest1); err != nil {
		t.Fatalf("create retest member 1: %v", err)
	}

	// 8. Create Retest Member 2
	retest2, err := assessmentcycle.NewRetestMember(tenantID, cycleID, retestID2, retestID1, 2, "alice", now)
	if err != nil {
		t.Fatalf("new retest member 2: %v", err)
	}
	if err := repo.CreateMember(ctx, retest2); err != nil {
		t.Fatalf("create retest member 2: %v", err)
	}

	// 9. GetCycleByAssessment
	foundCycle, err := repo.GetCycleByAssessment(ctx, tenantID, retestID2)
	if err != nil {
		t.Fatalf("get cycle by assessment: %v", err)
	}
	if foundCycle.ID != cycleID {
		t.Fatalf("found cycle = %v, want %v", foundCycle.ID, cycleID)
	}

	// 10. ListMembers
	members, err := repo.ListMembers(ctx, tenantID, cycleID)
	if err != nil {
		t.Fatalf("list members: %v", err)
	}
	if len(members) != 3 {
		t.Fatalf("expected 3 members, got %d", len(members))
	}
	if members[0].AssessmentID != rootID || members[1].AssessmentID != retestID1 || members[2].AssessmentID != retestID2 {
		t.Fatalf("unexpected members ordering: %+v", members)
	}

	// 11. LockCycleForUpdate
	lockedCycle, err := repo.LockCycleForUpdate(ctx, tenantID, cycleID)
	if err != nil {
		t.Fatalf("lock cycle for update: %v", err)
	}
	if lockedCycle.ID != cycleID {
		t.Fatalf("locked cycle id = %v, want %v", lockedCycle.ID, cycleID)
	}
}

func TestPostgresAssessmentCycleRepository_TenantIsolation(t *testing.T) {
	ctx, pool := setupTestDB(t)
	repo := NewAssessmentCycleRepository(pool)
	now := time.Now().UTC()

	tenantA := shared.ID(fmt.Sprintf("t-a-%d", time.Now().UnixNano()))
	tenantB := shared.ID(fmt.Sprintf("t-b-%d", time.Now().UnixNano()))
	rootA := shared.ID(fmt.Sprintf("root-a-%d", time.Now().UnixNano()))
	cycleA := shared.ID(fmt.Sprintf("cycle-a-%d", time.Now().UnixNano()))

	ensureTestTenantAndEngagement(t, ctx, pool, tenantA, rootA, "", "")
	ensureTestTenantAndEngagement(t, ctx, pool, tenantB, "other-root", "", "")

	c, _ := assessmentcycle.NewAssessmentCycle(cycleA, tenantA, "Tenant A Cycle", assessmentcycle.BoundaryStandalone, "", "", rootA, "alice", now)
	if err := repo.CreateCycle(ctx, c); err != nil {
		t.Fatalf("create cycle tenant A: %v", err)
	}

	// Tenant B should not be able to read Tenant A's cycle
	_, err := repo.GetCycle(ctx, tenantB, cycleA)
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cross-tenant read, got %v", err)
	}

	// Tenant B should not find cycle by Tenant A's assessment
	_, err = repo.GetCycleByAssessment(ctx, tenantB, rootA)
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cross-tenant GetCycleByAssessment, got %v", err)
	}
}

func TestPostgresAssessmentCycleRepository_UniqueConstraints(t *testing.T) {
	ctx, pool := setupTestDB(t)
	repo := NewAssessmentCycleRepository(pool)
	now := time.Now().UTC()
	tenantID := shared.ID(fmt.Sprintf("t-uniq-%d", time.Now().UnixNano()))

	rootID := shared.ID(fmt.Sprintf("root-u-%d", time.Now().UnixNano()))
	cycle1ID := shared.ID(fmt.Sprintf("c1-%d", time.Now().UnixNano()))
	cycle2ID := shared.ID(fmt.Sprintf("c2-%d", time.Now().UnixNano()))

	ensureTestTenantAndEngagement(t, ctx, pool, tenantID, rootID, "", "")

	c1, _ := assessmentcycle.NewAssessmentCycle(cycle1ID, tenantID, "Cycle 1", assessmentcycle.BoundaryStandalone, "", "", rootID, "alice", now)
	_ = repo.CreateCycle(ctx, c1)
	m1, _ := assessmentcycle.NewInitialMember(tenantID, cycle1ID, rootID, "alice", now)
	_ = repo.CreateMember(ctx, m1)

	// Attempting to add rootID to cycle2 should fail UNIQUE (tenant_id, assessment_id)
	c2, _ := assessmentcycle.NewAssessmentCycle(cycle2ID, tenantID, "Cycle 2", assessmentcycle.BoundaryStandalone, "", "", rootID, "alice", now)
	_ = repo.CreateCycle(ctx, c2)
	m2, _ := assessmentcycle.NewInitialMember(tenantID, cycle2ID, rootID, "alice", now)
	err := repo.CreateMember(ctx, m2)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected ErrConflict when adding assessment to second cycle, got %v", err)
	}
}

func TestPostgresAssessmentCycleRepository_ConcurrentRetestAllocation(t *testing.T) {
	ctx, pool := setupTestDB(t)
	repo := NewAssessmentCycleRepository(pool)
	txRunner := NewTenantTransactionRunner(pool)
	now := time.Now().UTC()
	tenantID := shared.ID(fmt.Sprintf("t-race-%d", time.Now().UnixNano()))

	rootID := shared.ID(fmt.Sprintf("root-race-%d", time.Now().UnixNano()))
	cycleID := shared.ID(fmt.Sprintf("cycle-race-%d", time.Now().UnixNano()))

	ensureTestTenantAndEngagement(t, ctx, pool, tenantID, rootID, "", "")

	cycle, _ := assessmentcycle.NewAssessmentCycle(cycleID, tenantID, "Race Cycle", assessmentcycle.BoundaryStandalone, "", "", rootID, "alice", now)
	_ = repo.CreateCycle(ctx, cycle)
	rootMember, _ := assessmentcycle.NewInitialMember(tenantID, cycleID, rootID, "alice", now)
	_ = repo.CreateMember(ctx, rootMember)

	const numWorkers = 8
	retestIDs := make([]shared.ID, numWorkers)
	for i := 0; i < numWorkers; i++ {
		retestIDs[i] = shared.ID(fmt.Sprintf("ret-race-%d-%d", i, time.Now().UnixNano()))
		ensureTestTenantAndEngagement(t, ctx, pool, tenantID, retestIDs[i], "", "")
	}

	allocatedNumbers := make([]int, numWorkers)
	var wg sync.WaitGroup
	errCh := make(chan error, numWorkers)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerIdx int, assessmentID shared.ID) {
			defer wg.Done()
			err := txRunner.Run(ctx, tenantID, func(txCtx context.Context) error {
				// Lock cycle row
				c, err := repo.LockCycleForUpdate(txCtx, tenantID, cycleID)
				if err != nil {
					return err
				}

				retestNum, err := c.AdvanceRetest(assessmentID, rootID, c.Version, "worker", time.Now())
				if err != nil {
					return err
				}

				if err := repo.UpdateCycleCAS(txCtx, c, c.Version-1); err != nil {
					return err
				}

				member, err := assessmentcycle.NewRetestMember(tenantID, cycleID, assessmentID, rootID, retestNum, "worker", time.Now())
				if err != nil {
					return err
				}

				if err := repo.CreateMember(txCtx, member); err != nil {
					return err
				}

				allocatedNumbers[workerIdx] = retestNum
				return nil
			})
			if err != nil {
				errCh <- err
			}
		}(i, retestIDs[i])
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent allocation failed: %v", err)
	}

	// Verify all allocated numbers are strictly distinct from 1 to numWorkers
	seen := make(map[int]bool)
	for _, n := range allocatedNumbers {
		if n < 1 || n > numWorkers {
			t.Errorf("allocated number out of range: %d", n)
		}
		if seen[n] {
			t.Errorf("duplicate retest number allocated: %d", n)
		}
		seen[n] = true
	}

	members, err := repo.ListMembers(ctx, tenantID, cycleID)
	if err != nil {
		t.Fatalf("list members: %v", err)
	}
	if len(members) != numWorkers+1 {
		t.Fatalf("expected %d members, got %d", numWorkers+1, len(members))
	}
}

func TestPostgresAssessmentCycleRepository_UnprivilegedRoleRLS(t *testing.T) {
	ctx, pool := setupTestDB(t)
	repo := NewAssessmentCycleRepository(pool)
	now := time.Now().UTC()

	tenantA := shared.ID(fmt.Sprintf("t-unp-a-%d", time.Now().UnixNano()))
	tenantB := shared.ID(fmt.Sprintf("t-unp-b-%d", time.Now().UnixNano()))
	rootA := shared.ID(fmt.Sprintf("root-unp-a-%d", time.Now().UnixNano()))
	cycleA := shared.ID(fmt.Sprintf("cycle-unp-a-%d", time.Now().UnixNano()))

	ensureTestTenantAndEngagement(t, ctx, pool, tenantA, rootA, "", "")
	ensureTestTenantAndEngagement(t, ctx, pool, tenantB, "root-b", "", "")

	// Create a dedicated non-superuser, non-BYPASSRLS test role
	const unprivRole = "synapse_cycle_rls_unpriv_test"
	cleanupRole := func() {
		_, _ = pool.Exec(ctx, `DROP OWNED BY `+unprivRole)
		_, _ = pool.Exec(ctx, `DROP ROLE IF EXISTS `+unprivRole)
	}
	cleanupRole()
	t.Cleanup(func() { cleanupRole() })

	if _, err := pool.Exec(ctx, `CREATE ROLE `+unprivRole+` NOLOGIN NOSUPERUSER NOBYPASSRLS`); err != nil {
		t.Fatalf("create unprivileged test role: %v", err)
	}
	if _, err := pool.Exec(ctx, `GRANT USAGE ON SCHEMA public TO `+unprivRole); err != nil {
		t.Fatalf("grant schema usage: %v", err)
	}
	if _, err := pool.Exec(ctx, `GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO `+unprivRole); err != nil {
		t.Fatalf("grant table privileges: %v", err)
	}

	// 1. Insert cycle for tenant A under unprivileged role
	c, _ := assessmentcycle.NewAssessmentCycle(cycleA, tenantA, "Tenant A Cycle", assessmentcycle.BoundaryStandalone, "", "", rootA, "alice", now)
	err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+unprivRole); err != nil {
			return err
		}
		return repo.CreateCycle(ctx, c)
	})
	if err != nil {
		t.Fatalf("create cycle under unprivileged role: %v", err)
	}

	// 2. Read under tenant A works
	err = WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+unprivRole); err != nil {
			return err
		}
		got, err := repo.GetCycle(ctx, tenantA, cycleA)
		if err != nil {
			return err
		}
		if got.ID != cycleA {
			return fmt.Errorf("id mismatch: got %v, want %v", got.ID, cycleA)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read cycle under tenant A: %v", err)
	}

	// 3. Read under tenant B fails with ErrNotFound (RLS blocks row visibility)
	err = WithTenant(ctx, pool, tenantB.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+unprivRole); err != nil {
			return err
		}
		_, err := repo.GetCycle(ctx, tenantB, cycleA)
		return err
	})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for tenant B cross-tenant read under RLS, got %v", err)
	}
}
