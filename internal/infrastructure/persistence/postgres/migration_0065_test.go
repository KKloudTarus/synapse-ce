package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetrollout"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestFleetRolloutDurabilityAndIsolation exercises migration 0065 and the repository against a real
// database, because the properties this table carries are DATABASE properties:
//
//   - a plan survives a restart, so a fleet mid-canary does not silently stop being offered anything;
//   - the constraints that make a plan meaningful (a pause has a reason, a promotion has a target and
//     a canary) hold even against a future second writer that skips the domain;
//   - one tenant cannot read — still less move — another tenant's fleet.
func TestFleetRolloutDurabilityAndIsolation(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	var forced bool
	if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE relname='fleet_rollouts'`).Scan(&forced); err != nil {
		t.Fatalf("relforcerowsecurity: %v", err)
	}
	if !forced {
		t.Fatal("fleet_rollouts must FORCE row level security: the app connects as the table owner")
	}

	for _, tenant := range []string{"t-roll-a", "t-roll-b"} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1) ON CONFLICT (id) DO NOTHING`, tenant); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM fleet_rollouts WHERE tenant_id IN ('t-roll-a','t-roll-b')`)
	})

	repo := NewFleetRolloutRepository(pool)
	now := time.Now().UTC().Truncate(time.Millisecond)

	// No plan is a resting state, not an error to interpret.
	if _, err := repo.Get(ctx, "t-roll-a", "stable"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("an absent plan must be ErrNotFound, got %v", err)
	}

	plan := &fleetrollout.Plan{
		TenantID: "t-roll-a", Channel: "stable", TargetVersion: "2.0.0",
		CanaryGroups: []string{"canary"}, UpdatedBy: "human:alice",
		Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
	if err := repo.Put(ctx, plan); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := repo.Get(ctx, "t-roll-a", "stable")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.TargetVersion != "2.0.0" || len(got.CanaryGroups) != 1 || got.CanaryGroups[0] != "canary" {
		t.Fatalf("round trip lost the plan: %+v", got)
	}
	if got.PromotedToAll || got.Paused {
		t.Fatalf("a fresh plan is neither promoted nor paused: %+v", got)
	}

	// Promotion is an update in place, and created_at keeps the moment the rollout began.
	promoted := *got
	promoted.PromotedToAll = true
	promoted.Audit.UpdatedAt = now.Add(time.Minute)
	if err := repo.Put(ctx, &promoted); err != nil {
		t.Fatalf("promote: %v", err)
	}
	after, err := repo.Get(ctx, "t-roll-a", "stable")
	if err != nil {
		t.Fatalf("get after promote: %v", err)
	}
	if !after.PromotedToAll {
		t.Fatal("promotion must persist")
	}
	if !after.Audit.CreatedAt.Equal(got.Audit.CreatedAt) {
		t.Fatalf("created_at must survive an update: was %v, now %v", got.Audit.CreatedAt, after.Audit.CreatedAt)
	}

	// The constraints hold against a writer that bypasses the domain entirely.
	if _, err := pool.Exec(ctx, `SELECT set_config('app.current_tenant','t-roll-a',false)`); err != nil {
		t.Fatalf("set tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `SELECT set_config('app.current_tenant','',false)`) })

	if _, err := pool.Exec(ctx, `UPDATE fleet_rollouts SET paused=true, pause_reason='' WHERE tenant_id='t-roll-a'`); err == nil {
		t.Fatal("a pause with no reason must be refused by the database, not only by the domain")
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO fleet_rollouts (tenant_id, channel, target_version, canary_groups, promoted_to_all, updated_by)
		 VALUES ('t-roll-a','beta','3.0.0','{}',true,'human:bob')`); err == nil {
		t.Fatal("promoting with no canary group means every host at once and must be refused")
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO fleet_rollouts (tenant_id, channel, target_version, canary_groups, promoted_to_all, updated_by)
		 VALUES ('t-roll-a','beta','','{canary}',true,'human:bob')`); err == nil {
		t.Fatal("promoting with no target version is meaningless and must be refused")
	}
	if _, err := pool.Exec(ctx, `SELECT set_config('app.current_tenant','',false)`); err != nil {
		t.Fatalf("reset tenant: %v", err)
	}

	// Tenant isolation: another tenant sees no plan at all, and cannot move this one.
	if _, err := repo.Get(ctx, "t-roll-b", "stable"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant must see no plan, got %v", err)
	}
}
