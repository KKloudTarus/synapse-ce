package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestMigration0134DASTRuns(t *testing.T) {
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
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	id := randHex(t)
	tenantA, tenantB := shared.ID("dr-a-"+id), shared.ID("dr-b-"+id)
	engA := "dr-eng-" + id
	for _, stmt := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, []any{tenantA.String(), tenantB.String()}},
		{`INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'dast-eng')`, []any{engA, tenantA.String()}},
	} {
		if _, err := pool.Exec(ctx, stmt.q, stmt.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, q := range []string{
			`DELETE FROM dast_runs WHERE tenant_id IN ($1,$2)`,
			`DELETE FROM engagements WHERE tenant_id IN ($1,$2)`,
			`DELETE FROM tenants WHERE id IN ($1,$2)`,
		} {
			if _, err := pool.Exec(bg, q, tenantA.String(), tenantB.String()); err != nil {
				t.Errorf("cleanup %q: %v (next run will fail)", q, err)
			}
		}
	})

	repo := NewDASTRunStore(pool)
	tctx := shared.WithTenant(ctx, tenantA)
	now := time.Now().UTC()
	run, err := dastrun.NewRun(shared.ID("run-"+id), tenantA, shared.ID(engA), shared.ID("act-"+id), "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveDASTRun(tctx, run); err != nil {
		t.Fatalf("save queued: %v", err)
	}
	// Advance it to a terminal state and persist the outcome.
	_ = run.Start()
	if err := run.Succeed("confirmed", 200, shared.ID("ev-"+id), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveDASTRun(tctx, run); err != nil {
		t.Fatalf("save succeeded: %v", err)
	}

	got, err := repo.GetDASTRun(tctx, tenantA, run.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != dastrun.RunSucceeded || got.Verdict != "confirmed" || got.HTTPStatus != 200 || got.EvidenceID != shared.ID("ev-"+id) || got.FinishedAt == nil {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	// Cross-tenant read is rejected: tenant B cannot see tenant A's run.
	if _, err := repo.GetDASTRun(shared.WithTenant(ctx, tenantB), tenantB, run.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant read = %v, want ErrNotFound", err)
	}

	// FinishRun is the compare-and-set that terminalizes a run only from 'running'. A second, conflicting
	// FinishRun (a redelivered or lease-overlapping worker that lost the race) must not clobber the first
	// outcome. This is the postgres side of the HIGH-severity clobber fix.
	run2, err := dastrun.NewRun(shared.ID("run2-"+id), tenantA, shared.ID(engA), shared.ID("act2-"+id), "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	_ = run2.Start()
	if err := repo.SaveDASTRun(tctx, run2); err != nil {
		t.Fatalf("save running: %v", err)
	}
	winner := run2
	if err := winner.Succeed("confirmed", 200, shared.ID("ev2-"+id), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if won, err := repo.FinishRun(tctx, tenantA, winner); err != nil || !won {
		t.Fatalf("first FinishRun won=%v err=%v, want won=true", won, err)
	}
	loser := run2 // a stale copy still 'running'
	loser.Fail("interrupted", now.Add(2*time.Second))
	if won, err := repo.FinishRun(tctx, tenantA, loser); err != nil {
		t.Fatalf("second FinishRun: %v", err)
	} else if won {
		t.Fatal("second FinishRun won the CAS; it must not clobber a terminal run")
	}
	got2, err := repo.GetDASTRun(tctx, tenantA, run2.ID)
	if err != nil {
		t.Fatalf("get run2: %v", err)
	}
	if got2.Status != dastrun.RunSucceeded || got2.Verdict != "confirmed" || got2.ErrorCode != "" {
		t.Fatalf("CAS clobbered the recorded success: %+v", got2)
	}
	if got2.EngagementID != shared.ID(engA) || got2.ActionID != shared.ID("act2-"+id) || got2.Actor != "operator" || got2.StartedAt.IsZero() {
		t.Fatalf("identity fields did not round-trip: %+v", got2)
	}

	// SaveDASTRun must not move a terminal row backward (the ON CONFLICT guard). A stale worker writing a
	// failure over a recorded success is a no-op.
	stale := run2
	stale.Fail("interrupted", now.Add(3*time.Second))
	if err := repo.SaveDASTRun(tctx, stale); err != nil {
		t.Fatalf("stale SaveDASTRun errored: %v", err)
	}
	frozen, err := repo.GetDASTRun(tctx, tenantA, run2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if frozen.Status != dastrun.RunSucceeded || frozen.Verdict != "confirmed" {
		t.Fatalf("terminal row was moved backward by a stale save: %+v", frozen)
	}

	// StartRun is the queued -> running compare-and-set: it wins once from queued and loses thereafter, so
	// only one worker executes the probe.
	run3, err := dastrun.NewRun(shared.ID("run3-"+id), tenantA, shared.ID(engA), shared.ID("act3-"+id), "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveDASTRun(tctx, run3); err != nil {
		t.Fatalf("save queued run3: %v", err)
	}
	started := run3
	_ = started.Start()
	if won, err := repo.StartRun(tctx, tenantA, started); err != nil || !won {
		t.Fatalf("first StartRun won=%v err=%v, want won=true", won, err)
	}
	if won, err := repo.StartRun(tctx, tenantA, started); err != nil || won {
		t.Fatalf("second StartRun won=%v err=%v, want won=false", won, err)
	}
}
