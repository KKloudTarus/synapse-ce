package memory

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func mkRun(t *testing.T, tenant, id shared.ID) dastrun.Run {
	t.Helper()
	run, err := dastrun.NewRun(id, tenant, "eng-1", "act-1", "operator", time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatalf("NewRun: %v", err)
	}
	return run
}

func TestDASTRunStoreTenantIsolationByCompositeKey(t *testing.T) {
	// A run id is only unique within a tenant. Two tenants using the same id must not collide: reading
	// tenant B's id must not return tenant A's run, and saving B must not overwrite A. This matches the
	// Postgres (tenant_id, id) primary key.
	s := NewDASTRunStore()
	ctx := context.Background()
	shared0 := shared.ID("dup-id")
	if err := s.SaveDASTRun(ctx, mkRun(t, "tenant-a", shared0)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveDASTRun(ctx, mkRun(t, "tenant-b", shared0)); err != nil {
		t.Fatal(err)
	}
	a, err := s.GetDASTRun(ctx, "tenant-a", shared0)
	if err != nil || a.TenantID != "tenant-a" {
		t.Fatalf("tenant-a run = %+v, err=%v", a, err)
	}
	b, err := s.GetDASTRun(ctx, "tenant-b", shared0)
	if err != nil || b.TenantID != "tenant-b" {
		t.Fatalf("tenant-b run = %+v, err=%v", b, err)
	}
	// A tenant cannot read another tenant's run under the same id.
	if _, err := s.GetDASTRun(ctx, "tenant-c", shared0); err == nil {
		t.Fatal("tenant-c read a run it does not own")
	}
}

func TestDASTRunStoreTerminalRunIsImmutable(t *testing.T) {
	// Once a run is terminal, SaveDASTRun must not move it backward. This is the defense-in-depth that
	// stops a stale worker (whose lease was reclaimed) from un-terminalizing a recorded outcome.
	s := NewDASTRunStore()
	ctx := context.Background()
	run := mkRun(t, "t1", "run-1")
	_ = run.Start()
	if err := s.SaveDASTRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	succeeded := run
	if err := succeeded.Succeed("confirmed", 200, "ev-1", time.Unix(1_700_000_001, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FinishRun(ctx, "t1", succeeded); err != nil {
		t.Fatal(err)
	}
	// A stale worker tries to write the run back to running, then to a failure.
	stale := run // still 'running'
	if err := s.SaveDASTRun(ctx, stale); err != nil {
		t.Fatal(err)
	}
	failed := run
	failed.Fail("interrupted", time.Unix(1_700_000_002, 0).UTC())
	if err := s.SaveDASTRun(ctx, failed); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDASTRun(ctx, "t1", "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != dastrun.RunSucceeded || got.Verdict != "confirmed" || got.ErrorCode != "" {
		t.Fatalf("terminal run was mutated by a stale write: %+v", got)
	}
}

func TestDASTRunStoreFinishRunCompareAndSet(t *testing.T) {
	// FinishRun only terminalizes from 'running', and a second conflicting FinishRun does not clobber.
	s := NewDASTRunStore()
	ctx := context.Background()
	run := mkRun(t, "t1", "run-2")
	_ = run.Start()
	if err := s.SaveDASTRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	winner := run
	if err := winner.Succeed("confirmed", 200, "ev-2", time.Unix(1_700_000_001, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	if won, err := s.FinishRun(ctx, "t1", winner); err != nil || !won {
		t.Fatalf("first FinishRun won=%v err=%v", won, err)
	}
	loser := run // stale 'running' copy
	loser.Fail("interrupted", time.Unix(1_700_000_002, 0).UTC())
	if won, err := s.FinishRun(ctx, "t1", loser); err != nil || won {
		t.Fatalf("second FinishRun won=%v err=%v, want won=false", won, err)
	}
	got, _ := s.GetDASTRun(ctx, "t1", "run-2")
	if got.Status != dastrun.RunSucceeded {
		t.Fatalf("CAS clobbered success: %+v", got)
	}
}

func TestDASTRunStoreStartRunCompareAndSet(t *testing.T) {
	// StartRun moves queued -> running only once; a second delivery that finds the run already running
	// loses the compare-and-set (won=false) and must not go on to probe.
	s := NewDASTRunStore()
	ctx := context.Background()
	run := mkRun(t, "t1", "run-s")
	if err := s.SaveDASTRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	running := run
	_ = running.Start()
	if won, err := s.StartRun(ctx, "t1", running); err != nil || !won {
		t.Fatalf("first StartRun won=%v err=%v, want won=true", won, err)
	}
	if won, err := s.StartRun(ctx, "t1", running); err != nil || won {
		t.Fatalf("second StartRun won=%v err=%v, want won=false", won, err)
	}
}
