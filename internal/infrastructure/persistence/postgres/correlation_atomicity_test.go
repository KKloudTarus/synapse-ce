package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/correlation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/incidentuc"
)

func TestCorrelationIncidentAndCheckpointCommitAtomically(t *testing.T) {
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

	suffix := randHex(t)
	tenantID := shared.ID("corr-atomic-tenant-" + suffix)
	engagementID := shared.ID("corr-atomic-eng-" + suffix)
	incidentID := shared.ID("corr-atomic-inc-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenantID.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,$1)`, engagementID.String(), tenantID.String()); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		conn, acquireErr := pool.Acquire(bg)
		if acquireErr != nil {
			return
		}
		defer conn.Release()
		if _, cleanupErr := conn.Exec(bg, `SET session_replication_role = replica`); cleanupErr != nil {
			return
		}
		defer conn.Exec(bg, `SET session_replication_role = origin`)
		_, _ = conn.Exec(bg, `DELETE FROM incident_events WHERE tenant_id=$1`, tenantID.String())
		_, _ = conn.Exec(bg, `DELETE FROM correlation_assignments WHERE tenant_id=$1`, tenantID.String())
		_, _ = conn.Exec(bg, `DELETE FROM correlation_active_sessions WHERE tenant_id=$1`, tenantID.String())
		_, _ = conn.Exec(bg, `DELETE FROM correlation_staged_signals WHERE tenant_id=$1`, tenantID.String())
		_, _ = conn.Exec(bg, `DELETE FROM correlation_checkpoints WHERE tenant_id=$1`, tenantID.String())
		_, _ = conn.Exec(bg, `DELETE FROM engagements WHERE id=$1`, engagementID.String())
		_, _ = conn.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tenantID.String())
	})

	incidentEvents := NewIncidentEventRepository(pool)
	incidents, err := incidentuc.NewService(incidentEvents)
	if err != nil {
		t.Fatal(err)
	}
	state := NewCorrelationStateRepository(pool)
	runner := NewTenantTransactionRunner(pool)
	tenantCtx := shared.WithTenant(ctx, tenantID)
	at := time.Unix(1_800_000_000, 0).UTC()
	snapshot := correlation.SourcePosition{RecordedAt: at, ID: "snapshot-1"}
	started, err := state.BeginCorrelationSnapshot(tenantCtx, engagementID, 0, snapshot, at, "policy")
	if err != nil {
		t.Fatalf("begin snapshot: %v", err)
	}
	first := started
	first.Revision++
	first.Phase = correlation.PhaseConsume
	first.SourceCursor = snapshot
	signal := correlation.Signal{ID: "det-1", AssetID: "asset-1", EntityID: "process-1", OccurredAt: at, Severity: shared.SeverityHigh}
	if err := state.StageCorrelationSignals(tenantCtx, engagementID, started.Revision, first, []correlation.Signal{signal}); err != nil {
		t.Fatalf("stage snapshot: %v", err)
	}
	events := []incident.IncidentEvent{{
		IncidentID: incidentID, Kind: incident.EventCreated, At: at, Actor: "correlator",
		AssetID: "asset-1", Severity: shared.SeverityHigh, DetectionID: "det-1", Title: "correlated detection",
	}}
	assignment := correlation.Assignment{
		SignalID: "det-1", IncidentID: incidentID, AssetID: "asset-1", EntityID: "process-1",
		OccurredAt: at, Severity: shared.SeverityHigh, Outcome: correlation.AssignmentAttached,
	}
	next := first
	next.Revision++
	next.StagedCursor = correlation.SignalPosition{OccurredAt: at, ID: "det-1"}
	next.MaxObservedAt, next.Watermark = at, at.Add(-time.Minute)

	err = runner.Run(tenantCtx, tenantID, func(txCtx context.Context) error {
		if _, _, err := incidents.RecordCorrelation(txCtx, events); err != nil {
			return err
		}
		return state.CommitCorrelationConsume(txCtx, engagementID, 0, first, []correlation.Assignment{assignment}, nil, snapshot, false)
	})
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale checkpoint transaction error=%v, want conflict", err)
	}
	if rolledBack, err := incidentEvents.LoadEvents(tenantCtx, incidentID); err != nil || len(rolledBack) != 0 {
		t.Fatalf("incident append survived checkpoint rollback: events=%v err=%v", rolledBack, err)
	}

	if err := runner.Run(tenantCtx, tenantID, func(txCtx context.Context) error {
		if _, _, err := incidents.RecordCorrelation(txCtx, events); err != nil {
			return err
		}
		return state.CommitCorrelationConsume(txCtx, engagementID, first.Revision, next, []correlation.Assignment{assignment}, nil, snapshot, false)
	}); err != nil {
		t.Fatalf("commit incident and checkpoint: %v", err)
	}
	committedEvents, err := incidentEvents.LoadEvents(tenantCtx, incidentID)
	if err != nil || len(committedEvents) != 1 {
		t.Fatalf("committed incident events=%v err=%v", committedEvents, err)
	}
	committedState, err := state.LoadCorrelationState(tenantCtx, engagementID, []shared.ID{"det-1"}, 100)
	if err != nil || committedState.Checkpoint.Revision != next.Revision || len(committedState.KnownSignalIDs) != 1 {
		t.Fatalf("committed correlation state=%+v err=%v", committedState, err)
	}
}
