package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/correlation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func stageCorrelationTestSnapshot(ctx context.Context, repo *CorrelationStateRepository, engagement shared.ID, at time.Time) (correlation.Checkpoint, correlation.SourcePosition, error) {
	snapshot := correlation.SourcePosition{RecordedAt: at, ID: "snapshot-1"}
	started, err := repo.BeginCorrelationSnapshot(ctx, engagement, 0, snapshot, at, "policy")
	if err != nil {
		return correlation.Checkpoint{}, correlation.SourcePosition{}, err
	}
	next := started
	next.Revision++
	next.Phase = correlation.PhaseConsume
	next.SourceCursor = snapshot
	signal := correlation.Signal{ID: "det-1", AssetID: "asset-1", EntityID: "process-1", OccurredAt: at, Severity: shared.SeverityHigh}
	if err := repo.StageCorrelationSignals(ctx, engagement, started.Revision, next, []correlation.Signal{signal}); err != nil {
		return correlation.Checkpoint{}, correlation.SourcePosition{}, err
	}
	return next, snapshot, nil
}

func TestCorrelationStateRepository(t *testing.T) {
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
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	suffix := randHex(t)
	tenant := shared.ID("corr-tenant-" + suffix)
	engagement := shared.ID("corr-eng-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,$1)`, engagement.String(), tenant.String()); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM correlation_assignments WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(context.Background(), `DELETE FROM correlation_active_sessions WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(context.Background(), `DELETE FROM correlation_staged_signals WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(context.Background(), `DELETE FROM correlation_checkpoints WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(context.Background(), `DELETE FROM engagements WHERE id=$1`, engagement.String())
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.String())
	})

	repo := NewCorrelationStateRepository(pool)
	tenantCtx := shared.WithTenant(ctx, tenant)
	at := time.Unix(1_800_000_000, 0).UTC()
	staged, snapshot, err := stageCorrelationTestSnapshot(tenantCtx, repo, engagement, at)
	if err != nil {
		t.Fatalf("stage snapshot: %v", err)
	}
	next := staged
	next.Revision++
	next.StagedCursor = correlation.SignalPosition{OccurredAt: at, ID: "det-1"}
	next.MaxObservedAt, next.Watermark = at, at.Add(-time.Minute)
	added := []correlation.Assignment{{SignalID: "det-1", IncidentID: "inc-1", AssetID: "asset-1", EntityID: "process-1", OccurredAt: at, Severity: shared.SeverityHigh, Outcome: correlation.AssignmentAttached}}
	if err := repo.CommitCorrelationConsume(tenantCtx, engagement, staged.Revision, next, added, nil, snapshot, false); err != nil {
		t.Fatalf("advance: %v", err)
	}
	if err := repo.CommitCorrelationConsume(tenantCtx, engagement, staged.Revision, next, added, nil, snapshot, false); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale advance must conflict, got %v", err)
	}
	got, err := repo.LoadCorrelationState(tenantCtx, engagement, []shared.ID{"det-1"}, 100)
	assignmentMatches := len(got.ActiveSessions) == 0 && len(got.KnownSignalIDs) == 1
	checkpointMatches := got.Checkpoint.Revision == next.Revision && got.Checkpoint.MaxObservedAt.Equal(next.MaxObservedAt) && got.Checkpoint.Watermark.Equal(next.Watermark)
	if err != nil || !checkpointMatches || !assignmentMatches {
		t.Fatalf("loaded state mismatch: %+v err=%v", got, err)
	}
	other, err := repo.LoadCorrelationState(shared.WithTenant(ctx, "other-tenant"), engagement, []shared.ID{"det-1"}, 100)
	if err != nil || other.Checkpoint.Revision != 0 || len(other.ActiveSessions) != 0 || len(other.KnownSignalIDs) != 0 {
		t.Fatalf("cross-tenant state leaked: %+v err=%v", other, err)
	}
}
