package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestTelemetryLosses(t *testing.T) {
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
	tenant := shared.ID("tloss-" + id)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_losses WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_events WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tenant.String())
	})

	now := time.Now().UTC().Truncate(time.Microsecond)
	repo := NewTelemetryRepository(pool, time.Hour, 2*time.Hour)
	tctx := shared.WithTenant(ctx, tenant)

	// A stored full batch, plus a Truncated and a Dropped loss on the same host/class.
	if err := repo.Ingest(tctx, ports.TelemetryBatch{TenantID: tenant, HostID: "host-1", AssetID: "asset-1", AgentID: "agent:1",
		Class: detection.ClassProcess, Sequence: 1, SampleRate: 1, Events: []detection.Event{telEvent("ps", now.Add(-5*time.Minute))}}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	trunc := ports.TelemetryLoss{HostID: "host-1", AssetID: "asset-1", Class: detection.ClassProcess, Sequence: 2, Disposition: telemetry.Truncated,
		ObservedCount: 10, KeptCount: 4, DroppedCount: 6, Reason: "ingest budget exceeded", FromAt: now.Add(-4 * time.Minute), ToAt: now.Add(-2 * time.Minute)}
	if err := repo.RecordLoss(tctx, trunc); err != nil {
		t.Fatalf("record truncation: %v", err)
	}
	// Exact immutable retry is idempotent, including sub-microsecond timestamp differences
	// that PostgreSQL cannot preserve.
	retry := trunc
	retry.FromAt = retry.FromAt.Add(123 * time.Nanosecond)
	retry.ToAt = retry.ToAt.Add(456 * time.Nanosecond)
	if err := repo.RecordLoss(tctx, retry); err != nil {
		t.Fatalf("re-record truncation: %v", err)
	}
	contradictory := trunc
	contradictory.AssetID = "asset-2"
	if err := repo.RecordLoss(tctx, contradictory); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("contradictory immutable retry error = %v, want conflict", err)
	}
	if err := repo.RecordLoss(tctx, ports.TelemetryLoss{HostID: "host-1", AssetID: "asset-1", Class: detection.ClassProcess, Sequence: 3, Disposition: telemetry.Dropped,
		ObservedCount: 5, KeptCount: 0, DroppedCount: 5, Reason: "source buffer evicted observed process events", FromAt: now.Add(-3 * time.Minute), ToAt: now.Add(-1 * time.Minute)}); err != nil {
		t.Fatalf("record drop: %v", err)
	}
	// An inconsistent loss is refused (counts do not add up).
	if err := repo.RecordLoss(tctx, ports.TelemetryLoss{HostID: "host-1", AssetID: "asset-1", Class: detection.ClassProcess, Sequence: 4, Disposition: telemetry.Truncated,
		ObservedCount: 10, KeptCount: 4, DroppedCount: 5, Reason: "bad", FromAt: now, ToAt: now}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an inconsistent loss must be refused, got %v", err)
	}

	// The hunt surfaces both losses and reports the window incomplete (never complete despite a full batch).
	res, err := repo.Query(tctx, ports.HuntQuery{HostID: "host-1", Class: detection.ClassProcess})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(res.Losses) != 2 {
		t.Fatalf("both losses must surface (idempotent record kept one truncation), got %+v", res.Losses)
	}
	if res.Complete {
		t.Error("a window with losses must never report complete")
	}
	// A different class in the same window has no losses.
	if r2, _ := repo.Query(tctx, ports.HuntQuery{HostID: "host-1", Class: detection.ClassNetwork}); len(r2.Losses) != 0 {
		t.Errorf("losses must be class-scoped, got %+v", r2.Losses)
	}
	// An asset-pivot hunt (only AssetID set) must ALSO surface the losses — otherwise a truncated/dropped
	// window reads complete on that acceptance pattern (the D2 hole this closes).
	ap, err := repo.Query(tctx, ports.HuntQuery{AssetID: "asset-1", Class: detection.ClassProcess})
	if err != nil {
		t.Fatalf("asset-pivot query: %v", err)
	}
	if len(ap.Losses) != 2 || ap.Complete {
		t.Fatalf("an asset-pivot hunt must surface losses and never be complete, got losses=%+v complete=%v", ap.Losses, ap.Complete)
	}
	// Time-window OVERLAP: a hunt whose Since lands INSIDE the truncation span [now-4m, now-2m] must still
	// surface it (a point anchor at the earliest dropped event would miss this) → never reads complete.
	inside, err := repo.Query(tctx, ports.HuntQuery{HostID: "host-1", Class: detection.ClassProcess, Since: now.Add(-3 * time.Minute), Until: now})
	if err != nil {
		t.Fatalf("windowed query: %v", err)
	}
	if len(inside.Losses) == 0 || inside.Complete {
		t.Fatalf("a hunt window overlapping a dropped span must surface the loss and not be complete, got losses=%+v complete=%v", inside.Losses, inside.Complete)
	}
	// A window entirely AFTER both spans (starts at now, spans end by now-1m) sees no loss.
	if after, _ := repo.Query(tctx, ports.HuntQuery{HostID: "host-1", Class: detection.ClassProcess, Since: now.Add(time.Minute)}); len(after.Losses) != 0 {
		t.Errorf("a window after all dropped spans must see no loss, got %+v", after.Losses)
	}
}
