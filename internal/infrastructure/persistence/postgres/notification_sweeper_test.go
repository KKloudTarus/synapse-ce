package postgres

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/logstream"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	reconuc "github.com/KKloudTarus/synapse-ce/internal/usecase/recon"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestNotificationSweepersReclaimTenantlessMaintenanceRuns proves maintenance
// may enumerate work across tenants with context.Background(), while each
// terminal write still binds to the engagement's authoritative tenant. It uses
// the PostgreSQL stores and notification projector rather than a fake store so
// a missing tenant context cannot be hidden by a test double.
func TestNotificationSweepersReclaimTenantlessMaintenanceRuns(t *testing.T) {
	fixture := newIdentityFixture(t)
	pool := fixture.runtime
	if err := CheckRLSRuntimeRole(context.Background(), pool); err != nil {
		t.Fatalf("sweeper integration must enforce RLS: %v", err)
	}
	now := time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)
	clock := &notificationTestClock{at: now}
	engagements := NewEngagementRepository(pool)
	jobs := NewScanJobStore(pool)
	runs := NewReconRunStore(pool)
	events := NewNotificationRepository(pool)
	events.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, events, time.Minute)

	for _, tenant := range []shared.ID{"sweep-a", "sweep-b"} {
		ctx := shared.WithTenant(context.Background(), tenant)
		if _, err := fixture.admin.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
			t.Fatal(err)
		}
		eng := notificationSweepEngagement(t, tenant, now)
		startedAt := now.Add(-time.Hour)
		if tenant == "sweep-b" {
			// Project analyses use a hidden engagement that public engagement lookups
			// deliberately exclude. Maintenance must still recover its stranded runs.
			eng.ProjectID = "sweep-project"
			startedAt = now.Add(-2 * time.Hour)
			if _, err := fixture.admin.Exec(ctx, `INSERT INTO projects(id,tenant_id,name,key,source_binding) VALUES($1,$2,'Sweep project','sweep-project','{}')`, eng.ProjectID, tenant); err != nil {
				t.Fatal(err)
			}
		}
		if err := engagements.Create(ctx, eng); err != nil {
			t.Fatal(err)
		}
		// Activate the framework before terminal producers run, as production does.
		if _, err := source.Poll(ctx, now, 100); err != nil {
			t.Fatal(err)
		}
		if err := jobs.CreateRunning(ctx, ports.ScanJob{
			ID:           "sweep-scan-" + tenant.String(),
			EngagementID: eng.ID.String(),
			Target:       "https://" + tenant.String() + ".example.test",
			Kind:         ports.TargetGit,
			Status:       ports.ScanRunning,
			StartedAt:    startedAt,
		}); err != nil {
			t.Fatal(err)
		}
		if err := runs.Save(ctx, recon.Run{
			ID:           shared.ID("sweep-recon-" + tenant.String()),
			EngagementID: eng.ID,
			Tool:         "sweeper-test",
			Target:       tenant.String() + ".example.test",
			Status:       recon.StatusRunning,
			StartedAt:    startedAt,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Deleting an engagement can leave legacy scan rows without an owner. More
	// than a full batch of older orphans must not starve valid tenant-owned work.
	if _, err := fixture.admin.Exec(context.Background(), `INSERT INTO scan_jobs(id,engagement_id,target,kind,status,stage,progress,started_at)
		SELECT 'orphan-scan-'||n, 'deleted-eng-'||n, 'https://example.test', 'git', 'running', '', 0, $1
		FROM generate_series(1,101) AS n`, now.Add(-3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if stale, err := jobs.ListStaleRunning(context.Background(), now.Add(-5*time.Minute), 1); err != nil || len(stale) != 1 || stale[0].TenantID != "sweep-b" {
		t.Fatalf("global oldest scan batch=%+v err=%v; want tenant B without orphan quota", stale, err)
	}
	if stale, err := runs.ListStaleRunning(context.Background(), now.Add(-5*time.Minute), 1); err != nil || len(stale) != 1 || stale[0].TenantID != "sweep-b" {
		t.Fatalf("global oldest recon batch=%+v err=%v; want tenant B", stale, err)
	}

	scaService := scauc.NewService(engagements, nil, nil, nil, jobs, nil, nil, &notificationTestIDs{}, ports.Provenance{}, clock, NewAuditLog(pool), shared.SeverityHigh, 0, nil, nil, nil, nil, nil, nil, nil)
	scaService.SetRunLock(memory.NewRunLock())

	audit := NewAuditLog(pool)
	guard, err := execution.NewGuard(engagements, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := evidenceuc.NewService(memory.NewEvidenceStore(), blob.NewMemory(), audit, clock, &notificationTestIDs{})
	if err != nil {
		t.Fatal(err)
	}
	reconService, err := reconuc.NewService(guard, notificationSweepRunner{}, runs, evidence, engagements, logstream.NewBroker(0), notificationSweepDispatcher{}, clock, &notificationTestIDs{}, map[string]ports.ReconTool{"sweeper-test": notificationSweepTool{}}, time.Minute, 1024, false)
	if err != nil {
		t.Fatal(err)
	}
	reconService.SetRunLock(memory.NewRunLock())

	t.Run("scan sweeper binds each engagement owner", func(t *testing.T) {
		if reclaimed, err := scaService.SweepStaleScans(context.Background(), 5*time.Minute); err != nil || reclaimed != 2 {
			t.Fatalf("reclaim stale scans = %d, %v; want 2, nil", reclaimed, err)
		}
		for _, tenant := range []shared.ID{"sweep-a", "sweep-b"} {
			ctx := shared.WithTenant(context.Background(), tenant)
			if scan, err := jobs.GetJob(ctx, "sweep-scan-"+tenant.String()); err != nil || scan.Status != ports.ScanFailed || scan.FinishedAt == nil {
				t.Fatalf("tenant %s scan = %+v, %v; want persisted failed terminal", tenant, scan, err)
			}
			assertNotificationSweepSourceCount(t, pool, ctx, tenant, "scan_job", "sweep-scan-"+tenant.String(), 1)
		}
	})

	t.Run("recon sweeper binds each engagement owner", func(t *testing.T) {
		if reclaimed, err := reconService.SweepStaleRuns(context.Background(), 5*time.Minute); err != nil || reclaimed != 2 {
			t.Fatalf("reclaim stale recon runs = %d, %v; want 2, nil", reclaimed, err)
		}
		for _, tenant := range []shared.ID{"sweep-a", "sweep-b"} {
			ctx := shared.WithTenant(context.Background(), tenant)
			if run, err := runs.Get(ctx, shared.ID("sweep-recon-"+tenant.String())); err != nil || run.Status != recon.StatusFailed || run.FinishedAt == nil {
				t.Fatalf("tenant %s recon = %+v, %v; want persisted failed terminal", tenant, run, err)
			}
			assertNotificationSweepSourceCount(t, pool, ctx, tenant, "recon_run", "sweep-recon-"+tenant.String(), 1)
		}
	})

	// A restarted maintenance loop must observe terminal state and create no new
	// source record. Projecting twice also leaves exactly one immutable event per run.
	t.Run("restart replay emits one immutable event per run", func(t *testing.T) {
		if reclaimed, err := scaService.SweepStaleScans(context.Background(), 5*time.Minute); err != nil || reclaimed != 0 {
			t.Fatalf("replay stale scans = %d, %v; want 0, nil", reclaimed, err)
		}
		if reclaimed, err := reconService.SweepStaleRuns(context.Background(), 5*time.Minute); err != nil || reclaimed != 0 {
			t.Fatalf("replay stale recon runs = %d, %v; want 0, nil", reclaimed, err)
		}
		for _, tenant := range []shared.ID{"sweep-a", "sweep-b"} {
			ctx := shared.WithTenant(context.Background(), tenant)
			if _, err := source.Poll(ctx, now.Add(time.Minute), 100); err != nil {
				t.Fatal(err)
			}
			if _, err := source.Poll(ctx, now.Add(2*time.Minute), 100); err != nil {
				t.Fatal(err)
			}
			for _, eventType := range []notification.EventType{notification.EventScanFailed, notification.EventReconRunFinished} {
				published, err := events.ListRecentNotificationEvents(ctx, tenant, eventType, 10)
				if err != nil || len(published) != 1 {
					t.Fatalf("tenant %s %s events=%d err=%v; want one", tenant, eventType, len(published), err)
				}
				assertPublishedEventSchema(t, published[0])
			}
			assertNotificationSweepSourceCount(t, pool, ctx, tenant, "scan_job", "sweep-scan-"+tenant.String(), 1)
			assertNotificationSweepSourceCount(t, pool, ctx, tenant, "recon_run", "sweep-recon-"+tenant.String(), 1)
		}
	})
	t.Run("strict cutoff and equal timestamp ordering", func(t *testing.T) {
		ctx := shared.WithTenant(context.Background(), "sweep-a")
		cutoff := now.Add(-5 * time.Minute)
		for _, id := range []shared.ID{"cutoff-a", "cutoff-Z"} {
			if err := runs.Save(ctx, recon.Run{ID: id, EngagementID: "sweep-eng-sweep-a", Tool: "sweeper-test", Target: "example.test", Status: recon.StatusRunning, StartedAt: cutoff}); err != nil {
				t.Fatal(err)
			}
		}
		if err := jobs.CreateRunning(ctx, ports.ScanJob{ID: "cutoff-scan", EngagementID: "sweep-eng-sweep-a", Kind: ports.TargetGit, Target: "https://example.test", Status: ports.ScanRunning, StartedAt: cutoff}); err != nil {
			t.Fatal(err)
		}
		if stale, err := runs.ListStaleRunning(context.Background(), cutoff, 100); err != nil || len(stale) != 0 {
			t.Fatalf("recon cutoff equality included rows: %+v, %v", stale, err)
		}
		if stale, err := jobs.ListStaleRunning(context.Background(), cutoff, 100); err != nil || len(stale) != 0 {
			t.Fatalf("scan cutoff equality included rows: %+v, %v", stale, err)
		}
		if stale, err := runs.ListStaleRunning(context.Background(), cutoff.Add(time.Microsecond), 1); err != nil || len(stale) != 1 || stale[0].Run.ID != "cutoff-Z" {
			t.Fatalf("recon tie ordering: %+v, %v", stale, err)
		}
		if stale, err := jobs.ListStaleRunning(context.Background(), cutoff.Add(time.Microsecond), 1); err != nil || len(stale) != 1 || stale[0].Job.ID != "cutoff-scan" {
			t.Fatalf("scan cutoff crossing: %+v, %v", stale, err)
		}
	})
}

func notificationSweepEngagement(t *testing.T, tenant shared.ID, at time.Time) *engagement.Engagement {
	t.Helper()
	eng, err := engagement.New(shared.ID("sweep-eng-"+tenant.String()), "", "Sweep "+tenant.String(), "", at.Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	eng.TenantID = tenant
	return eng
}

func assertNotificationSweepSourceCount(t *testing.T, pool *pgxpool.Pool, ctx context.Context, tenant shared.ID, sourceKind, sourceID string, want int) {
	t.Helper()
	var got int
	err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND source_kind=$2 AND source_id=$3`, tenant, sourceKind, sourceID).Scan(&got)
	})
	if err != nil || got != want {
		t.Fatalf("tenant %s %s/%s source records=%d err=%v; want %d", tenant, sourceKind, sourceID, got, err, want)
	}
}

type notificationSweepRunner struct{}

func (notificationSweepRunner) Run(context.Context, ports.ToolSpec) (ports.ToolResult, error) {
	return ports.ToolResult{}, fmt.Errorf("runner must not execute while sweeping")
}

type notificationSweepDispatcher struct{}

func (notificationSweepDispatcher) Submit(func(context.Context)) error { return nil }

type notificationSweepTool struct{}

func (notificationSweepTool) Name() string                       { return "sweeper-test" }
func (notificationSweepTool) Binary() string                     { return "sweeper-test" }
func (notificationSweepTool) Action() string                     { return "recon.sweeper-test" }
func (notificationSweepTool) Accepts(engagement.TargetKind) bool { return false }
func (notificationSweepTool) CapabilitySensitive() bool          { return false }
func (notificationSweepTool) BuildArgs(engagement.Target) (ports.ToolSpec, error) {
	return ports.ToolSpec{}, fmt.Errorf("not used")
}
func (notificationSweepTool) Parse([]byte) ([]recon.Result, error) { return nil, nil }
