package postgres

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	comparisonuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcomparison"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	lineageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/worker"
)

// Explicit browser-QA helper for macOS hosts, where the all-purpose production
// worker correctly refuses to boot without Linux/amd64 bubblewrap. This uses the
// same durable claim loop and application handlers, but registers NO executable
// scan/recon/integration jobs. It can only connect to an isolated local UI test DB.
// It does not replace production-worker sandbox conformance testing.
func TestAssessmentUIWorker(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_ASSESSMENT_UI_WORKER_DSN")
	if dsn == "" {
		t.Skip("explicit local browser-QA helper")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Hostname() != "127.0.0.1" || !strings.HasPrefix(parsed.Path, "/assessment_cycle_ui_") {
		t.Fatal("browser-QA worker requires an isolated loopback assessment_cycle_ui_ database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := CheckRLSRuntimeRole(ctx, pool); err != nil {
		t.Fatal(err)
	}
	clock, ids := idgen.SystemClock{}, idgen.RandomID{}
	audit, tx := NewAuditLog(pool), NewTenantTransactionRunner(pool)
	queue, cycles := NewJobQueue(pool, ids), NewAssessmentCycleRepository(pool)
	snapshots, lineageStore, comparisons := NewAssessmentSnapshotRepository(pool), NewFindingLineageRepository(pool), NewAssessmentComparisonRepository(pool)
	verification, err := comparisonuc.NewRetestVerificationReader(lineageStore, snapshots, NewRetestRepository(pool))
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := comparisonuc.NewService(comparisons, snapshots, cycles, lineageStore, tx, audit, clock, ids, verification, nil)
	if err != nil {
		t.Fatal(err)
	}
	lineage, err := lineageuc.NewService(lineageStore, tx, audit, clock, ids, nil)
	if err != nil {
		t.Fatal(err)
	}
	comparison.SetAPIStores(nil, queue, lineage)
	decisions, err := cycleuc.NewClosureDecisionReader(lineageStore, snapshots, NewRetestRepository(pool), NewSLAStore(pool))
	if err != nil {
		t.Fatal(err)
	}
	reports, err := cycleuc.NewClosureReportService(cycles, cycles, snapshots, comparisons, decisions, audit)
	if err != nil {
		t.Fatal(err)
	}
	jobs := worker.New(queue, map[string]worker.Handler{
		comparisonuc.JobKind:                   worker.HandlerFunc(func(ctx context.Context, job ports.QueuedJob) error { return comparison.HandleJob(ctx, job.Payload) }),
		cycleuc.AssessmentClosureReportJobKind: worker.HandlerFunc(reports.HandleJob),
	}, worker.Config{Poll: 250 * time.Millisecond, Visibility: 2 * time.Minute, MaxAttempts: 3}, nil)
	if err := jobs.Run(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
