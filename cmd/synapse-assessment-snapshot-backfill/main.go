// Command synapse-assessment-snapshot-backfill projects historical scan evidence into immutable legacy Assessment Snapshots.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/platform/logging"
	snapshotuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentsnapshot"
)

type snapshotBackfillOptions struct {
	tenants       []shared.ID
	actor         string
	dryRun        bool
	batchSize     int
	resumeAfter   shared.ID
	timeout       time.Duration
	leaseDuration time.Duration
}

func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	options, err := parseSnapshotBackfillOptions(args, output)
	if err != nil {
		return err
	}
	cfg := config.Load()
	log := logging.New(cfg.LogLevel)
	if cfg.DBDSN == "" {
		return errors.New("synapse-assessment-snapshot-backfill requires SYNAPSE_DB_DSN")
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, options.timeout)
	defer cancel()
	pool, err := postgres.Connect(ctx, cfg.DBDSN)
	if err != nil {
		return err
	}
	defer pool.Close()

	clock, ids := idgen.SystemClock{}, idgen.RandomID{}
	engagements := postgres.NewEngagementRepository(pool)
	cycles := postgres.NewAssessmentCycleRepository(pool)
	snapshots := postgres.NewAssessmentSnapshotRepository(pool)
	runs := postgres.NewScanRunStore(pool)
	results := postgres.NewScanResultStore(pool)
	audit := postgres.NewAuditLog(pool)
	projector, err := snapshotuc.NewLegacyProjector(snapshots, cycles, postgres.NewTenantTransactionRunner(pool), ids, clock, audit)
	if err != nil {
		return err
	}
	runner, err := snapshotuc.NewBackfillRunner(projector, engagements, postgres.NewAssessmentSnapshotBackfillRepository(pool), runs, results, ids, clock, audit, nil)
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	if len(hostname) > 160 {
		hostname = hostname[:160]
	}
	ctx, cancelRuns := context.WithCancel(ctx)
	defer cancelRuns()
	errorsCh := make(chan error, len(options.tenants))
	var wait sync.WaitGroup
	for index, tenantID := range options.tenants {
		wait.Add(1)
		go func(index int, tenantID shared.ID) {
			defer wait.Done()
			leaseOwner := strings.Join([]string{hostname, strconv.Itoa(os.Getpid()), strconv.Itoa(index)}, "-")
			log.Info("assessment snapshot backfill started", "tenant_id", tenantID, "dry_run", options.dryRun, "batch_size", options.batchSize)
			run, err := runner.Run(ctx, snapshotuc.BackfillRequest{
				TenantID: tenantID, Actor: options.actor, LeaseOwner: leaseOwner, DryRun: options.dryRun,
				BatchSize: options.batchSize, ResumeAfter: options.resumeAfter, LeaseDuration: options.leaseDuration,
			})
			if err == nil && run.FailedCount > 0 {
				err = fmt.Errorf("tenant %s snapshot backfill completed with %d stable failure records", tenantID, run.FailedCount)
			}
			if err != nil {
				errorsCh <- fmt.Errorf("tenant %s: %w", tenantID, err)
				cancelRuns()
				return
			}
			log.Info("assessment snapshot backfill completed", "tenant_id", tenantID, "run_id", run.ID, "processed", run.ProcessedCount, "created", run.CreatedCount, "would_create", run.WouldCreateCount, "skipped", run.SkippedCount, "failed", run.FailedCount, "checkpoint", run.CheckpointAssessment)
		}(index, tenantID)
	}
	wait.Wait()
	close(errorsCh)
	var combined error
	for err := range errorsCh {
		combined = errors.Join(combined, err)
	}
	return combined
}

func parseSnapshotBackfillOptions(args []string, output io.Writer) (snapshotBackfillOptions, error) {
	flags := flag.NewFlagSet("synapse-assessment-snapshot-backfill", flag.ContinueOnError)
	flags.SetOutput(output)
	tenantsValue := flags.String("tenants", "", "comma-separated tenant IDs; maximum four")
	actor := flags.String("actor", "assessment-snapshot-backfill", "audit actor")
	dryRun := flags.Bool("dry-run", false, "plan without creating legacy Snapshots")
	batchSize := flags.Int("batch-size", snapshotuc.DefaultAssessmentSnapshotBackfillBatch, "rows per committed batch")
	resumeAfter := flags.String("resume-after", "", "initial Assessment ID checkpoint; single tenant only")
	timeout := flags.Duration("timeout", 30*time.Minute, "overall command timeout")
	leaseDuration := flags.Duration("lease-duration", 10*time.Minute, "per-tenant job lease")
	if err := flags.Parse(args); err != nil {
		return snapshotBackfillOptions{}, err
	}
	if flags.NArg() != 0 {
		return snapshotBackfillOptions{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	seen := map[shared.ID]bool{}
	tenants := make([]shared.ID, 0, 4)
	for _, value := range strings.Split(*tenantsValue, ",") {
		tenantID := shared.ID(strings.TrimSpace(value))
		if tenantID.IsZero() || seen[tenantID] {
			continue
		}
		seen[tenantID] = true
		tenants = append(tenants, tenantID)
	}
	if len(tenants) == 0 || len(tenants) > 4 {
		return snapshotBackfillOptions{}, errors.New("--tenants requires between one and four unique tenant IDs")
	}
	if *batchSize < 1 || *batchSize > snapshotuc.MaxAssessmentSnapshotBackfillBatch {
		return snapshotBackfillOptions{}, fmt.Errorf("--batch-size must be between 1 and %d", snapshotuc.MaxAssessmentSnapshotBackfillBatch)
	}
	if strings.TrimSpace(*actor) == "" || len(strings.TrimSpace(*actor)) > 256 {
		return snapshotBackfillOptions{}, errors.New("--actor must contain between 1 and 256 characters")
	}
	if *timeout <= 0 || *leaseDuration <= 0 {
		return snapshotBackfillOptions{}, errors.New("--timeout and --lease-duration must be positive")
	}
	if strings.TrimSpace(*resumeAfter) != "" && len(tenants) != 1 {
		return snapshotBackfillOptions{}, errors.New("--resume-after requires exactly one tenant")
	}
	return snapshotBackfillOptions{
		tenants: tenants, actor: strings.TrimSpace(*actor), dryRun: *dryRun, batchSize: *batchSize,
		resumeAfter: shared.ID(strings.TrimSpace(*resumeAfter)), timeout: *timeout, leaseDuration: *leaseDuration,
	}, nil
}
