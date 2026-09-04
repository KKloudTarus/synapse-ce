package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/platform/logging"
	comparisonuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcomparison"
)

type comparisonBackfillOptions struct {
	tenants           []shared.ID
	actor             string
	dryRun            bool
	repairFailed      bool
	batchSize         int
	backlogWarning    int
	backlogHardLimit  int
	oldestActiveLimit time.Duration
	afterUpdatedAt    time.Time
	afterCycleID      shared.ID
	timeout           time.Duration
}

func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	cfg := config.Load()
	if err := cfg.ValidateAssessmentLifecycleRollout(); err != nil {
		return err
	}
	options, err := parseComparisonBackfillOptions(args, output, cfg)
	if err != nil {
		return err
	}
	if cfg.DBDSN == "" {
		return errors.New("synapse-assessment-comparison-backfill requires SYNAPSE_DB_DSN")
	}
	for _, tenantID := range options.tenants {
		if !cfg.AssessmentShadowForTenant(tenantID.String()) {
			return fmt.Errorf("tenant %s is not enabled by SYNAPSE_ASSESSMENT_IDENTITY_COMPARISON_SHADOW_TENANTS", tenantID)
		}
	}

	log := logging.New(cfg.LogLevel)
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
	cycles := postgres.NewAssessmentCycleRepository(pool)
	comparisons := postgres.NewAssessmentComparisonRepository(pool)
	snapshots := postgres.NewAssessmentSnapshotRepository(pool)
	lineage := postgres.NewFindingLineageRepository(pool)
	verification, err := comparisonuc.NewRetestVerificationReader(lineage, snapshots, postgres.NewRetestRepository(pool))
	if err != nil {
		return err
	}
	service, err := comparisonuc.NewService(
		comparisons, snapshots, cycles, lineage,
		postgres.NewTenantTransactionRunner(pool), postgres.NewAuditLog(pool), clock, ids, verification, nil,
	)
	if err != nil {
		return err
	}
	service.SetAPIStores(nil, postgres.NewJobQueue(pool, ids), nil)
	runner, err := comparisonuc.NewBackfillRunner(service, cycles, comparisons, clock, postgres.NewAuditLog(pool))
	if err != nil {
		return err
	}

	lock := postgres.NewRunLock(pool)
	concurrency := cfg.AssessmentTenantJobs
	if concurrency > len(options.tenants) {
		concurrency = len(options.tenants)
	}
	semaphore := make(chan struct{}, concurrency)
	errorsCh := make(chan error, len(options.tenants))
	var wait sync.WaitGroup
	for _, tenantID := range options.tenants {
		wait.Add(1)
		go func(tenantID shared.ID) {
			defer wait.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				errorsCh <- ctx.Err()
				return
			}
			release, acquired, err := lock.TryLock(ctx, "assessment-comparison-backfill:"+tenantID.String())
			if err != nil {
				errorsCh <- fmt.Errorf("tenant %s: %w", tenantID, err)
				cancel()
				return
			}
			if !acquired {
				errorsCh <- fmt.Errorf("tenant %s already has an assessment comparison backfill running", tenantID)
				cancel()
				return
			}
			defer release()

			result, err := runner.Run(ctx, comparisonuc.BackfillRequest{
				TenantID: tenantID, Actor: options.actor, DryRun: options.dryRun, RepairFailed: options.repairFailed,
				BatchSize: options.batchSize, BacklogWarning: options.backlogWarning, BacklogHardLimit: options.backlogHardLimit,
				OldestActiveLimit: options.oldestActiveLimit, AfterUpdatedAt: options.afterUpdatedAt, AfterCycleID: options.afterCycleID,
			})
			if err != nil {
				errorsCh <- fmt.Errorf("tenant %s: %w", tenantID, err)
				cancel()
				return
			}
			log.Info("assessment comparison backfill completed",
				"tenant_id", tenantID, "dry_run", options.dryRun, "processed", result.Processed, "queued", result.Queued,
				"existing", result.Existing, "would_queue", result.WouldQueue, "skipped", result.Skipped,
				"repair_attempted", result.RepairAttempted, "repaired", result.Repaired, "would_repair", result.WouldRepair,
				"backlog", result.Backlog.Active(), "backlog_warning", result.BacklogWarning,
				"checkpoint_updated_at", result.CheckpointUpdatedAt, "checkpoint_cycle_id", result.CheckpointCycleID,
			)
		}(tenantID)
	}
	wait.Wait()
	close(errorsCh)
	var combined error
	for err := range errorsCh {
		combined = errors.Join(combined, err)
	}
	return combined
}

func parseComparisonBackfillOptions(args []string, output io.Writer, cfg config.Config) (comparisonBackfillOptions, error) {
	flags := flag.NewFlagSet("synapse-assessment-comparison-backfill", flag.ContinueOnError)
	flags.SetOutput(output)
	tenantsValue := flags.String("tenants", "", "comma-separated tenant IDs; maximum four")
	actor := flags.String("actor", "assessment-comparison-backfill", "audit actor")
	dryRun := flags.Bool("dry-run", false, "plan without queueing or repairing comparisons")
	repairFailed := flags.Bool("repair-failed", false, "repair one deterministic batch of failed comparisons before queueing missing comparisons")
	batchSize := flags.Int("batch-size", cfg.AssessmentBatchSize, "cycles or failed comparisons per batch")
	backlogWarning := flags.Int("backlog-warning", cfg.AssessmentBacklogWarning, "queued plus generating warning threshold")
	backlogHardLimit := flags.Int("backlog-hard-limit", cfg.AssessmentBacklogHardLimit, "queued plus generating hard gate")
	oldestActiveLimit := flags.Duration("oldest-active-limit", comparisonuc.DefaultComparisonOldestActiveLimit, "oldest queued or generating hard gate")
	afterUpdatedAtValue := flags.String("after-updated-at", "", "RFC3339 cycle update checkpoint; single tenant only")
	afterCycleIDValue := flags.String("after-cycle-id", "", "cycle ID checkpoint paired with --after-updated-at")
	timeout := flags.Duration("timeout", 2*time.Hour, "overall command timeout")
	if err := flags.Parse(args); err != nil {
		return comparisonBackfillOptions{}, err
	}
	if flags.NArg() != 0 {
		return comparisonBackfillOptions{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
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
		return comparisonBackfillOptions{}, errors.New("--tenants requires between one and four unique tenant IDs")
	}
	if strings.TrimSpace(*actor) == "" || len(strings.TrimSpace(*actor)) > 256 {
		return comparisonBackfillOptions{}, errors.New("--actor must contain between 1 and 256 characters")
	}
	if *batchSize < 1 || *batchSize > comparisonuc.MaxComparisonBackfillBatch {
		return comparisonBackfillOptions{}, fmt.Errorf("--batch-size must be between 1 and %d", comparisonuc.MaxComparisonBackfillBatch)
	}
	if *backlogWarning < 1 || *backlogWarning > comparisonuc.DefaultComparisonBacklogWarning {
		return comparisonBackfillOptions{}, fmt.Errorf("--backlog-warning must be between 1 and %d", comparisonuc.DefaultComparisonBacklogWarning)
	}
	if *backlogHardLimit < *backlogWarning || *backlogHardLimit > comparisonuc.DefaultComparisonBacklogHardLimit {
		return comparisonBackfillOptions{}, fmt.Errorf("--backlog-hard-limit must be between warning threshold %d and %d", *backlogWarning, comparisonuc.DefaultComparisonBacklogHardLimit)
	}
	if *oldestActiveLimit <= 0 || *timeout <= 0 {
		return comparisonBackfillOptions{}, errors.New("--oldest-active-limit and --timeout must be positive")
	}
	if (strings.TrimSpace(*afterUpdatedAtValue) == "") != (strings.TrimSpace(*afterCycleIDValue) == "") {
		return comparisonBackfillOptions{}, errors.New("--after-updated-at and --after-cycle-id must be supplied together")
	}
	var afterUpdatedAt time.Time
	if value := strings.TrimSpace(*afterUpdatedAtValue); value != "" {
		if len(tenants) != 1 {
			return comparisonBackfillOptions{}, errors.New("comparison backfill checkpoint requires exactly one tenant")
		}
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return comparisonBackfillOptions{}, fmt.Errorf("--after-updated-at must be RFC3339: %w", err)
		}
		afterUpdatedAt = parsed.UTC()
	}
	return comparisonBackfillOptions{
		tenants: tenants, actor: strings.TrimSpace(*actor), dryRun: *dryRun, repairFailed: *repairFailed,
		batchSize: *batchSize, backlogWarning: *backlogWarning, backlogHardLimit: *backlogHardLimit,
		oldestActiveLimit: *oldestActiveLimit, afterUpdatedAt: afterUpdatedAt,
		afterCycleID: shared.ID(strings.TrimSpace(*afterCycleIDValue)), timeout: *timeout,
	}, nil
}
