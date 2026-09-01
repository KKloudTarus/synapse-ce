// Command synapse-finding-lineage-backfill projects legacy Findings into versioned Identities and immutable Observations.
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
	lineageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findinglineage"
)

type lineageBackfillOptions struct {
	tenants       []shared.ID
	producers     []string
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
	options, err := parseLineageBackfillOptions(args, output)
	if err != nil {
		return err
	}
	cfg := config.Load()
	log := logging.New(cfg.LogLevel)
	if cfg.DBDSN == "" {
		return errors.New("synapse-finding-lineage-backfill requires SYNAPSE_DB_DSN")
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
	audit := postgres.NewAuditLog(pool)
	lineage, err := lineageuc.NewService(postgres.NewFindingLineageRepository(pool), postgres.NewTenantTransactionRunner(pool), audit, clock, ids, nil)
	if err != nil {
		return err
	}
	backfillRepository := postgres.NewFindingLineageBackfillRepository(pool)
	runner, err := lineageuc.NewFindingLineageBackfillRunner(
		lineage, backfillRepository, backfillRepository, postgres.NewAssessmentSnapshotRepository(pool),
		postgres.NewVulnerabilityOccurrenceStore(pool), postgres.NewJudgmentRepository(pool), ids, clock, audit, nil,
	)
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
			log.Info("finding lineage backfill started", "tenant_id", tenantID, "dry_run", options.dryRun, "batch_size", options.batchSize)
			run, err := runner.RunBackfill(ctx, lineageuc.FindingLineageBackfillRequest{
				TenantID: tenantID, Actor: options.actor, LeaseOwner: leaseOwner, DryRun: options.dryRun,
				BatchSize: options.batchSize, ProducerFilter: options.producers, ResumeAfter: options.resumeAfter, LeaseDuration: options.leaseDuration,
			})
			if err != nil {
				errorsCh <- fmt.Errorf("tenant %s: %w", tenantID, err)
				cancelRuns()
				return
			}
			log.Info("finding lineage backfill completed", "tenant_id", tenantID, "run_id", run.ID, "processed", run.ProcessedCount,
				"observation_created", run.ObservationCreatedCount, "provisional_candidate_created", run.ProvisionalCandidateCount, "skipped", run.SkippedCount, "checkpoint", run.CheckpointFinding)
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

func parseLineageBackfillOptions(args []string, output io.Writer) (lineageBackfillOptions, error) {
	flags := flag.NewFlagSet("synapse-finding-lineage-backfill", flag.ContinueOnError)
	flags.SetOutput(output)
	tenantsValue := flags.String("tenants", "", "comma-separated tenant IDs; maximum four")
	producersValue := flags.String("producers", "", "optional comma-separated producer filters")
	actor := flags.String("actor", "finding-lineage-backfill", "audit actor")
	dryRun := flags.Bool("dry-run", false, "plan outcomes without writing lineage objects")
	batchSize := flags.Int("batch-size", lineageuc.DefaultFindingLineageBackfillBatch, "source Findings per committed batch")
	resumeAfter := flags.String("resume-after", "", "initial Finding ID checkpoint; single tenant only")
	timeout := flags.Duration("timeout", 30*time.Minute, "overall command timeout")
	leaseDuration := flags.Duration("lease-duration", 10*time.Minute, "per-tenant job lease")
	if err := flags.Parse(args); err != nil {
		return lineageBackfillOptions{}, err
	}
	if flags.NArg() != 0 {
		return lineageBackfillOptions{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
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
		return lineageBackfillOptions{}, errors.New("--tenants requires between one and four unique tenant IDs")
	}
	if *batchSize < 1 || *batchSize > lineageuc.MaxFindingLineageBackfillBatch {
		return lineageBackfillOptions{}, fmt.Errorf("--batch-size must be between 1 and %d", lineageuc.MaxFindingLineageBackfillBatch)
	}
	if strings.TrimSpace(*actor) == "" || len(strings.TrimSpace(*actor)) > 256 {
		return lineageBackfillOptions{}, errors.New("--actor must contain between 1 and 256 characters")
	}
	if *timeout <= 0 || *leaseDuration <= 0 {
		return lineageBackfillOptions{}, errors.New("--timeout and --lease-duration must be positive")
	}
	if strings.TrimSpace(*resumeAfter) != "" && len(tenants) != 1 {
		return lineageBackfillOptions{}, errors.New("--resume-after requires exactly one tenant")
	}
	producerValues := strings.Split(*producersValue, ",")
	producers, err := lineageuc.NormalizeFindingLineageProducerFilters(producerValues)
	if err != nil {
		return lineageBackfillOptions{}, err
	}
	return lineageBackfillOptions{
		tenants: tenants, producers: producers, actor: strings.TrimSpace(*actor), dryRun: *dryRun, batchSize: *batchSize,
		resumeAfter: shared.ID(strings.TrimSpace(*resumeAfter)), timeout: *timeout, leaseDuration: *leaseDuration,
	}, nil
}
