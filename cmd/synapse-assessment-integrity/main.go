// Command synapse-assessment-integrity runs the read-only Assessment Cycle integrity verifier.
package main

import (
	"context"
	"encoding/json"
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
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
)

type integrityOptions struct {
	tenants       []shared.ID
	actor         string
	batchSize     int
	timeout       time.Duration
	leaseDuration time.Duration
}

type findingOutput struct {
	TenantID     shared.ID       `json:"tenant_id"`
	RunID        shared.ID       `json:"run_id"`
	OccurrenceID string          `json:"occurrence_id"`
	AssessmentID shared.ID       `json:"assessment_id"`
	CycleID      shared.ID       `json:"cycle_id,omitempty"`
	MemberID     shared.ID       `json:"member_id,omitempty"`
	ReasonCode   string          `json:"reason_code"`
	Severity     string          `json:"severity"`
	RepairPlan   json.RawMessage `json:"repair_plan"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	options, err := parseIntegrityOptions(args, os.Stderr)
	if err != nil {
		return err
	}
	cfg := config.Load()
	log := logging.New(cfg.LogLevel)
	if cfg.DBDSN == "" {
		return errors.New("synapse-assessment-integrity requires SYNAPSE_DB_DSN")
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
	repository := postgres.NewAssessmentCycleIntegrityRepository(pool)
	audit := postgres.NewAuditLog(pool)
	verifier, err := cycleuc.NewIntegrityVerifier(repository, repository, ids, clock, audit, nil)
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	if len(hostname) > 160 {
		hostname = hostname[:160]
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	var outputMu sync.Mutex
	errorsCh := make(chan error, len(options.tenants))
	var wait sync.WaitGroup
	for index, tenantID := range options.tenants {
		wait.Add(1)
		go func(index int, tenantID shared.ID) {
			defer wait.Done()
			leaseOwner := strings.Join([]string{hostname, strconv.Itoa(os.Getpid()), strconv.Itoa(index)}, "-")
			log.Info("assessment cycle integrity verification started", "tenant_id", tenantID, "batch_size", options.batchSize)
			run, err := verifier.Run(ctx, cycleuc.IntegrityRequest{TenantID: tenantID, Actor: options.actor, LeaseOwner: leaseOwner, BatchSize: options.batchSize, LeaseDuration: options.leaseDuration})
			if err != nil {
				errorsCh <- fmt.Errorf("tenant %s: %w", tenantID, err)
				return
			}
			findings, err := repository.ListAssessmentCycleIntegrityFindings(ctx, tenantID, run.ID)
			if err != nil {
				errorsCh <- fmt.Errorf("tenant %s list findings: %w", tenantID, err)
				return
			}
			outputMu.Lock()
			for _, finding := range findings {
				if err := encoder.Encode(findingOutput{
					TenantID: finding.TenantID, RunID: finding.RunID, OccurrenceID: finding.OccurrenceID, AssessmentID: finding.AssessmentID,
					CycleID: finding.CycleID, MemberID: finding.MemberID, ReasonCode: finding.ReasonCode, Severity: finding.Severity, RepairPlan: finding.RepairPlan,
				}); err != nil {
					outputMu.Unlock()
					errorsCh <- fmt.Errorf("tenant %s write finding output: %w", tenantID, err)
					return
				}
			}
			outputMu.Unlock()
			log.Info("assessment cycle integrity verification completed", "tenant_id", tenantID, "run_id", run.ID, "scanned", run.ScannedCount, "clean", run.CleanCount, "findings", run.FindingCount, "checkpoint", run.CheckpointAssessment)
			if run.FindingCount > 0 {
				errorsCh <- fmt.Errorf("tenant %s integrity verification found %d repair plans", tenantID, run.FindingCount)
			}
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

func parseIntegrityOptions(args []string, output io.Writer) (integrityOptions, error) {
	flags := flag.NewFlagSet("synapse-assessment-integrity", flag.ContinueOnError)
	flags.SetOutput(output)
	tenantsValue := flags.String("tenants", "", "comma-separated tenant IDs; maximum four")
	actor := flags.String("actor", "assessment-cycle-integrity", "audit actor")
	dryRun := flags.Bool("dry-run", true, "read-only verification mode")
	batchSize := flags.Int("batch-size", cycleuc.DefaultAssessmentCycleIntegrityBatch, "Assessments per committed checkpoint")
	timeout := flags.Duration("timeout", 30*time.Minute, "overall command timeout")
	leaseDuration := flags.Duration("lease-duration", 10*time.Minute, "per-tenant verifier lease")
	if err := flags.Parse(args); err != nil {
		return integrityOptions{}, err
	}
	if flags.NArg() != 0 {
		return integrityOptions{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if !*dryRun {
		return integrityOptions{}, errors.New("the integrity verifier is read-only; --dry-run=false is not supported")
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
		return integrityOptions{}, errors.New("--tenants requires between one and four unique tenant IDs")
	}
	if *batchSize < 1 || *batchSize > cycleuc.MaxAssessmentCycleIntegrityBatch {
		return integrityOptions{}, fmt.Errorf("--batch-size must be between 1 and %d", cycleuc.MaxAssessmentCycleIntegrityBatch)
	}
	if strings.TrimSpace(*actor) == "" || len(strings.TrimSpace(*actor)) > 256 {
		return integrityOptions{}, errors.New("--actor must contain between 1 and 256 characters")
	}
	if *timeout <= 0 || *leaseDuration <= 0 {
		return integrityOptions{}, errors.New("--timeout and --lease-duration must be positive")
	}
	return integrityOptions{tenants: tenants, actor: strings.TrimSpace(*actor), batchSize: *batchSize, timeout: *timeout, leaseDuration: *leaseDuration}, nil
}
