// Command synapse-identity-backfill projects legacy users into the additive identity model, records
// shadow parity evidence, runs the rollback drill, or delivers pending person-audit obligations.
// users stays the writer of record throughout; the command never repairs the legacy source.
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
	"syscall"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/platform/logging"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identityfoundation"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const maxTenants = 16

// Exit codes. A parity outcome is reported only when every tenant ran without an operational
// failure; across tenants the worst outcome wins (aborted over not ready over ready).
const (
	exitReady    = 0 // every shadow report is ready: zero drift and zero ambiguous rows
	exitFailure  = 1 // invalid arguments or an operational failure in any tenant
	exitNotReady = 3 // drift within --max-drift, or ambiguous rows remain
	exitAborted  = 4 // drift above --max-drift
)

const exitCodeUsage = `
Exit status:
  0  ready: every shadow report has zero drift and zero ambiguous rows (also success for
     rollback and deliver)
  1  invalid arguments or an operational failure in any tenant
  3  not ready: drift is within --max-drift, or ambiguous rows remain
  4  aborted: drift is above --max-drift in at least one tenant
`

// outcomeError carries a parity outcome to the process exit status.
type outcomeError struct {
	code int
	err  error
}

func (e *outcomeError) Error() string { return e.err.Error() }
func (e *outcomeError) Unwrap() error { return e.err }

// reportOutcome classifies one shadow report into its exit code and a short label.
func reportOutcome(r ports.IdentityShadowReport) (int, string) {
	switch {
	case r.Ready:
		return exitReady, "ready"
	case r.Aborted:
		return exitAborted, "aborted"
	default:
		return exitNotReady, "not_ready"
	}
}

// exitCode maps the result of run to the process exit status.
func exitCode(err error) int {
	if err == nil {
		return exitReady
	}
	var outcome *outcomeError
	if errors.As(err, &outcome) {
		return outcome.code
	}
	return exitFailure
}

type backfillOptions struct {
	mode      string
	tenants   []shared.ID
	issuer    string
	actor     string
	batchSize int
	maxDrift  int
	limit     int
	timeout   time.Duration
	lease     time.Duration
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(exitCode(err))
	}
}

func run(args []string, output io.Writer) error {
	options, err := parseOptions(args, output)
	if err != nil {
		return err
	}
	cfg := config.Load()
	log := logging.New(cfg.LogLevel)
	if cfg.DBDSN == "" {
		return errors.New("synapse-identity-backfill requires SYNAPSE_DB_DSN")
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
	if err := postgres.CheckRLSRuntimeRole(ctx, pool); err != nil {
		return err
	}
	store, err := postgres.NewIdentityFoundationStore(pool)
	if err != nil {
		return err
	}
	svc, err := identityfoundation.NewService(store, store, idgen.SystemClock{}, idgen.RandomID{})
	if err != nil {
		return err
	}
	var combined, parity error
	worst := exitReady
	// recordParity logs a report and keeps the worst parity outcome across tenants.
	recordParity := func(tenantID shared.ID, r ports.IdentityShadowReport) {
		code, label := reportOutcome(r)
		logReport(log, r, label)
		if code == exitReady {
			return
		}
		worst = max(worst, code)
		parity = errors.Join(parity, fmt.Errorf("tenant %s: shadow report %s is %s (drift %d, max drift %d, authenticator mismatch %d, ambiguous %d)",
			tenantID, r.ID, label, r.DriftTotal, options.maxDrift, r.AuthenticatorMismatches, r.Ambiguous))
	}
	switch options.mode {
	case "deliver":
		stats, err := svc.DeliverPersonAudit(ctx, options.tenants, options.limit)
		log.Info("person audit delivery pass", "delivered", stats.Delivered, "failed", stats.Failed, "exhausted", stats.Exhausted)
		return err
	}
	// Tenants run sequentially: each holds its own fence, and one failure does not stop the rest.
	for _, tenantID := range options.tenants {
		var err error
		switch options.mode {
		case "backfill":
			var result identityfoundation.BackfillResult
			result, err = svc.Backfill(ctx, tenantID, identityfoundation.BackfillOptions{
				Actor: options.actor, Issuer: options.issuer, BatchSize: options.batchSize, Lease: options.lease,
				Thresholds: ports.IdentityShadowThresholds{MaxDrift: options.maxDrift},
			})
			if err == nil {
				recordParity(tenantID, result.Report)
			}
		case "shadow":
			var report ports.IdentityShadowReport
			report, err = svc.Shadow(ctx, tenantID, ports.IdentityShadowThresholds{MaxDrift: options.maxDrift})
			if err == nil {
				recordParity(tenantID, report)
			}
		case "rollback":
			err = svc.Rollback(ctx, tenantID, options.actor)
			if err == nil {
				log.Info("identity projection rolled back", "tenant_id", tenantID)
			}
		}
		if err != nil {
			combined = errors.Join(combined, fmt.Errorf("tenant %s: %w", tenantID, err))
		}
	}
	if combined != nil {
		return errors.Join(combined, parity)
	}
	if parity != nil {
		return &outcomeError{code: worst, err: parity}
	}
	return nil
}

type infoLogger interface {
	Info(msg string, args ...any)
}

// logReport keeps drift and ambiguous rows as separate counts: drift is a parity mismatch the
// max-drift threshold applies to, while an ambiguous row needs operator resolution before readiness.
func logReport(log infoLogger, r ports.IdentityShadowReport, outcome string) {
	log.Info("identity shadow report", "tenant_id", r.TenantID, "report_id", r.ID, "outcome", outcome,
		"legacy_users", r.LegacyUsers, "memberships", r.Memberships,
		"credentials_expected", r.CredentialsExpected, "credentials_matched", r.CredentialsMatched,
		"authenticators_expected", r.AuthenticatorsExpected, "authenticators_matched", r.AuthenticatorsMatched,
		"authenticator_mismatches", r.AuthenticatorMismatches, "drift_total", r.DriftTotal, "missing_memberships", r.MissingMemberships, "role_drift", r.RoleDrift,
		"state_drift", r.StateDrift, "digest_mismatches", r.DigestMismatches, "routing_mismatches", r.RoutingMismatches,
		"ambiguous", r.Ambiguous, "placeholders", r.Placeholders,
		"aborted", r.Aborted, "ready", r.Ready, "rollback_prepared", r.RollbackPrepared)
}

func parseOptions(args []string, output io.Writer) (backfillOptions, error) {
	flags := flag.NewFlagSet("synapse-identity-backfill", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.Usage = func() {
		_, _ = fmt.Fprintf(flags.Output(), "Usage of %s:\n", flags.Name())
		flags.PrintDefaults()
		_, _ = fmt.Fprint(flags.Output(), exitCodeUsage)
	}
	mode := flags.String("mode", "backfill", "backfill, shadow, rollback or deliver")
	tenantsValue := flags.String("tenants", "", fmt.Sprintf("comma-separated tenant IDs; maximum %d", maxTenants))
	issuer := flags.String("oidc-issuer", "", "configured fixed OIDC issuer whose approved links are imported; empty imports none")
	actor := flags.String("actor", "identity-backfill", "audit actor")
	// The cap keeps one batch transaction within max_locks_per_transaction: the membership index
	// trigger takes one advisory lock per inserted person, and every lock is held until commit.
	batchSize := flags.Int("batch-size", 200, "users per committed batch (1-1000)")
	maxDrift := flags.Int("max-drift", 0, "drift up to this count reports not ready (exit 3); above it the report aborts (exit 4)")
	limit := flags.Int("delivery-limit", 100, "obligations per tenant per delivery pass (1-500)")
	timeout := flags.Duration("timeout", 30*time.Minute, "overall command timeout")
	lease := flags.Duration("lease-duration", 10*time.Minute, "a running backfill updated within this window blocks a new one")
	if err := flags.Parse(args); err != nil {
		return backfillOptions{}, err
	}
	if flags.NArg() != 0 {
		return backfillOptions{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	switch *mode {
	case "backfill", "shadow", "rollback", "deliver":
	default:
		return backfillOptions{}, fmt.Errorf("--mode %q is not one of backfill, shadow, rollback, deliver", *mode)
	}
	seen := map[shared.ID]bool{}
	var tenants []shared.ID
	for _, value := range strings.Split(*tenantsValue, ",") {
		tenantID := shared.ID(strings.TrimSpace(value))
		if tenantID.IsZero() || seen[tenantID] {
			continue
		}
		seen[tenantID] = true
		tenants = append(tenants, tenantID)
	}
	if len(tenants) == 0 || len(tenants) > maxTenants {
		return backfillOptions{}, fmt.Errorf("--tenants requires between one and %d unique tenant IDs", maxTenants)
	}
	if *batchSize < 1 || *batchSize > 1000 {
		return backfillOptions{}, errors.New("--batch-size must be between 1 and 1000")
	}
	if *limit < 1 || *limit > 500 {
		return backfillOptions{}, errors.New("--delivery-limit must be between 1 and 500")
	}
	if *maxDrift < 0 {
		return backfillOptions{}, errors.New("--max-drift must not be negative")
	}
	trimmedActor := strings.TrimSpace(*actor)
	if trimmedActor == "" || len(trimmedActor) > 256 {
		return backfillOptions{}, errors.New("--actor must contain between 1 and 256 characters")
	}
	trimmedIssuer := strings.TrimSpace(*issuer)
	if trimmedIssuer != *issuer || len(trimmedIssuer) > 2048 {
		return backfillOptions{}, errors.New("--oidc-issuer must be an exact issuer without surrounding whitespace")
	}
	if *timeout <= 0 || *lease <= 0 {
		return backfillOptions{}, errors.New("--timeout and --lease-duration must be positive")
	}
	return backfillOptions{
		mode: *mode, tenants: tenants, issuer: trimmedIssuer, actor: trimmedActor, batchSize: *batchSize,
		maxDrift: *maxDrift, limit: *limit, timeout: *timeout, lease: *lease,
	}, nil
}
