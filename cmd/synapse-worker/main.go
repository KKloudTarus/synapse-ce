// Command synapse-worker is the privileged execution worker: it
// claims recon jobs the API enqueued to the durable queue and runs them under the SAME
// gate/audit/evidence invariants as the in-process path, but with the sandbox + kernel
// egress allowlist (through a narrow root-owned broker on hardened execution hosts). It is a
// composition root only – no business logic. It coexists with the API via a role-scoped
// concurrent queue claim loops, and the evidence chain is multi-writer-safe.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/composition/scacompose"
	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityreconcile"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/cloudsandbox"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/ebpf"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/egressbroker"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/llm/openai"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/logstream"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	recontools "github.com/KKloudTarus/synapse-ce/internal/infrastructure/recon"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/signing"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sourceartifact"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/timestamp"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/enry"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/license"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/licensemeta"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/risk"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/vulnerabilityprovider"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/binregistry"
	"github.com/KKloudTarus/synapse-ce/internal/platform/buildinfo"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/platform/jobs"
	"github.com/KKloudTarus/synapse-ce/internal/platform/logging"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/agenttools"
	analysisuc "github.com/KKloudTarus/synapse-ce/internal/usecase/analysis"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/assetuc"
	attackpathuc "github.com/KKloudTarus/synapse-ce/internal/usecase/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/cspm"
	egresspolicy "github.com/KKloudTarus/synapse-ce/internal/usecase/egress"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	exploitationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/exploitation"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/leaderuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	reconuc "github.com/KKloudTarus/synapse-ce/internal/usecase/recon"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/vulnerabilitycorrelation"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/vulnerabilityevaluation"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/vulnerabilitymonitor"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/vulnerabilityprojection"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/vulnerabilityreconciliation"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/vulnerabilityrollout"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/vulnerabilityruntime"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/worker"
	writeupdraftuc "github.com/KKloudTarus/synapse-ce/internal/usecase/writeupdraftuc"
)

func main() {
	cfg := config.Load()
	log := logging.New(cfg.LogLevel)
	toolExecution, err := cfg.ResolveToolExecution(config.ProcessRoleWorker)
	if err != nil {
		log.Error("tool execution posture invalid", "err", err)
		os.Exit(1)
	}
	log.Info("starting synapse-worker", "env", cfg.Environment, "tool_execution", toolExecution)
	if err := cfg.ValidateSandboxPosture(); err != nil {
		log.Error("sandbox posture invalid", "err", err)
		os.Exit(1)
	}
	if err := cfg.ValidateMigrationPosture(); err != nil {
		log.Error("database migration posture invalid", "err", err)
		os.Exit(1)
	}
	if err := cfg.ValidateWorkerConcurrency(); err != nil {
		log.Error("worker concurrency invalid", "err", err)
		os.Exit(1)
	}
	if err := cfg.ValidateEgressGrantPosture(config.ProcessRoleWorker); err != nil {
		log.Error("egress grant posture invalid", "err", err)
		os.Exit(1)
	}
	if err := cfg.ValidateNetworkExecutionPosture(config.ProcessRoleWorker); err != nil {
		log.Error("network execution posture invalid", "err", err)
		os.Exit(1)
	}

	// The worker shares the API's Postgres (the queue + the recon/evidence repos), so a DSN
	// is required – an in-memory queue is not shared across processes.
	if cfg.DBDSN == "" {
		log.Error("synapse-worker requires SYNAPSE_DB_DSN (the durable queue + repos shared with the API)")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	clock := idgen.SystemClock{}
	ids := idgen.RandomID{}

	startup, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if cfg.DBAutoMigrate {
		migrationStarted := time.Now()
		if err := postgres.MigrateLocked(startup, cfg.MigrationDSN()); err != nil {
			log.Error("db migrate failed", "err", err)
			os.Exit(1)
		}
		log.Info("db migrations complete", "duration", time.Since(migrationStarted))
	} else {
		log.Info("db auto-migration disabled; readiness requires current migrations")
	}
	pool, err := postgres.ConnectPool(startup, cfg.DBDSN, postgres.PoolConfig{
		MaxConns: int32(cfg.DBMaxConns), MinConns: int32(cfg.DBMinConns),
		MaxConnLifetime: cfg.DBMaxConnLifetime, MaxConnIdleTime: cfg.DBMaxConnIdleTime,
	})
	if err != nil {
		log.Error("db connect failed", "err", err)
		os.Exit(1)
	}
	defer pool.Close()
	if !cfg.DBAutoMigrate {
		if err := postgres.CheckMigrationsReady(startup, pool); err != nil {
			log.Error("database migrations are not current", "err", err)
			os.Exit(1)
		}
	}
	if err := postgres.CheckRLSRuntimeRole(startup, pool); err != nil {
		log.Error("the worker DB role cannot enforce row level security – refusing to serve", "err", err)
		os.Exit(1)
	}
	// Concurrent workers are safe: queue claim fences reject stale deliveries, each run has a
	// per-run execution lease, and only deployment-global sweepers run under a leader lease.

	// Repos shared with the API.
	repo := postgres.NewEngagementRepository(pool)
	reconRunStore := postgres.NewReconRunStore(pool)
	evidenceStore := postgres.NewEvidenceStore(pool)
	auditLog := postgres.NewAuditLog(pool)
	queue := postgres.NewJobQueue(pool, ids)
	vulnerabilitySources := postgres.NewVulnerabilitySourceStore(pool)
	vulnerabilityRuns := postgres.NewSyncRunStore(pool, ids)
	vulnerabilityMaterializer := postgres.NewAdvisoryMaterializer(pool)
	vulnerabilityInventory := postgres.NewComponentInventoryStore(pool)
	vulnerabilityOccurrences := postgres.NewVulnerabilityOccurrenceStore(pool)
	vulnerabilityAssessments := postgres.NewVulnerabilityRiskAssessmentStore(pool)
	vulnerabilityActions := postgres.NewVulnerabilityActionStore(pool)
	vulnerabilityReconcileRuns := postgres.NewVulnerabilityReconcileRunStore(pool, ids)
	vulnerabilityTransactions := postgres.NewTenantTransactionRunner(pool)
	leaderStore := postgres.NewLeaderStore(pool)
	cloudRunStore := postgres.NewCloudRunStore(pool)
	scanRepo := postgres.NewScanRepository(pool)
	scanResultStore := postgres.NewScanResultStore(pool)
	scanJobStore := postgres.NewScanJobStore(pool)
	scanRunStore := postgres.NewScanRunStore(pool)
	findingRepo := postgres.NewFindingRepository(pool)
	importedSBOMStore := postgres.NewImportedSBOMStore(pool)

	// Credential vault – same master key as the API so secrets resolve.
	credVault := vault.NewPostgresVault(pool, mustVaultCipher(cfg, log))

	// Evidence blob store (shared with the API when MinIO is configured).
	var blobStore ports.BlobStore
	if cfg.BlobEndpoint != "" {
		bs, berr := blob.NewMinIO(context.Background(), blob.Config{Endpoint: cfg.BlobEndpoint, AccessKey: cfg.BlobAccessKey, SecretKey: cfg.BlobSecretKey, Bucket: cfg.BlobBucket, UseSSL: cfg.BlobUseSSL})
		if berr != nil {
			log.Error("blob store init failed", "err", berr)
			os.Exit(1)
		}
		blobStore = bs
	} else {
		blobStore = blob.NewMemory()
	}

	guard, err := execution.NewGuard(repo, clock, auditLog)
	if err != nil {
		log.Error("guard init failed", "err", err)
		os.Exit(1)
	}
	evidenceService, err := evidenceuc.NewService(evidenceStore, blobStore, auditLog, clock, ids)
	if err != nil {
		log.Error("evidence service init failed", "err", err)
		os.Exit(1)
	}

	// Tamper-resistant custody: the worker SEALS evidence (recon + agent), so it must
	// also attest + anchor the heads it advances – not leave them un-anchored until a later API
	// read. Wire the SAME ed25519 signer (shared seed ⇒ consistent attestation with the API) +
	// RFC-3161 TSA, fail-CLOSED in production (an ephemeral attestation key cannot back an
	// "origin" claim across restarts). recon.execute calls Verify after a seal to anchor here.
	if seed, serr := signing.DecodeSeed(cfg.EvidenceSigningSeed); serr != nil {
		log.Error("evidence signing seed invalid", "err", serr) // never log the seed itself
		os.Exit(1)
	} else if signer, serr := signing.NewEd25519Signer(seed); serr != nil {
		log.Error("evidence signer init failed", "err", serr)
		os.Exit(1)
	} else {
		if signer.Ephemeral() && cfg.IsProduction() {
			log.Error("SYNAPSE_EVIDENCE_SIGNING_SEED is required in production for a stable attestation key")
			os.Exit(1)
		}
		evidenceService.SetSigner(signer.WithContext(evidence.AttestationContextEvidence))
		if signer.Ephemeral() {
			log.Warn("worker chain-head signing key is ephemeral – set SYNAPSE_EVIDENCE_SIGNING_SEED", "key_id", signer.KeyID())
		} else {
			log.Info("worker chain-head attestation enabled", "key_id", signer.KeyID())
		}
	}
	var tsaClient ports.TimestampAuthority
	if cfg.TSAURL != "" {
		tc, terr := timestamp.NewClient(cfg.TSAURL, 0)
		if terr != nil {
			log.Error("timestamp authority init failed", "err", terr)
			os.Exit(1)
		}
		tsaClient = tc
		log.Info("worker external RFC-3161 anchoring enabled", "tsa", cfg.TSAURL)
	}
	evidenceService.SetTimestamper(tsaClient, postgres.NewTimestampStore(pool))

	prov := ports.Provenance{
		ToolVersions: map[string]string{
			"go-enry": buildinfo.Module("github.com/go-enry/go-enry/v2"),
			"synapse": buildinfo.App(),
		},
		VulnDBSource: "osv.dev",
	}
	scaExecution, eerr := scacompose.BuildExecution(cfg, log, postgres.NewAdvisoryRepository(pool))
	if eerr != nil {
		log.Error(eerr.Error())
		os.Exit(1)
	}
	scaService := scauc.NewService(repo, findingRepo, scanRepo, scanResultStore, scanJobStore, scanRunStore, evidenceService, ids, prov, clock, auditLog, shared.Severity(cfg.FindingMinSeverity), cfg.ScanTimeout, scaExecution.Acquirer,
		enry.New(), scaExecution.SBOMGen, scaExecution.Sources,
		risk.New(cfg.KEVURL, cfg.EPSSURL, nil), license.New(), licensemeta.NewChain(licensemeta.NewOSMetadata(), licensemeta.New(cfg.DepsDevURL, nil), licensemeta.NewPyPI("", nil)))
	scaService.SetImportedSBOMStore(importedSBOMStore)
	configureCleanup := scacompose.Configure(scaService, cfg, scaExecution.Sandbox, log)
	defer configureCleanup()
	if cfg.ComplianceEnabled {
		scaService.SetComplianceEnabled(true) // attach the AppSec-baseline benchmark (per-control PASS/FAIL)
		log.Info("compliance report ENABLED (Synapse AppSec Baseline; deterministic, LLM-free)")
	}
	scaService.SetRunLock(postgres.NewLeaseRunLock(pool, ids.NewID().String(), cfg.ScanTimeout+time.Minute))

	// The sandbox is REQUIRED here – the worker exists to run recon contained.
	sb, serr := sandbox.NewRunner(cfg.ReconTimeout, cfg.ReconMaxOutput, cfg.SandboxMemMax, cfg.SandboxPidsMax)
	if serr != nil {
		log.Error("synapse-worker requires the sandbox (bubblewrap) – install it", "err", serr)
		os.Exit(1)
	}
	sb.SetVault(credVault)
	toolRegistry := binregistry.New(cfg.ToolHashes, true)
	if cfg.CSPMEnabled {
		if !filepath.IsAbs(cfg.CSPMHelperBin) {
			log.Error("SYNAPSE_CSPM_HELPER_BIN must be an absolute path when CSPM is enabled")
			os.Exit(1)
		}
		resolvedHelper, err := filepath.EvalSymlinks(cfg.CSPMHelperBin)
		if err != nil {
			log.Error("resolve CSPM helper path", "err", err)
			os.Exit(1)
		}
		cfg.CSPMHelperBin = resolvedHelper
		if _, ok := cfg.ToolHashes[resolvedHelper]; !ok {
			if _, ok = cfg.ToolHashes[filepath.Base(resolvedHelper)]; !ok {
				log.Error("CSPM helper requires an authoritative SHA-256 pin in SYNAPSE_TOOL_HASHES")
				os.Exit(1)
			}
		}
	}
	sb.SetBinaryRegistry(toolRegistry)
	egressLive := false
	var grantAuthority egressbroker.GrantAuthority
	if strings.TrimSpace(cfg.EgressGrantAuthorityURL) != "" || strings.TrimSpace(cfg.EgressGrantAuthorityToken) != "" {
		grantAuthority, err = egressbroker.NewHTTPGrantAuthority(cfg.EgressGrantAuthorityURL, cfg.EgressGrantAuthorityToken, 10*time.Second)
		if err != nil {
			log.Error("egress grant authority configuration invalid", "err", err)
			os.Exit(1)
		}
	}
	broker, berr := egressbroker.NewClient(cfg.EgressBrokerSocket, 10*time.Second, grantAuthority)
	if berr != nil {
		log.Error("egress broker configuration invalid", "err", berr)
		os.Exit(1)
	}
	perr := waitForEgressBroker(ctx, broker)
	if perr == nil && grantAuthority != nil {
		sb.SetEgressEnforcer(broker)
		sb.SetConnMonitor(ebpf.NewMonitor()) // per-run eBPF connect-log (best-effort)
		egressLive = true
		log.Info("worker: root-owned kernel egress broker enabled")
	} else if cfg.IsProduction() {
		if perr == nil {
			perr = errors.New("egress grant authority is required")
		}
		log.Error("production worker requires a usable scoped-egress broker", "err", perr)
		os.Exit(1)
	} else if perr != nil {
		log.Warn("worker has no usable scoped-egress broker – recon will remain network-isolated", "err", perr)
	} else {
		log.Warn("worker has no egress grant authority – recon will remain network-isolated")
	}

	logBroker := logstream.NewBroker(0)
	reconPool := jobs.NewPool(cfg.ReconConcurrency, cfg.ReconQueueSize) // required by the service; the worker uses RunJob
	reconService, err := reconuc.NewService(guard, sb, reconRunStore, evidenceService, repo, logBroker, reconPool, clock, ids,
		recontools.Registry(), cfg.ReconTimeout, cfg.ReconMaxOutput, cfg.ReconAllowCapabilitySensitive)
	if err != nil {
		log.Error("recon service init failed", "err", err)
		os.Exit(1)
	}
	if egressLive {
		reconService.SetSandboxEnforcement(egresspolicy.Compile)
	}
	reconService.SetRunLock(postgres.NewLeaseRunLock(pool, ids.NewID().String(), cfg.ReconTimeout+time.Minute))

	var maintenanceTasks []func(context.Context)
	handlers := map[string]worker.Handler{
		reconuc.JobKind:   reconJobHandler{svc: reconService}, // Handle + OnDeadLetter (finalize the run)
		scauc.ScanJobKind: scaJobHandler{svc: scaService},
	}
	vulnerabilityRegistry := vulnerabilitymonitor.NewRegistry()
	vulnerabilityRollout, err := vulnerabilityrollout.New(vulnerabilityrollout.Config{
		ProviderSync: cfg.VulnerabilityProviderSyncEnabled, OccurrenceWrites: cfg.VulnerabilityOccurrenceWritesEnabled,
		FindingProjection: cfg.VulnerabilityFindingProjectionEnabled, Actions: cfg.VulnerabilityActionsEnabled,
		Notifications: cfg.VulnerabilityNotificationsEnabled, DryRun: cfg.VulnerabilityDryRunEnabled,
		TenantAllowlist: cfg.VulnerabilityTenantAllowlist,
	})
	if err != nil {
		log.Error("vulnerability rollout init failed", "err", err)
		os.Exit(1)
	}
	if err := vulnerabilityprovider.RegisterAll(vulnerabilityRegistry, vulnerabilityprovider.Dependencies{
		LookupCanonical: vulnerabilityMaterializer.GetCanonical,
		CurrentRecords:  vulnerabilityMaterializer.CurrentSourceRecordIDs,
		ResolveSecret: func(ctx context.Context, reference string) ([]byte, error) {
			return credVault.Resolve(ctx, shared.DefaultTenant, reference)
		},
	}); err != nil {
		log.Error("vulnerability provider registry init failed", "err", err)
		os.Exit(1)
	}
	vulnerabilityMonitor, err := vulnerabilitymonitor.NewService(vulnerabilitySources, vulnerabilityRuns, vulnerabilityMaterializer, vulnerabilityRegistry, clock)
	if err != nil {
		log.Error("vulnerability monitor init failed", "err", err)
		os.Exit(1)
	}
	vulnerabilityMonitor.SetRollout(vulnerabilityRollout)
	vulnerabilityMonitor.SetRunLock(postgres.NewLeaseRunLock(pool, ids.NewID().String(), cfg.ReconTimeout+time.Minute))
	vulnerabilityProjection, err := vulnerabilityprojection.NewService(postgres.NewFindingRepository(pool))
	if err != nil {
		log.Error("vulnerability finding projection init failed", "err", err)
		os.Exit(1)
	}
	vulnerabilityEvaluator, err := vulnerabilityevaluation.NewService(vulnerabilityMaterializer, vulnerabilityAssessments, vulnerabilityProjection, clock)
	if err != nil {
		log.Error("vulnerability evaluation init failed", "err", err)
		os.Exit(1)
	}
	vulnerabilityEvaluator.SetActionStore(vulnerabilityActions)
	vulnerabilityEvaluator.SetRollout(vulnerabilityRollout)
	vulnerabilityAdvisoryCorrelation, err := vulnerabilitycorrelation.NewService(vulnerabilityInventory, vulnerabilityMaterializer, vulnerabilityOccurrences)
	if err != nil {
		log.Error("vulnerability advisory correlation init failed", "err", err)
		os.Exit(1)
	}
	vulnerabilityAdvisoryCorrelation.SetEvaluator(vulnerabilityEvaluator, clock)
	vulnerabilityAdvisoryCorrelation.SetRollout(vulnerabilityRollout)
	vulnerabilityAdvisoryCorrelation.SetTransactionRunner(vulnerabilityTransactions)
	vulnerabilityEvaluationCheckpoints, ok := any(vulnerabilityMaterializer).(ports.AdvisoryEvaluationCheckpointStore)
	if !ok {
		log.Error("advisory materializer does not support evaluation checkpoints")
		os.Exit(1)
	}
	vulnerabilityReconciliation, err := vulnerabilityreconciliation.NewService(vulnerabilityReconcileRuns, repo, vulnerabilityMaterializer, vulnerabilityMaterializer, vulnerabilityOccurrences, vulnerabilityAdvisoryCorrelation, vulnerabilityEvaluationCheckpoints, 0)
	if err != nil {
		log.Error("vulnerability reconciliation init failed", "err", err)
		os.Exit(1)
	}
	vulnerabilityReconciliation.SetRollout(vulnerabilityRollout)
	vulnerabilityReconciliation.SetRunLock(postgres.NewLeaseRunLock(pool, ids.NewID().String(), cfg.ReconTimeout+time.Minute))
	vulnerabilitySBOMCorrelation, err := vulnerabilitycorrelation.NewSBOMReconciler(vulnerabilityInventory, vulnerabilityMaterializer, vulnerabilityMaterializer, vulnerabilityOccurrences)
	if err != nil {
		log.Error("vulnerability SBOM correlation init failed", "err", err)
		os.Exit(1)
	}
	vulnerabilitySBOMCorrelation.SetEvaluator(vulnerabilityEvaluator, clock)
	vulnerabilitySBOMCorrelation.SetRollout(vulnerabilityRollout)
	vulnerabilitySBOMCorrelation.SetTransactionRunner(vulnerabilityTransactions)
	vulnerabilityRuntime, err := vulnerabilityruntime.NewCoordinator(repo, repo, vulnerabilityAdvisoryCorrelation, vulnerabilitySBOMCorrelation, vulnerabilityEvaluationCheckpoints, clock)
	if err != nil {
		log.Error("vulnerability runtime init failed", "err", err)
		os.Exit(1)
	}
	vulnerabilityMonitor.SetReconciler(vulnerabilityRuntime)
	handlers[vulnerabilitymonitor.JobKind] = vulnerabilitySyncJobHandler{svc: vulnerabilityMonitor}
	handlers[vulnerabilityreconcile.JobKind] = vulnerabilityReconcileJobHandler{svc: vulnerabilityReconciliation}
	if cfg.CSPMEnabled {
		connectors := make(map[cloudposture.Provider]ports.CloudConnector, len(cfg.CSPMProviders))
		for _, name := range cfg.CSPMProviders {
			provider := cloudposture.Provider(strings.ToLower(strings.TrimSpace(name)))
			if !provider.Valid() {
				log.Error("unknown CSPM provider", "provider", provider)
				os.Exit(1)
			}
			connectors[provider] = cspm.Evaluator{}
		}
		assetRepo := postgres.NewAssetRepository(pool)
		assetSvc, cerr := assetuc.NewService(assetRepo, auditLog, clock, ids)
		if cerr != nil {
			log.Error("CSPM asset service init failed", "err", cerr)
			os.Exit(1)
		}
		findingRepo := postgres.NewFindingRepository(pool)
		cloudSvc, cerr := cspm.NewService(connectors, assetSvc, findingRepo, repo, auditLog, clock)
		if cerr != nil {
			log.Error("CSPM service init failed", "err", cerr)
			os.Exit(1)
		}
		if cerr = cloudSvc.SetDurableExecution(cloudRunStore, queue, ids); cerr != nil {
			log.Error("CSPM durable execution init failed", "err", cerr)
			os.Exit(1)
		}
		evidenceSealer, cerr := cspm.NewEvidenceSealer(evidenceService)
		if cerr != nil {
			log.Error("CSPM evidence init failed", "err", cerr)
			os.Exit(1)
		}
		cloudSvc.SetEvidenceSealer(evidenceSealer)
		cloudSvc.SetObservationStore(postgres.NewCloudObservationStore(pool))
		cloudSvc.SetRunLock(postgres.NewLeaseRunLock(pool, ids.NewID().String(), cfg.ReconTimeout+time.Minute))
		egressHosts := map[cloudposture.Provider][]string{}
		for _, entry := range cfg.CSPMEgressHosts {
			providerName, host, ok := strings.Cut(entry, "=")
			provider := cloudposture.Provider(strings.TrimSpace(providerName))
			if !ok || !provider.Valid() || strings.TrimSpace(host) == "" {
				log.Error("invalid SYNAPSE_CSPM_EGRESS_HOSTS entry", "entry", entry)
				os.Exit(1)
			}
			egressHosts[provider] = append(egressHosts[provider], strings.TrimSpace(host))
		}
		executor, xerr := cloudsandbox.New(sb, credVault, cfg.CSPMHelperBin, cfg.CSPMRate, cfg.ReconTimeout, cfg.ReconMaxOutput, egressHosts)
		if xerr != nil || !egressLive {
			log.Error("CSPM requires sandboxed helper with kernel egress enforcement", "err", xerr)
			os.Exit(1)
		}
		cloudSvc.SetSandboxExecutor(executor)
		attributor, cerr := attackpathuc.NewRecorder(assetRepo, postgres.NewAttackPathStore(pool), repo)
		if cerr != nil {
			log.Error("CSPM attribution init failed", "err", cerr)
			os.Exit(1)
		}
		cloudSvc.SetAttributor(attributor)
		expectations, cerr := cspm.NewExpectationSource(repo, postgres.NewProjectAnalysisStore(pool), sourceartifact.New(cfg.ProjectSourceArtifactDir, cfg.ProjectSourceMaxFileBytes, cfg.ProjectSourceMaxFiles, cfg.ProjectSourceMaxBytes))
		if cerr != nil {
			log.Error("CSPM expectation source init failed", "err", cerr)
			os.Exit(1)
		}
		cloudSvc.SetExpectationSource(expectations)
		handlers[cspm.JobKind] = cspmJobHandler{svc: cloudSvc}
		log.Info("CSPM worker handler ENABLED", "providers", cfg.CSPMProviders)
	}
	visibility := cfg.ReconTimeout + time.Minute
	if cfg.ScanTimeout+time.Minute > visibility {
		visibility = cfg.ScanTimeout + time.Minute
	}

	// durable agent runs. Register the agent handler with a DEDICATED
	// dispatcher-backed recon service (its own pool, NO SetQueue) – so the agent executor's
	// blocking recon poll never starves THIS worker's recon-claim loop (the self-deadlock the
	// design flags). The agent session lock is the connection-holding advisory RunLock (it must
	// not expire mid-LLM-loop); recon uses the row-lease lock above.
	if cfg.AgentEnabled && cfg.LLMModel == "" {
		// The API hard-errors in this case; the worker degrades to no-agent (fail-safe) but must say so,
		// or a misconfigured worker silently runs without the durable agent handler (operator visibility).
		log.Warn("SYNAPSE_AGENT_ENABLED is set but SYNAPSE_LLM_MODEL is empty: the durable agent handler is DISABLED on this worker (set SYNAPSE_LLM_MODEL to match the API)")
	}
	if cfg.AgentEnabled && cfg.LLMModel != "" {
		agentSessionStore := postgres.NewAgentSessionStore(pool)
		approvalStore := postgres.NewApprovalStore(pool)
		findingRepo := postgres.NewFindingRepository(pool)
		planStore := postgres.NewAgentPlanStore(pool)
		decisionStore := postgres.NewAgentDecisionStore(pool)

		agentReconPool := jobs.NewPool(cfg.AgentReconConcurrency, cfg.ReconQueueSize)
		defer agentReconPool.Shutdown(context.Background()) // graceful drain on shutdown (symmetry with the API)
		agentReconSvc, aerr := reconuc.NewService(guard, sb, reconRunStore, evidenceService, repo, logBroker, agentReconPool, clock, ids,
			recontools.Registry(), cfg.ReconTimeout, cfg.ReconMaxOutput, cfg.ReconAllowCapabilitySensitive)
		if aerr != nil {
			log.Error("agent recon service init failed", "err", aerr)
			os.Exit(1)
		}
		if egressLive {
			agentReconSvc.SetSandboxEnforcement(egresspolicy.Compile) // NO SetQueue / SetRunLock – in-process only
		}

		llm, lerr := openai.New(cfg.LLMBaseURL, cfg.LLMAPIKey, cfg.LLMModel, cfg.LLMTimeout)
		if lerr != nil {
			log.Error("llm client init failed", "err", lerr) // never logs the key
			os.Exit(1)
		}
		approvalSvc, perr := approval.NewService(approvalStore, auditLog, clock, agent.ApprovalMode(cfg.AgentApprovalMode), cfg.AgentApprovalTimeout)
		if perr != nil {
			log.Error("approval service init failed", "err", perr)
			os.Exit(1)
		}
		agentGate, gerr := safety.NewGate(guard, approvalSvc, evidenceService)
		if gerr != nil {
			log.Error("safety gate init failed", "err", gerr)
			os.Exit(1)
		}
		reconToolList := make([]ports.ReconTool, 0, len(recontools.Registry()))
		for _, t := range recontools.Registry() {
			reconToolList = append(reconToolList, t)
		}
		agentCatalog, cerr := agenttools.New(findingRepo, evidenceStore, reconToolList, auditLog, clock, ids)
		if cerr != nil {
			log.Error("agent catalog init failed", "err", cerr)
			os.Exit(1)
		}
		// Build the SAME toolset dependencies the inline API agent wires so a DURABLE run advertises an
		// IDENTICAL tool set (#161 parity). Before this, the worker enabled only planning + finding
		// proposals, so an agent driven durably saw a strictly smaller toolset than the same session run
		// inline. Findings/hypotheses (exploitation) + reachability (scan-result store) are always on;
		// judgments + writeup drafts mirror their feature flags — matching the API exactly. All are
		// PROPOSE-only here: a distinct human confirms/verifies out of band via the API (PermReview).
		exploitSvc, eerr := exploitationuc.NewService(findingRepo, evidenceService, auditLog, clock, ids)
		if eerr != nil {
			log.Error("exploitation service init failed", "err", eerr)
			os.Exit(1)
		}
		toolset := agenttools.AgentToolset{
			Findings:     exploitSvc,
			Hypotheses:   exploitSvc,
			Reachability: postgres.NewScanResultStore(pool),
		}
		if cfg.JudgmentsEnabled {
			judgmentSvc, jerr := analysisuc.NewService(postgres.NewJudgmentRepository(pool), evidenceService, auditLog, clock, ids)
			if jerr != nil {
				log.Error("analysis (judgment) service init failed", "err", jerr)
				os.Exit(1)
			}
			toolset.Judgments = judgmentSvc
		}
		if cfg.WriteupDraftsEnabled {
			writeupSvc, werr := writeupdraftuc.NewService(postgres.NewWriteupDraftRepository(pool), auditLog, clock, ids)
			if werr != nil {
				log.Error("writeup-draft service init failed", "err", werr)
				os.Exit(1)
			}
			toolset.WriteupDrafts = writeupSvc
		}
		if terr := agentCatalog.EnableAgentToolset(toolset); terr != nil {
			log.Error("agent toolset wiring failed (durable/inline parity)", "err", terr)
			os.Exit(1)
		}
		agentExec, xerr := orchestrator.NewReconExecutor(agentReconSvc, evidenceService, clock, 500*time.Millisecond, cfg.ReconTimeout+time.Minute)
		if xerr != nil {
			log.Error("agent executor init failed", "err", xerr)
			os.Exit(1)
		}
		orch, oerr := orchestrator.New(llm, agentCatalog, agentGate, agentExec, evidenceService, agentSessionStore, approvalStore, auditLog, clock, ids,
			orchestrator.Config{Model: cfg.LLMModel, ProviderBase: cfg.LLMBaseURL, MaxSteps: cfg.AgentMaxSteps, TokenBudget: cfg.AgentTokenBudget, MaxDuration: cfg.AgentMaxDuration, MaxParallel: cfg.AgentMaxParallel})
		if oerr != nil {
			log.Error("orchestrator init failed", "err", oerr)
			os.Exit(1)
		}
		orch.SetRunLock(postgres.NewRunLock(pool))                   // advisory session lock (cannot expire mid-loop)
		orch.SetPlanStore(planStore)                                 // drive a proposed plan DAG (node-CAS idempotency)
		orch.SetDecisionStore(decisionStore)                         // structured decision-log projection
		handlers[orchestrator.JobKind] = agentJobHandler{orch: orch} // Handle + OnDeadLetter (finalize the session)

		// Re-drive sessions stranded by a crash; sweep approval timeouts (fail-closed) + resume.
		reconciler, rerr := orchestrator.NewReconciler(agentSessionStore, queue, clock, cfg.AgentMaxDuration+5*time.Minute, log)
		if rerr != nil {
			log.Error("reconciler init failed", "err", rerr)
			os.Exit(1)
		}
		approvalSvc.SetResumeEnqueuer(func(ctx context.Context, sid, aid shared.ID) error {
			sess, err := agentSessionStore.GetSession(ctx, sid)
			if err != nil {
				return err
			}
			tenantCtx := shared.WithTenant(ctx, sess.TenantID)
			p, err := orchestrator.ResumeJob(tenantCtx, sid, aid)
			if err != nil {
				return err
			}
			_, err = queue.Enqueue(tenantCtx, orchestrator.JobKind, p)
			return err
		})
		maintenanceTasks = append(maintenanceTasks,
			func(ctx context.Context) { reconciler.Run(ctx, 5*time.Minute) },
			func(ctx context.Context) { approvalSvc.RunSweeper(ctx, cfg.ApprovalSweepInterval) },
		)
		if cfg.AgentMaxDuration+time.Minute > visibility {
			visibility = cfg.AgentMaxDuration + time.Minute
		}
		log.Info("AI agent worker handler ENABLED (durable)", "model", cfg.LLMModel)
	}

	// Deployment-global recovery work is leader-gated. Queue claim loops are deliberately
	// not leader-gated: every worker must claim and execute durable jobs.
	maintenanceTasks = append(maintenanceTasks,
		func(ctx context.Context) {
			staleFor := cfg.ScanTimeout + 5*time.Minute
			t := time.NewTicker(5 * time.Minute)
			defer t.Stop()
			for {
				if n, err := scaService.SweepStaleScans(ctx, staleFor); err != nil && ctx.Err() == nil {
					log.Warn("sca stale-scan sweep failed", "err", err)
				} else if n > 0 {
					log.Info("sca stale-scan sweeper reclaimed stranded scans", "count", n)
				}
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		},
		func(ctx context.Context) {
			staleFor := cfg.ReconTimeout + 5*time.Minute
			t := time.NewTicker(5 * time.Minute)
			defer t.Stop()
			for {
				if n, err := reconService.SweepStaleRuns(ctx, staleFor); err != nil && ctx.Err() == nil {
					log.Warn("recon stale-run sweep failed", "err", err)
				} else if n > 0 {
					log.Info("recon stale-run sweeper reclaimed stranded runs", "count", n)
				}
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		},
	)

	if cfg.LeaderElectionEnabled {
		resource := cfg.LeaderResource + "-worker-maintenance"
		elector, eerr := leaderuc.NewElector(leaderStore, auditLog, clock, resource, ids.NewID().String(), cfg.LeaderTerm, cfg.LeaderRenew)
		if eerr != nil {
			log.Error("worker leader election configuration invalid", "err", eerr)
			os.Exit(1)
		}
		go elector.Run(ctx)
		go func() {
			var maintenanceCancel context.CancelFunc
			wasLeader := false
			t := time.NewTicker(time.Second)
			defer t.Stop()
			defer func() {
				if maintenanceCancel != nil {
					maintenanceCancel()
				}
			}()
			for {
				leader := elector.IsLeader()
				if leader && !wasLeader {
					maintenanceCtx, cancel := context.WithCancel(ctx)
					maintenanceCancel = cancel
					for _, task := range maintenanceTasks {
						go task(maintenanceCtx)
					}
				}
				if !leader && wasLeader && maintenanceCancel != nil {
					maintenanceCancel()
					maintenanceCancel = nil
				}
				wasLeader = leader
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		}()
		log.Info("worker maintenance leader election ENABLED", "resource", resource, "term", cfg.LeaderTerm, "renew", cfg.LeaderRenew)
	} else {
		// Keep the single-worker behavior explicit: without leader election, maintenance runs here.
		for _, task := range maintenanceTasks {
			go task(ctx)
		}
	}

	var loops sync.WaitGroup
	for i := 0; i < cfg.WorkerConcurrency; i++ {
		loops.Add(1)
		go func(loop int) {
			defer loops.Done()
			w := worker.New(queue, handlers, worker.Config{Visibility: visibility, MaxAttempts: 3}, log.With("loop", loop+1))
			if err := w.Run(ctx); err != nil && ctx.Err() == nil {
				log.Error("worker claim loop exited with error", "loop", loop+1, "err", err)
			}
		}(i)
	}
	loops.Wait()
	log.Info("synapse-worker stopped", "loops", cfg.WorkerConcurrency)
}

// mustVaultCipher builds the vault cipher from the master key (ephemeral in dev), exiting
// on failure. Mirrors the API so secrets sealed by one resolve in the other – INCLUDING the
// production fail-closed guard: without a configured key the worker would seal/resolve under a
// per-process ephemeral key that diverges from the API's, so every credentialed recon run
// breaks. Fail closed in production rather than fail open to an ephemeral key.
type egressReadinessWaiter interface {
	WaitReady(context.Context, time.Duration) error
}

func waitForEgressBroker(ctx context.Context, broker egressReadinessWaiter) error {
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return broker.WaitReady(probeCtx, 100*time.Millisecond)
}

func mustVaultCipher(cfg config.Config, log *slog.Logger) *vault.Cipher {
	var key []byte
	if cfg.VaultMasterKey != "" {
		k, err := vault.DecodeKey(cfg.VaultMasterKey)
		if err != nil {
			log.Error("vault master key invalid", "err", err) // never log the key itself
			os.Exit(1)
		}
		key = k
	} else {
		if cfg.IsProduction() {
			log.Error("SYNAPSE_VAULT_MASTER_KEY is required in production (durable credential encryption shared with the API)")
			os.Exit(1)
		}
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			log.Error("vault ephemeral key generation failed", "err", err)
			os.Exit(1)
		}
		log.Warn("credential vault key is ephemeral – set SYNAPSE_VAULT_MASTER_KEY; stored secrets will not survive restart")
	}
	c, err := vault.NewCipher(key)
	if err != nil {
		log.Error("vault cipher init failed", "err", err)
		os.Exit(1)
	}
	return c
}

// scaJobHandler binds the SCA service to the worker's Handler + DeadLetterer interfaces:
// running a scan job is RunScanJob; dead-lettering one finalizes the backing ScanJob to a
// terminal failed state (parity with recon + agent), so a stranded scan is operator-visible
// rather than stuck non-terminal with no result.
type scaJobHandler struct{ svc *scauc.Service }

func (h scaJobHandler) Handle(ctx context.Context, job ports.QueuedJob) error {
	return h.svc.RunScanJob(ctx, job.Payload)
}

func (h scaJobHandler) OnDeadLetter(ctx context.Context, job ports.QueuedJob, cause error) error {
	return h.svc.FailStrandedScanJob(ctx, job.Payload, cause)
}

// reconJobHandler binds the recon service to the worker's Handler + DeadLetterer interfaces:
// running a recon job is RunJob; dead-lettering one finalizes the backing run so it is not left
// stranded with no terminal record (there is no stale-run reclaim sweep).
type reconJobHandler struct{ svc *reconuc.Service }

func (h reconJobHandler) Handle(ctx context.Context, job ports.QueuedJob) error {
	return h.svc.RunJob(ctx, job.Payload)
}

func (h reconJobHandler) OnDeadLetter(ctx context.Context, job ports.QueuedJob, cause error) error {
	return h.svc.FailStrandedJob(ctx, job.Payload, cause)
}

// agentJobHandler binds the orchestrator to the worker's Handler + DeadLetterer interfaces:
// running an agent job is RunJob; dead-lettering one finalizes the backing session, so the
// reconciler stops re-driving it (closes the dead-letter → re-drive livelock).
// cspmJobHandler binds durable CSPM execution and dead-letter finalization.
type cspmJobHandler struct{ svc *cspm.Service }

type vulnerabilitySyncJobHandler struct{ svc *vulnerabilitymonitor.Service }

type vulnerabilityReconcileJobHandler struct {
	svc *vulnerabilityreconciliation.Service
}

func (h vulnerabilityReconcileJobHandler) Handle(ctx context.Context, job ports.QueuedJob) error {
	_, err := h.svc.ExecuteJob(ctx, job.ID)
	return err
}

func (h vulnerabilityReconcileJobHandler) OnDeadLetter(ctx context.Context, job ports.QueuedJob, cause error) error {
	return h.svc.FailJob(ctx, job.ID, cause)
}

func (h vulnerabilitySyncJobHandler) Handle(ctx context.Context, job ports.QueuedJob) error {
	_, err := h.svc.ExecuteJob(ctx, job.ID)
	return err
}

func (h vulnerabilitySyncJobHandler) OnDeadLetter(ctx context.Context, job ports.QueuedJob, cause error) error {
	return h.svc.FailJob(ctx, job.ID, cause)
}

func (h cspmJobHandler) Handle(ctx context.Context, job ports.QueuedJob) error {
	return h.svc.RunJob(ctx, job.Payload)
}

func (h cspmJobHandler) OnDeadLetter(ctx context.Context, job ports.QueuedJob, cause error) error {
	return h.svc.FailStrandedJob(ctx, job.Payload, cause)
}

type agentJobHandler struct{ orch *orchestrator.Orchestrator }

func (h agentJobHandler) Handle(ctx context.Context, job ports.QueuedJob) error {
	return h.orch.RunJob(ctx, job.Payload)
}

func (h agentJobHandler) OnDeadLetter(ctx context.Context, job ports.QueuedJob, cause error) error {
	return h.orch.FailStrandedJob(ctx, job.Payload, cause)
}
