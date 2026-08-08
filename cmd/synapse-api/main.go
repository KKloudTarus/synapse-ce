// Command synapse-api is the HTTP API server entrypoint.
//
// normalize-path → minimal auth (single-user token, fail-closed) →
// first-run AUP gate, in front of the clean-architecture layers. SCA scans are
// gated by engagement scope + authorization window, acquired into an
// isolated workspace, and audited. Real adapters: go-enry (languages),
// Syft (SBOM), OSV.dev (vulns), license policy. Persistence is PostgreSQL when
// SYNAPSE_DB_DSN is set, else in-memory (dev).
package main

import (
	"context"
	"crypto/rand"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/httpapi"
	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/acquire"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/cache/sbomcache"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/ebpf"
	egressinfra "github.com/KKloudTarus/synapse-ce/internal/infrastructure/egress"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetca"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/llm/openai"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/logstream"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/file"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	recontools "github.com/KKloudTarus/synapse-ce/internal/infrastructure/recon"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/report"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/signing"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sourceartifact"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sourcesnippet"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/timestamp"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/toolrunner"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/bincat"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/codeanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/codeinventory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/duplication"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/enry"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/gitdiff"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/gomodgraph"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/govulncheck"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/gradleresolve"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/grype"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ignorefile"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jarchecksum"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jarhash"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jarlicense"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jsimports"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jsresolve"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jvmreach"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/license"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/licensefile"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/licensemeta"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/manifest"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/manifestresolve"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/mavencoord"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/mavenresolve"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/misconfig"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/msi"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/npmresolve"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/nvd"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ospkg"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/osv"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownadvisory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownsbom"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/pyimports"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/qualityprofile"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/risk"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/sast"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/secretscan"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/srcimports"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/syft"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/taintcallgraph"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/vexfile"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/binregistry"
	"github.com/KKloudTarus/synapse-ce/internal/platform/buildinfo"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/platform/httpserver"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/platform/jobs"
	"github.com/KKloudTarus/synapse-ce/internal/platform/logging"
	"github.com/KKloudTarus/synapse-ce/internal/platform/worksign"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/agenttools"
	analysisuc "github.com/KKloudTarus/synapse-ce/internal/usecase/analysis"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/assetuc"
	audituc "github.com/KKloudTarus/synapse-ce/internal/usecase/audit"
	aupuc "github.com/KKloudTarus/synapse-ce/internal/usecase/aup"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/codequality"
	credentialsuc "github.com/KKloudTarus/synapse-ce/internal/usecase/credentials"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/crosscheckjudge"
	dastrunneruc "github.com/KKloudTarus/synapse-ce/internal/usecase/dastrunner"
	dastverifieruc "github.com/KKloudTarus/synapse-ce/internal/usecase/dastverifier"
	dastworkflowuc "github.com/KKloudTarus/synapse-ce/internal/usecase/dastworkflow"
	egresspolicy "github.com/KKloudTarus/synapse-ce/internal/usecase/egress"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	exploitationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/exploitation"
	exportuc "github.com/KKloudTarus/synapse-ce/internal/usecase/export"
	findingsuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findings"
	clusterinventoryuc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/clusterinventory"
	coverageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/coverage"
	hostinventoryuc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetagentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetwork"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fptriage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/jsreach"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/leaderuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/llmverifier"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/pyreach"
	qualitygatesuc "github.com/KKloudTarus/synapse-ce/internal/usecase/qualitygates"
	qualityprofilesuc "github.com/KKloudTarus/synapse-ce/internal/usecase/qualityprofiles"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachproof"
	reconuc "github.com/KKloudTarus/synapse-ce/internal/usecase/recon"
	reportuc "github.com/KKloudTarus/synapse-ce/internal/usecase/report"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/rules"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/sarifingest"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/sbomcrosscheckjudge"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/srcreach"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/taintscan"
	threatmodeluc "github.com/KKloudTarus/synapse-ce/internal/usecase/threatmodeluc"
	transferuc "github.com/KKloudTarus/synapse-ce/internal/usecase/transfer"
	usersuc "github.com/KKloudTarus/synapse-ce/internal/usecase/users"
	vexuc "github.com/KKloudTarus/synapse-ce/internal/usecase/vex"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/worker"
	writeupdraftuc "github.com/KKloudTarus/synapse-ce/internal/usecase/writeupdraftuc"
)

// requireJudgmentsOrSkip decides whether a judgment-minting analyzer that now defaults ON (reachability,
// cross-check, SBOM cross-check) may wire. With the judgment service present it wires. With judgments off it
// AUTO-SKIPS (warn) – a default-on analyzer must not crash a judgments-off deployment – UNLESS the operator
// EXPLICITLY set the analyzer's flag =true, which is a real contradiction worth failing closed on.
func requireJudgmentsOrSkip(log *slog.Logger, hasJudgment bool, envKey, name string) bool {
	if hasJudgment {
		return true
	}
	if _, explicit := os.LookupEnv(envKey); explicit {
		log.Error(name + " requires SYNAPSE_JUDGMENTS_ENABLED (it mints judgments); enable judgments or unset " + envKey)
		os.Exit(1)
	}
	log.Warn(name + " auto-skipped: SYNAPSE_JUDGMENTS_ENABLED is off (it mints judgments)")
	return false
}

func main() {
	cfg := config.Load()
	log := logging.New(cfg.LogLevel)
	log.Info("starting synapse-api", "env", cfg.Environment, "single_tenant", cfg.SingleTenant)

	// Fail closed: no anonymous access. The token is never logged.
	if cfg.APIToken == "" {
		log.Error("SYNAPSE_API_TOKEN is required (no anonymous access). Set it, e.g. `export SYNAPSE_API_TOKEN=$(openssl rand -hex 32)`.")
		os.Exit(1)
	}

	clock := idgen.SystemClock{}
	ids := idgen.RandomID{}
	acquirer := acquire.New().WithMaxWorkspaceBytes(cfg.MaxWorkspaceBytes).WithImageRootFS(cfg.ImageRootFSEnabled).WithComparisonDepth(cfg.ProjectGitComparisonDepth)

	// Persistence: PostgreSQL when configured, else file + in-memory (dev).
	var repo ports.EngagementRepository
	var projectRepo ports.ProjectRepository
	var assetStore ports.AssetRepository
	var scannedImageStore ports.ScannedImageStore
	var workOrderStore ports.WorkOrderStore
	var fleetAgentStore ports.FleetAgentStore
	var leaderStore ports.LeaderStore // postgres only; nil in memory mode (single process)
	var findingRepo ports.FindingRepository
	var judgmentStore analysisuc.Store // postgres or memory; satisfies both the narrow Store + ports.JudgmentStore
	var commentRepo ports.CommentRepository
	var retestRepo ports.RetestRepository
	var userRepo ports.UserRepository
	var auditReader ports.AuditReader
	var scanRepo ports.ScanRepository
	var scanResultStore ports.ScanResultStore
	var importedSBOMStore ports.ImportedSBOMStore
	var importedFindingStore ports.ImportedFindingStore // third-party (SARIF) findings under governance
	var scanJobStore ports.ScanJobStore
	var scanRunStore ports.ScanRunStore
	var projectAnalysisStore ports.ProjectAnalysisStore
	var qualityGateStore ports.QualityGateStore
	var qualityProfileStore ports.QualityProfileStore
	var qualityGateMutator ports.QualityGateMutator
	var reconRunStore ports.ReconRunStore
	var evidenceStore ports.EvidenceStore
	var advisoryStore ports.AdvisoryStore         // owned normalized-advisory store (global reference data, not tenant-scoped)
	var threatModelStore ports.ThreatModelStore   // per-engagement architecture threat model (tenant-scoped)
	var writeupDraftStore ports.WriteupDraftStore // AI-proposed, human-gated finding write-up drafts
	var aupStore ports.AUPStore
	var auditLog ports.AuditLogger
	var timestampStore ports.TimestampStore
	var credVault ports.CredentialVault
	var reconQueue ports.JobQueue                 // durable queue for recon-via-worker (Postgres only)
	var reconRunLock ports.RunLocker              // recon run lease (Postgres only); row-lease, no pinned conn
	var agentRunLock ports.RunLocker              // agent SESSION lock (advisory; cannot expire mid-LLM-loop)
	var agentSessionStore ports.AgentSessionStore // agent sessions + transcript
	var approvalStore ports.ApprovalStore         // durable HITL approval queue
	var planStore ports.PlanStore                 // agent execution-plan DAG
	var decisionStore ports.DecisionStore         // structured decision log

	// Credential vault cipher: a configured master key gives durable
	// encryption; an empty key yields an ephemeral one (dev only – stored secrets won't
	// survive a restart, and Postgres ciphertext becomes undecryptable, so production
	// fails closed). The key is never logged.
	vaultCipher := func() *vault.Cipher {
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
				log.Error("SYNAPSE_VAULT_MASTER_KEY is required in production (durable credential encryption)")
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
	}()

	if cfg.DBDSN != "" {
		// Bounded so a migration that blocks can't hang boot forever. NOTE: no
		// advisory lock yet – run a single instance (or a one-shot migrate job)
		// until multi-replica horizontal scaling lands (P5).
		startup, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := postgres.Migrate(startup, cfg.DBDSN); err != nil {
			log.Error("db migrate failed", "err", err)
			os.Exit(1)
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
		// Single-instance guard: until horizontal scaling the repos
		// ignore tenant_id and there is no leader election, so two writers would race. A
		// session advisory lock makes the assumption explicit + enforced – a second
		// instance fails fast instead of silently corrupting state.
		lockConn, ok, lerr := postgres.AcquireSingletonLock(startup, pool, "api")
		if lerr != nil {
			log.Error("single-instance lock check failed", "err", lerr)
			os.Exit(1)
		}
		if !ok {
			log.Error("another synapse-api instance holds the single-instance lock – this build runs ONE instance (stop the other first); horizontal scaling is P5")
			os.Exit(1)
		}
		defer lockConn.Release()
		log.Info("acquired single-instance advisory lock")
		repo = postgres.NewEngagementRepository(pool)
		projectRepo = postgres.NewProjectRepository(pool)
		findingRepo = postgres.NewFindingRepository(pool)
		judgmentStore = postgres.NewJudgmentRepository(pool)
		commentRepo = postgres.NewCommentRepository(pool)
		retestRepo = postgres.NewRetestRepository(pool)
		userRepo = postgres.NewUserRepository(pool)
		scanRepo = postgres.NewScanRepository(pool)
		scanResultStore = postgres.NewScanResultStore(pool)
		importedSBOMStore = postgres.NewImportedSBOMStore(pool)
		importedFindingStore = postgres.NewImportedFindingRepository(pool)
		scanJobStore = postgres.NewScanJobStore(pool)
		scanRunStore = postgres.NewScanRunStore(pool)
		projectAnalysisStore = postgres.NewProjectAnalysisStore(pool)
		qualityGateStore = postgres.NewQualityGateStore(pool)
		qualityProfileStore = postgres.NewQualityProfileStore(pool)
		reconRunStore = postgres.NewReconRunStore(pool)
		evidenceStore = postgres.NewEvidenceStore(pool)
		advisoryStore = postgres.NewAdvisoryRepository(pool)
		threatModelStore = postgres.NewThreatModelRepository(pool)
		writeupDraftStore = postgres.NewWriteupDraftRepository(pool)
		assetStore = postgres.NewAssetRepository(pool)
		scannedImageStore = postgres.NewScannedImageStore(pool)
		workOrderStore = postgres.NewWorkOrderRepository(pool)
		fleetAgentStore = postgres.NewFleetAgentRepository(pool)
		leaderStore = postgres.NewLeaderStore(pool)
		// SECURITY (#431 req 6, #432, #409): the fleet_* tables are RLS-protected, but RLS is a
		// silent no-op if the runtime DB role is SUPERUSER or holds BYPASSRLS. When any fleet
		// feature is enabled we refuse to serve unless the role can actually enforce isolation.
		// imported_findings is RLS-protected too (migration 0064), and RLS is a silent no-op under a
		// SUPERUSER/BYPASSRLS role no matter what FORCE says. The check is unconditional here rather
		// than fleet-only: a table whose isolation claim is written into its own migration must not be
		// served by a role that cannot honour it.
		if rerr := postgres.CheckRLSRuntimeRole(startup, pool); rerr != nil {
			log.Error("an RLS-protected table is in use but the DB role cannot enforce row level security – refusing to serve", "err", rerr)
			os.Exit(1)
		}
		aupStore = postgres.NewAUPStore(pool)
		pgAudit := postgres.NewAuditLog(pool)
		auditLog, auditReader = pgAudit, pgAudit
		qualityGateMutator = postgres.NewQualityGateMutator(pool)
		timestampStore = postgres.NewTimestampStore(pool)
		credVault = vault.NewPostgresVault(pool, vaultCipher)
		reconQueue = postgres.NewJobQueue(pool, ids)
		// Shared by recon AND the in-process SCA worker, so the base lease TTL must cover the
		// longer of the two timeouts (the renewer extends it while live, but the base must not
		// be shorter than a max-length scan). row-lease: no pinned conn.
		reconRunLock = postgres.NewLeaseRunLock(pool, ids.NewID().String(), max(cfg.ReconTimeout, cfg.ScanTimeout)+time.Minute)
		agentRunLock = postgres.NewRunLock(pool) // advisory: held for the agent run, cannot expire mid-loop
		agentSessionStore = postgres.NewAgentSessionStore(pool)
		approvalStore = postgres.NewApprovalStore(pool)
		planStore = postgres.NewAgentPlanStore(pool)
		decisionStore = postgres.NewAgentDecisionStore(pool)
		log.Info("persistence: postgres")
	} else {
		repo = memory.NewEngagementRepository()
		projectRepo = memory.NewProjectRepository()
		assetStore = memory.NewAssetStore()
		scannedImageStore = memory.NewScannedImageStore()
		workOrderStore = memory.NewWorkOrderStore()
		fleetAgentStore = memory.NewFleetAgentStore()
		findingRepo = memory.NewFindingRepository()
		judgmentStore = memory.NewJudgmentStore()
		commentRepo = memory.NewCommentRepository()
		retestRepo = memory.NewRetestRepository()
		userRepo = memory.NewUserRepository()
		scanRepo = memory.NewScanRepository()
		scanResultStore = memory.NewScanResultStore()
		importedSBOMStore = memory.NewImportedSBOMStore()
		importedFindingStore = memory.NewImportedFindingStore()
		scanJobStore = memory.NewScanJobStore()
		scanRunStore = memory.NewScanRunStore()
		projectAnalysisStore = memory.NewProjectAnalysisStore()
		qualityGateStore = memory.NewQualityGateStore()
		qualityProfileStore = memory.NewQualityProfileStore()
		reconRunStore = memory.NewReconRunRepository()
		evidenceStore = memory.NewEvidenceStore()
		advisoryStore = memory.NewAdvisoryStore()
		threatModelStore = memory.NewThreatModelStore()
		writeupDraftStore = memory.NewWriteupDraftStore()
		aupStore = file.NewAUPStore(cfg.AUPFile)
		fileAudit := file.NewAuditLog(cfg.AuditFile)
		auditLog, auditReader = fileAudit, fileAudit
		qualityGateMutator = memory.NewQualityGateMutator(qualityGateStore.(*memory.QualityGateStore), projectRepo.(*memory.ProjectRepository), auditLog)
		timestampStore = memory.NewTimestampStore()
		credVault = vault.NewMemoryVault(vaultCipher, nil)
		agentSessionStore = memory.NewAgentSessionStore()
		approvalStore = memory.NewApprovalStore()
		planStore = memory.NewPlanStore()
		decisionStore = memory.NewDecisionStore()
		log.Info("persistence: in-memory + file (set SYNAPSE_DB_DSN for postgres)")
	}

	// Reproducibility provenance: tool/lib versions captured at startup;
	// Syft's version is read per scan from the SBOM, the OSV snapshot from scan time.
	prov := ports.Provenance{
		ToolVersions: map[string]string{
			"go-enry": buildinfo.Module("github.com/go-enry/go-enry/v2"),
			"synapse": buildinfo.App(),
		},
		VulnDBSource: "osv.dev",
	}

	// Use cases.
	engService := enguc.NewService(repo, clock, ids, auditLog)
	projectService := projectuc.NewService(projectRepo, repo, clock, ids, auditLog, !cfg.IsProduction())
	projectService.SetArchiveStore(file.NewProjectArchiveStore(cfg.ProjectUploadDir, cfg.MaxWorkspaceBytes))
	projectService.SetAnalysisStore(projectAnalysisStore)
	if issueStore, ok := projectAnalysisStore.(ports.ProjectIssueStore); ok {
		projectService.SetIssueStore(issueStore)
	} else {
		log.Error("project issue store is not configured")
		os.Exit(1)
	}
	if hotspotStore, ok := projectAnalysisStore.(ports.ProjectHotspotStore); ok {
		projectService.SetHotspotStore(hotspotStore)
	} else {
		log.Error("project hotspot store is not configured")
		os.Exit(1)
	}
	projectService.SetFindingRepository(findingRepo)
	qualityGateService := qualitygatesuc.NewService(qualityGateStore, auditLog, clock)
	qualityGateService.SetMutator(qualityGateMutator)
	projectService.SetQualityGates(qualityGateService)
	projectService.SetQualityGateMutator(qualityGateMutator)
	ruleCatalog, catalogErr := rulecatalog.Default()
	if catalogErr != nil {
		log.Error("rule catalog init failed", "err", catalogErr)
		os.Exit(1)
	}
	projectService.SetRuleCatalog(ruleCatalog)
	qualityProfileService := qualityprofilesuc.NewService(qualityProfileStore, ruleCatalog, projectRepo, auditLog, clock)
	projectService.SetQualityProfiles(qualityProfileService)
	// Measures API cursor signing: an HMAC-SHA256 key that prevents pagination token tampering.
	// Production MUST supply at least 32 bytes via SYNAPSE_MEASURE_CURSOR_SECRET; dev gets an
	// ephemeral random key (cursors won't survive a restart, which is acceptable for dev).
	{
		var cursorKey []byte
		if raw := cfg.MeasureCursorSecret; raw != "" {
			cursorKey = []byte(raw)
		} else if cfg.IsProduction() {
			log.Error("SYNAPSE_MEASURE_CURSOR_SECRET is required in production (at least 32 bytes); set it, e.g. `openssl rand -hex 32`")
			os.Exit(1)
		} else {
			cursorKey = make([]byte, 32)
			if _, err := rand.Read(cursorKey); err != nil {
				log.Error("measure cursor secret ephemeral key generation failed", "err", err)
				os.Exit(1)
			}
			log.Warn("measure cursor signing key is ephemeral – set SYNAPSE_MEASURE_CURSOR_SECRET; tokens won't survive restart")
		}
		if err := projectService.SetCursorSecret(cursorKey); err != nil {
			log.Error("measure cursor signing key rejected", "err", err)
			os.Exit(1)
		}
	}
	// Evidence artifact blob store: MinIO/S3 when configured, else in-memory (dev).
	var blobStore ports.BlobStore
	if cfg.BlobEndpoint != "" {
		bs, err := blob.NewMinIO(context.Background(), blob.Config{
			Endpoint:  cfg.BlobEndpoint,
			AccessKey: cfg.BlobAccessKey,
			SecretKey: cfg.BlobSecretKey,
			Bucket:    cfg.BlobBucket,
			UseSSL:    cfg.BlobUseSSL,
		})
		if err != nil {
			log.Error("blob store init failed", "err", err)
			os.Exit(1)
		}
		blobStore = bs
		log.Info("blob store: minio/s3", "bucket", cfg.BlobBucket)
	} else {
		blobStore = blob.NewMemory()
		log.Info("blob store: in-memory (set SYNAPSE_BLOB_ENDPOINT for MinIO/S3)")
	}
	// Evidence vault: the one tamper-evident chain + verify-on-read path per engagement.
	evidenceService, err := evidenceuc.NewService(evidenceStore, blobStore, auditLog, clock, ids)
	if err != nil {
		log.Error("evidence vault init failed", "err", err)
		os.Exit(1)
	}
	evidenceService.SetLogger(log) // surface dropped tamper alerts (not silent)
	// Chain-head attestation (audit anchor): one ed25519 signer attests verified
	// evidence AND audit heads, so both custody chains prove origin, not just integrity.
	// A configured seed gives a stable key id; an empty seed yields an ephemeral key
	// (self-verifying, but not stable across runs).
	// auditSigner is the audit-context sibling of the evidence signer (same key, a
	// distinct domain-separation tag) so an evidence-head attestation can never be
	// replayed as an audit-head one. Assigned alongside the evidence signer below.
	var auditSigner ports.ChainSigner
	if seed, serr := signing.DecodeSeed(cfg.EvidenceSigningSeed); serr != nil {
		log.Error("evidence signing seed invalid", "err", serr) // never log the seed itself
		os.Exit(1)
	} else if signer, serr := signing.NewEd25519Signer(seed); serr != nil {
		log.Error("evidence signer init failed", "err", serr)
		os.Exit(1)
	} else {
		if signer.Ephemeral() && cfg.IsProduction() {
			// Fail closed: an ephemeral key changes every restart, so "origin attested"
			// would be a custody claim the instance cannot stand behind across runs.
			log.Error("SYNAPSE_EVIDENCE_SIGNING_SEED is required in production for a stable attestation key")
			os.Exit(1)
		}
		evidenceService.SetSigner(signer.WithContext(evidence.AttestationContextEvidence))
		auditSigner = signer.WithContext(evidence.AttestationContextAudit)
		if signer.Ephemeral() {
			log.Warn("chain-head signing key is ephemeral – set SYNAPSE_EVIDENCE_SIGNING_SEED for a stable attestation key", "key_id", signer.KeyID())
		} else {
			log.Info("chain-head attestation enabled (evidence + audit)", "key_id", signer.KeyID())
		}
	}
	// External RFC-3161 anchor: when a TSA is configured, verified evidence + audit
	// heads are externally timestamped (tamper-PROOF). The token is stored/returned
	// out-of-band, so report bytes are unchanged whether or not a TSA is set. Best-effort:
	// an unreachable TSA leaves heads pending-anchor, never failing a verify/report. The
	// audit service is given the timestamper after it is constructed below.
	var tsaClient ports.TimestampAuthority
	if cfg.TSAURL != "" {
		tc, terr := timestamp.NewClient(cfg.TSAURL, 0)
		if terr != nil {
			log.Error("timestamp authority init failed", "err", terr)
			os.Exit(1)
		}
		tsaClient = tc
		log.Info("external RFC-3161 anchoring enabled", "tsa", cfg.TSAURL)
	}
	evidenceService.SetTimestamper(tsaClient, timestampStore)
	// SCA tool sandboxing (closes audit finding D2): syft + grype are offline, so
	// when the sandbox is enabled they run in an ISOLATED sandbox (read-only FS, no
	// network, dropped caps) – no egress/vault needed. Build/parse output is unchanged.
	// Best-effort: if bubblewrap is unavailable, syft/grype degrade to a direct exec.
	syftGen := syft.New(cfg.SyftBin)
	grypeSrc := grype.New(cfg.GrypeBin, cfg.GrypeDBDir)
	var scaSandbox *sandbox.Runner // hoisted: shared by syft/grype/acquisition AND the govulncheck reachability builder
	if cfg.SandboxEnabled {
		sb, serr := sandbox.NewRunner(cfg.ScanTimeout, cfg.ReconMaxOutput, cfg.SandboxMemMax, cfg.SandboxPidsMax)
		if serr != nil {
			// Fail CLOSED (re-audit fix): the operator explicitly asked for the sandbox
			// (SYNAPSE_SANDBOX_ENABLED=true); if it cannot be built we must NOT silently
			// degrade to a direct host exec of syft/grype/git/crane. Refuse to start –
			// mirrors the worker (which os.Exit's) and the prod-vault-key hardening.
			log.Error("SYNAPSE_SANDBOX_ENABLED is set but the sandbox is unavailable – refusing to run SCA/acquisition UNSANDBOXED; install bubblewrap or unset the flag", "err", serr)
			os.Exit(1)
		}
		scaSandbox = sb
		// syft/grype have no EgressPolicy on their spec → isolated netns, even though the
		// same runner is egress-capable; only the git clone spec carries a policy.
		scaSandbox.SetBinaryRegistry(binregistry.New(cfg.ToolHashes, true)) // refuse a replaced syft/grype (TOFU)
		syftGen = syftGen.WithRunner(scaSandbox)
		grypeSrc = grypeSrc.WithRunner(scaSandbox)
		log.Info("SCA tools (syft/grype) run sandboxed-isolated")
		// acquisition (git/image) ALWAYS runs sandboxed – never a direct exec. When
		// kernel egress is usable here (privileged), scope egress to the repo/registry
		// host; otherwise the fetch runs host-net but STILL fully sandboxed
		// (fs/seccomp/caps/cgroup), removing the direct-exec RCE surface.
		egressScoped := false
		if app, aerr := egressinfra.NewApplier(); aerr == nil {
			pctx, pcancel := context.WithTimeout(context.Background(), 10*time.Second)
			perr := app.Probe(pctx)
			pcancel()
			if perr == nil {
				scaSandbox.SetEgress(app)
				egressScoped = true
			}
		}
		acquirer = acquirer.WithSandbox(scaSandbox, egressScoped)
		if egressScoped {
			log.Info("acquisition (git/image) runs sandboxed + egress-scoped to the repo/registry host")
		} else {
			log.Info("acquisition (git/image) runs sandboxed (host-net; kernel egress scoping unavailable here)")
		}
	} else if cfg.IsProduction() {
		// Production must not ship with zero containment (re-audit: the flag defaults off).
		log.Error("SYNAPSE_SANDBOX_ENABLED is required in production (tool execution + acquisition containment); set it and install bubblewrap")
		os.Exit(1)
	} else {
		log.Warn("SANDBOX DISABLED (SYNAPSE_SANDBOX_ENABLED is off) – syft/grype/git/crane run UNSANDBOXED with NO seccomp/rootfs/egress/cgroup containment; dev only, never production")
	}
	// SBOM producer select: default Syft (pinned binary, full coverage + CycloneDX
	// dep-graph edges) or the detection-independent owned parsers. ownsbom is pure-Go (no exec) so it
	// needs no sandbox; its SBOM is components-only (no edges) over Tier-1 ecosystems – which OSV and
	// grype both accept (grype reconstructs a CycloneDX from the components when there is no Raw).
	var sbomGen ports.SBOMGenerator = syftGen
	switch cfg.SBOMProducer {
	case "", "syft":
		log.Info("SBOM producer = syft (pinned binary; full ecosystem coverage + CycloneDX dep-graph edges)") // default, wired above
	case "ownsbom":
		reg, rerr := ownsbom.DefaultRegistry()
		if rerr != nil {
			log.Error("build ownsbom SBOM producer", "err", rerr)
			os.Exit(1)
		}
		sbomGen = reg
		log.Info("SBOM producer = ownsbom (detection-independent owned parsers; no third-party scanner; components-only over Tier-1 ecosystems)")
	default:
		log.Error("invalid SYNAPSE_SBOM_PRODUCER (want 'syft' or 'ownsbom')", "value", cfg.SBOMProducer)
		os.Exit(1)
	}
	// Detection sources: Grype (offline DB) always; live OSV unless SYNAPSE_OFFLINE (air-gapped /
	// fast path – no per-scan network egress). The owned advisory store is opt-in
	// and offline, so it runs in both modes (detection independence).
	detectionSources := []ports.DetectionSource{grypeSrc}
	if !cfg.Offline {
		detectionSources = append([]ports.DetectionSource{osv.New(cfg.OSVBaseURL, nil)}, detectionSources...)
	} else {
		log.Info("SYNAPSE_OFFLINE: live OSV source disabled; detecting with offline sources only", "grype", true, "owned_advisory", cfg.OwnedAdvisoryEnabled)
	}
	if cfg.OwnedAdvisoryEnabled {
		detectionSources = append(detectionSources, ownadvisory.New(advisoryStore))
		log.Info("owned advisory DetectionSource ENABLED (offline match against the owned store, alongside OSV/Grype) – ensure the store is populated; an empty store yields no findings until the advisory ingester runs")
	}
	scaService := scauc.NewService(repo, findingRepo, scanRepo, scanResultStore, scanJobStore, scanRunStore, evidenceService, ids, prov, clock, auditLog, shared.Severity(cfg.FindingMinSeverity), cfg.ScanTimeout, acquirer,
		enry.New(), sbomGen,
		detectionSources,
		risk.New(cfg.KEVURL, cfg.EPSSURL, nil), license.New(), licensemeta.NewChain(licensemeta.NewOSMetadata(), licensemeta.New(cfg.DepsDevURL, nil), licensemeta.NewPyPI("", nil)))
	scaService.SetImportedSBOMStore(importedSBOMStore)
	// Record scanned image digests so the fleet cluster agent can correlate running images (#446).
	scaService.SetScannedImageRecorder(scannedImageStore)
	scaService.SetGateDecoder(qualityprofile.LoadGateBytes)
	scaService.SetSBOMEnricher(manifest.New())
	scaService.SetArtifactCataloger(msi.New())           // recover Windows Installer (.msi) product identity into the SBOM
	scaService.SetMavenCoordResolver(mavencoord.New())   // recover real Maven coords from JAR pom.properties (offline) before license lookup
	scaService.SetJarChecksumResolver(jarchecksum.New()) // capture JAR artifact SHA-1 from the workspace (Syft omits it from CycloneDX)
	// SHA-1 coordinate recovery for shaded/metadata-less JARs: offline trivy-java-db-format
	// index first (if configured), online Maven Central as the fallback. Best-effort.
	var jhResolvers []ports.JarHashResolver
	if cfg.JarHashDBPath != "" {
		if off, err := jarhash.NewOffline(cfg.JarHashDBPath); err != nil {
			log.Warn("JAR SHA-1 offline DB not usable – falling back to online only if enabled", "path", cfg.JarHashDBPath, "err", err)
		} else {
			defer func() { _ = off.Close() }() // release the read-only DB handle at shutdown
			jhResolvers = append(jhResolvers, off)
			log.Info("JAR SHA-1 coordinate recovery: OFFLINE index ENABLED (air-gap; no rate limit)", "path", cfg.JarHashDBPath)
		}
	}
	if cfg.JarHashOnlineEnabled {
		// An egress call to Maven Central; on the sandbox it needs search.maven.org in the egress allow-list.
		jhResolvers = append(jhResolvers, jarhash.New(cfg.JarHashBaseURL, nil))
		log.Info("JAR SHA-1 coordinate recovery: ONLINE Maven Central ENABLED (best-effort; fallback after offline)")
	}
	if len(jhResolvers) > 0 {
		scaService.SetJarHashResolver(jarhash.NewChain(jhResolvers...))
	}
	// Backfill unknown vuln severities from NVD CVSS (best-effort; set SYNAPSE_NVD_API_KEY for throughput).
	scaService.SetSeverityEnricher(nvd.New(cfg.NVDAPIURL, cfg.NVDAPIKey, nil).WithBudget(cfg.NVDBudget))
	scaService.SetIgnoreUnfixed(cfg.IgnoreUnfixed) // SYNAPSE_IGNORE_UNFIXED: suppress no-upstream-fix vulns (distro-noise reducer)
	// Offline license-text fallback: JAR-embedded licenses (jarlicense) + workspace LICENSE
	// files for every ecosystem.
	scaService.SetLicenseFileResolver(licensefile.NewChain(jarlicense.New(), licensefile.New()))
	// Transitive Go dependency edges via `go mod graph`, opt-in + best-effort. Sandboxed when the
	// SCA sandbox is on (low-risk: go mod graph only reads go.mod files, never compiles); a non-Go target /
	// no module cache adds no edges and never fails the scan.
	if cfg.GoModGraphEnabled {
		gmg := gomodgraph.New(cfg.GoBin)
		if scaSandbox != nil {
			gmg = gmg.WithRunner(scaSandbox)
		} else {
			// dev only (prod attaches the sandbox above): the direct path still pins GOPROXY=off +
			// GOTOOLCHAIN=local, but runs `go` outside the bwrap confinement – make that explicit.
			log.Warn("go mod graph runs UNSANDBOXED (SCA sandbox off; dev only)")
		}
		scaService.SetGraphResolver(gmg)
		log.Info("Go transitive-edge resolution ENABLED (go mod graph; best-effort, sandboxed when available)")
	}
	// Maven full-tree resolution (`mvn dependency:list`): resolves managed versions + the transitive tree
	// a from-source pom.xml scan can't, so Maven projects stop under-reporting. HIGHER RISK than go mod
	// graph – it RUNS the Maven toolchain (POM + parent-POM + plugin resolution) over UNTRUSTED project
	// config and reaches the Maven repo. The SERVER therefore enables it ONLY when the SCA sandbox is
	// present (egress confined to Maven Central) and FAILS CLOSED otherwise – it never host-execs mvn over
	// an untrusted target. Direct-exec is left to synapse-cli, the trusted-local dogfood path. Opt-in.
	if cfg.MavenResolveEnabled {
		if scaSandbox == nil {
			log.Warn("SYNAPSE_MAVEN_RESOLVE_ENABLED ignored: it requires the SCA sandbox (mvn would otherwise run untrusted POM config on the host). Enable the sandbox to use it.")
		} else {
			scaService.SetMavenResolver(mavenresolve.New(cfg.MvnBin).WithRunner(scaSandbox).
				WithRepoHosts(cfg.MavenRepoHosts).WithLocalRepo(cfg.MavenLocalRepo))
			log.Info("Maven transitive-tree resolution ENABLED (mvn dependency:list, sandbox-confined; best-effort)", "extra_repo_hosts", len(cfg.MavenRepoHosts), "persistent_cache", cfg.MavenLocalRepo != "")
		}
	}
	// Gradle full-tree resolution (`gradle dependencies`): same gap as Maven, but evaluating build.gradle
	// runs arbitrary build logic – so the SERVER enables it ONLY with the SCA sandbox and FAILS CLOSED
	// otherwise (never host-execs gradle over an untrusted target). A pinned gradle, never./gradlew.
	if cfg.GradleResolveEnabled {
		if scaSandbox == nil {
			log.Warn("SYNAPSE_GRADLE_RESOLVE_ENABLED ignored: it requires the SCA sandbox (gradle would otherwise run untrusted build logic on the host). Enable the sandbox to use it.")
		} else {
			scaService.SetGradleResolver(gradleresolve.New(cfg.GradleBin).WithRunner(scaSandbox).
				WithRepoHosts(cfg.MavenRepoHosts).WithGradleHome(cfg.GradleHome))
			log.Info("Gradle transitive-tree resolution ENABLED (gradle dependencies, sandbox-confined; best-effort)", "extra_repo_hosts", len(cfg.MavenRepoHosts), "persistent_cache", cfg.GradleHome != "")
		}
	}
	// npm resolution for a lockfile-less package.json (`npm install --package-lock-only --ignore-scripts`):
	// reaches the registry over an untrusted manifest, so the SERVER enables it ONLY with the SCA sandbox
	// and FAILS CLOSED otherwise (never host-execs npm over an untrusted target). --ignore-scripts + a
	// throwaway copy mean no project code runs and the source is never mutated. Opt-in.
	if cfg.NPMResolveEnabled {
		if scaSandbox == nil {
			log.Warn("SYNAPSE_NPM_RESOLVE_ENABLED ignored: it requires the SCA sandbox (npm would otherwise reach the network over an untrusted manifest on the host). Enable the sandbox to use it.")
		} else {
			scaService.SetNPMResolver(npmresolve.New(cfg.NPMBin).WithRunner(scaSandbox).WithRegistryHosts(cfg.NPMRegistryHosts))
			log.Info("npm resolution ENABLED (npm install --package-lock-only, sandbox-confined; best-effort)", "extra_registry_hosts", len(cfg.NPMRegistryHosts))
		}
	}
	// Lockfile-less manifest resolvers (composer.json / Gemfile / pyproject.toml): each runs its ecosystem
	// tool over an untrusted manifest and reaches the registry, so the SERVER enables them ONLY with the SCA
	// sandbox and FAILS CLOSED otherwise. Lock-only + no-scripts + a throwaway copy mean no project code runs.
	if cfg.ManifestResolveEnabled {
		if scaSandbox == nil {
			log.Warn("SYNAPSE_MANIFEST_RESOLVE_ENABLED ignored: it requires the SCA sandbox (composer/bundle/poetry would otherwise reach the network over an untrusted manifest on the host). Enable the sandbox to use it.")
		} else {
			binOf := map[string]string{"composer": cfg.ComposerBin, "gem": cfg.BundleBin, "poetry": cfg.PoetryBin}
			for _, eco := range []string{"composer", "gem", "poetry"} {
				scaService.AddManifestResolver(manifestresolve.New(eco, binOf[eco]).WithRunner(scaSandbox).WithRegistryHosts(cfg.ManifestRegistryHosts))
			}
			log.Info("lockfile-less manifest resolution ENABLED (composer/gem/poetry, sandbox-confined; best-effort)", "extra_registry_hosts", len(cfg.ManifestRegistryHosts))
		}
	}
	if cfg.JVMReachabilityEnabled {
		// Read-only bytecode parsing (no exec, no ToolRunner needed) – tags JVM components reachable/
		// unreferenced from the app's compiled closure. Best-effort; a not-built target tags nothing.
		scaService.SetJVMReachability(jvmreach.New())
		log.Info("coarse JVM class-reachability ENABLED (deprioritizes findings on unreferenced deps)")
	}
	if cfg.SASTEnabled {
		scaService.SetSASTAnalyzer(sast.New()) // deterministic pattern-SAST in the scan pipeline
		log.Info("pattern-SAST ENABLED (weak crypto / hardcoded secrets / insecure config)")
	}
	if cfg.SecretScanEnabled {
		scaService.SetSecretScanner(secretscan.New()) // deterministic, redacted secret scan in the scan pipeline
		log.Info("secret scanning ENABLED (hardcoded credentials; matches redacted)")
	}
	if cfg.ImageRootFSEnabled {
		scaService.SetOSPackageCataloger(ospkg.New())         // owned dpkg/apk cataloging from the materialized image rootfs
		scaService.SetInstalledPackageCataloger(bincat.New()) // owned Go-binary + Python dist-info cataloging from the rootfs
		log.Info("image-rootfs cataloging ENABLED (dpkg + apk OS packages; Go binaries + Python dist-info)")
	}
	if cfg.MisconfigEnabled {
		// Helm chart rendering shells out `helm template` over an UNTRUSTED chart; like the maven/gradle
		// resolvers it must be sandbox-confined on the API host (a crafted chart's Sprig getHostByName is an
		// SSRF vector). Wire it through the SCA sandbox when present; otherwise leave Helm rendering OFF.
		mc := misconfig.New()
		helmMode := "Helm rendering OFF (no SCA sandbox; a chart runs untrusted templates on the host)"
		if scaSandbox != nil {
			mc = mc.WithHelmRunner(scaSandbox)
			helmMode = "Helm charts rendered sandboxed (egress-denied)"
		}
		scaService.SetMisconfigScanner(mc) // deterministic IaC/config misconfig scan in the scan pipeline
		log.Info("misconfig scanning ENABLED (Dockerfile + Kubernetes + Terraform); " + helmMode)
	}
	// AI false-positive triage in the scan pipeline (opt-in, best-effort, PROPOSE-ONLY). Independent of
	// the agent: it critiques production-scope source findings. Single-model output is advisory-only; a
	// distinct verifier is required before the deterministic high-risk floor may grant a gate exemption.
	if cfg.FPTriageEnabled && strings.TrimSpace(cfg.FPTriageModel) != "" {
		scaService.SetFPTriageMode(scauc.AITriageMode(cfg.FPTriageMode))
		if tllm, terr := openai.New(cfg.LLMBaseURL, cfg.LLMAPIKey, cfg.FPTriageModel, cfg.LLMTimeout); terr != nil {
			log.Warn("AI false-positive triage DISABLED (LLM unavailable)", "err", terr)
		} else {
			coord := fptriage.New(tllm, cfg.FPTriageModel)
			mode := "advisory-only (distinct verifier required for gate exemption)"
			if cfg.VerifierModel != "" && cfg.VerifierModel != cfg.FPTriageModel {
				if vllm, verr := openai.New(cfg.LLMBaseURL, cfg.LLMAPIKey, cfg.VerifierModel, cfg.LLMTimeout); verr == nil {
					coord.WithVerifier(vllm, cfg.VerifierModel)
					if coord.VerifierModel() != "" {
						mode = "verified by " + coord.VerifierModel()
					} else {
						log.Warn("AI FP-triage verifier aliases the proposer after canonicalization; triage remains advisory-only", "verifier_model", cfg.VerifierModel)
					}
				} else {
					log.Warn("AI FP-triage verifier unavailable; triage remains advisory-only", "err", verr)
				}
			}
			scaService.SetFPTriage(fptriage.NewTriager(coord, func(root string) ports.SourceSnippetReader {
				return sourcesnippet.Reader{Root: root}
			}))
			log.Info("AI false-positive triage ENABLED ("+mode+")", "model", cfg.FPTriageModel, "triage_mode", cfg.FPTriageMode)
		}
	}
	if cfg.SuppressionEnabled {
		scaService.SetSuppressionLoader(ignorefile.New()) // repo-committed .synapseignore accepted-risk policy
		log.Info("suppression ENABLED (.synapseignore; suppressed findings retained + surfaced)")
	}
	if cfg.VEXEnabled {
		scaService.SetVEXLoader(vexfile.New()) // in-repo OpenVEX (.synapse.vex.json) accepted-risk assertions
		log.Info("in-scan VEX ENABLED (.synapse.vex.json; not_affected/fixed gate-exempt, still reported + sealed)")
	}
	if cfg.ComplianceEnabled {
		scaService.SetComplianceEnabled(true) // attach the AppSec-baseline benchmark (per-control PASS/FAIL)
		log.Info("compliance report ENABLED (Synapse AppSec Baseline; deterministic, LLM-free)")
	}
	scaService.SetDBMaxAgeDays(cfg.DBMaxAgeDays) // warn on stale reference DBs (KEV/EPSS/vuln-DB); 0 disables
	// Validate the configured detection priority once at startup: an invalid value would otherwise make
	// EVERY API scan return 400. Warn + fall back to comprehensive rather than crash a long-running server.
	detPriority := cfg.DetectionPriority
	if detPriority != "" {
		if _, err := scauc.NormalizeScanOptions(scauc.ScanOptions{Mode: scauc.ScanModeFull, DetectionPriority: detPriority}); err != nil {
			log.Warn("invalid SYNAPSE_DETECTION_PRIORITY; falling back to comprehensive", "value", detPriority, "err", err)
			detPriority = ""
		}
	}
	scaService.SetDetectionPriority(detPriority) // server default (comprehensive|precise); the API scan path has no per-request priority
	if cfg.ScanCacheEnabled {
		if dir := cfg.ResolveScanCacheDir(); dir != "" {
			scaService.SetSBOMCache(sbomcache.New(dir)) // content+version-addressed generated-SBOM cache
			log.Info("SBOM cache ENABLED", "dir", dir)
		}
	}
	aupService := aupuc.NewService(aupStore, auditLog, clock, cfg.AUPVersion)
	exportService := exportuc.NewService(findingRepo, clock, buildinfo.App())
	findingsService := findingsuc.NewService(findingRepo, commentRepo, retestRepo, auditLog, clock, ids)
	// Exploitation needs the SCORE-MUTATING finding store (SetEvidenceScore is on the concrete
	// repo, NOT ports.FindingRepository – read-only consumers can't move a score). Both the
	// postgres + memory concrete repos implement it; assert it from the interface-typed var.
	exploitFindings, ok := findingRepo.(exploitationuc.FindingStore)
	if !ok {
		log.Error("finding repository does not support evidence scoring (SetEvidenceScore)")
		os.Exit(1)
	}
	exploitationService, err := exploitationuc.NewService(exploitFindings, evidenceService, auditLog, clock, ids) // finding lifecycle
	if err != nil {
		log.Error("exploitation service init failed", "err", err)
		os.Exit(1)
	}
	reportService := reportuc.NewService(repo, findingRepo, retestRepo, evidenceService, report.NewRenderer(), scaService, clock, buildinfo.App())
	// Report builder formats: deterministic HTML/DOCX renderers consume the
	// same assembled document; PDF keeps its own typed maroto path.
	reportService.RegisterFormat(reportuc.FormatHTML, report.NewHTMLRenderer())
	reportService.RegisterFormat(reportuc.FormatDOCX, report.NewDOCXRenderer())
	// Engagement export/import: a portable bundle whose evidence chain is
	// re-verified on import (a tampered chain is rejected before any write).
	transferService, err := transferuc.NewService(repo, findingRepo, commentRepo, evidenceService, auditLog, clock, ids)
	if err != nil {
		log.Error("transfer service init failed", "err", err)
		os.Exit(1)
	}
	// VEX consume: apply client OpenVEX statements to findings (CRA-aligned).
	vexService, err := vexuc.NewService(repo, findingRepo, auditLog, clock)
	if err != nil {
		log.Error("vex service init failed", "err", err)
		os.Exit(1)
	}

	// Recon orchestration: one shared execution guard, an argv-only
	// ToolRunner (timeout + output cap), a bounded worker pool replacing the P1 bare
	// goroutine, and an in-memory log broker for SSE. Live recon stays lab-only
	// behind each engagement's LiveReconEnabled flag.
	reconGuard, err := execution.NewGuard(repo, clock, auditLog)
	if err != nil {
		log.Error("recon guard init failed", "err", err)
		os.Exit(1)
	}
	logBroker := logstream.NewBroker(0)
	reconPool := jobs.NewPool(cfg.ReconConcurrency, cfg.ReconQueueSize)
	defer reconPool.Shutdown(context.Background())
	// Select the tool runner: the bubblewrap sandbox when enabled, else the plain
	// argv ExecRunner. Fail closed if the sandbox is required but unavailable – never
	// silently run unsandboxed (mirrors the prod-signing-seed hardening).
	var reconRunner ports.ToolRunner = toolrunner.NewExecRunner(cfg.ReconTimeout, cfg.ReconMaxOutput)
	egressLive := false // set when the sandbox can kernel-enforce scope egress
	if cfg.SandboxEnabled {
		sb, serr := sandbox.NewRunner(cfg.ReconTimeout, cfg.ReconMaxOutput, cfg.SandboxMemMax, cfg.SandboxPidsMax)
		if serr != nil {
			log.Error("SYNAPSE_SANDBOX_ENABLED but the sandbox is unavailable – install bubblewrap or disable it", "err", serr)
			os.Exit(1)
		}
		reconRunner = sb
		sb.SetVault(credVault)                                      // resolve {{secret:NAME}} into the child env at exec time
		sb.SetBinaryRegistry(binregistry.New(cfg.ToolHashes, true)) // refuse a replaced recon tool binary (TOFU)
		// Egress enforcement: enable ONLY when the applier actually works here – it
		// needs CAP_NET_ADMIN + CAP_SYS_ADMIN, which an unprivileged API lacks. Probe and
		// degrade to network-isolated (still safe) rather than failing recon at runtime.
		if app, aerr := egressinfra.NewApplier(); aerr == nil {
			probeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			perr := app.Probe(probeCtx)
			cancel()
			if perr == nil {
				sb.SetEgress(app)
				sb.SetConnMonitor(ebpf.NewMonitor()) // per-run eBPF connect-log (best-effort)
				egressLive = true
				log.Info("recon sandbox enabled with KERNEL EGRESS enforcement (scope-restricted netns)")
			} else {
				log.Warn("sandbox egress not usable here (needs CAP_NET_ADMIN/SYS_ADMIN) – sandboxed recon runs network-ISOLATED; run capability-sensitive/live recon via synapse-worker", "err", perr)
			}
		} else {
			log.Warn("sandbox egress applier unavailable (no ip/iptables) – sandboxed recon runs network-isolated", "err", aerr)
		}
		if !sb.CgroupLimitsEnforced() {
			log.Warn("sandbox cgroup resource limits NOT enforced (no usable systemd-run --user)")
		}
	}
	reconService, err := reconuc.NewService(reconGuard, reconRunner,
		reconRunStore, evidenceService, repo, logBroker, reconPool, clock, ids, recontools.Registry(),
		cfg.ReconTimeout, cfg.ReconMaxOutput, cfg.ReconAllowCapabilitySensitive)
	if err != nil {
		log.Error("recon service init failed", "err", err)
		os.Exit(1)
	}
	if egressLive {
		// with kernel egress enforcement available, recon runs sandboxed-live –
		// capability-sensitive tools are permitted (contained) and each run carries a
		// scope-derived egress policy.
		reconService.SetSandboxEnforcement(egresspolicy.Compile)
	}
	var scaWorker *worker.Worker
	if cfg.ReconViaWorker {
		// defer execution to the durable queue. Recon goes to the privileged
		// synapse-worker (egress/capability needs CAP_NET_ADMIN). SCA is offline → an
		// IN-PROCESS worker here runs it (sandboxed, no privilege). Claim-by-kind keeps the
		// two from grabbing each other's jobs. Needs Postgres.
		if reconQueue != nil {
			reconService.SetQueue(reconQueue)
			scaService.SetQueue(reconQueue)
			reconService.SetRunLock(reconRunLock) // no duplicate live scan on redelivery
			scaService.SetRunLock(reconRunLock)
			scaWorker = worker.New(reconQueue, map[string]worker.Handler{
				scauc.ScanJobKind: scaJobHandler{svc: scaService}, // Handle + OnDeadLetter (finalize the ScanJob)
			}, worker.Config{Visibility: cfg.ScanTimeout + time.Minute, MaxAttempts: 3}, log)
			log.Info("execution deferred to the durable queue: recon → synapse-worker, SCA → in-process worker")
		} else {
			log.Warn("SYNAPSE_RECON_VIA_WORKER set but no Postgres queue (set SYNAPSE_DB_DSN) – running in-process")
		}
	}

	// Driving adapter.
	// Real operator identity: per-user API keys back attribution. The
	// env SYNAPSE_API_TOKEN seeds a bootstrap admin (id "operator") so existing
	// deployments keep authenticating and historical attribution stays valid.
	usersService, err := usersuc.NewService(userRepo, auditLog, clock, ids)
	if err != nil {
		log.Error("users service init failed", "err", err)
		os.Exit(1)
	}
	if err := usersService.EnsureBootstrapAdmin(context.Background(), cfg.APIToken); err != nil {
		log.Error("bootstrap admin seed failed", "err", err)
		os.Exit(1)
	}
	auth := httpapi.NewAuthenticator(func(ctx context.Context, token string) (httpapi.Principal, bool) {
		u, err := usersService.Authenticate(ctx, token)
		if err != nil {
			return httpapi.Principal{}, false
		}
		return httpapi.Principal{ID: u.ID.String(), Name: u.Name, Role: string(u.Role), TenantID: u.TenantID}, true
	})
	// Audit read/verify use case: same signer as evidence, so the audit head is
	// origin-attested at parity with the evidence chain.
	auditService, err := audituc.NewService(auditReader)
	if err != nil {
		log.Error("audit service init failed", "err", err)
		os.Exit(1)
	}
	auditService.SetSigner(auditSigner)
	auditService.SetTimestamper(tsaClient, timestampStore)
	auditService.SetLogger(log)
	// Credential vault management: write-only secrets, audited sans value.
	credentialsService, err := credentialsuc.NewService(credVault, auditLog, clock)
	if err != nil {
		log.Error("credentials service init failed", "err", err)
		os.Exit(1)
	}
	approvalSvc, err := approval.NewService(approvalStore, auditLog, clock, agent.ApprovalMode(cfg.AgentApprovalMode), cfg.AgentApprovalTimeout)
	if err != nil {
		log.Error("approval service init failed", "err", err)
		os.Exit(1)
	}
	safetyGate, err := safety.NewGate(reconGuard, approvalSvc, evidenceService)
	if err != nil {
		log.Error("safety gate init failed", "err", err)
		os.Exit(1)
	}
	router := httpapi.NewRouter(log, auth, engService, scaService, aupService, findingsService, exportService, reportService, evidenceService, reconService, logBroker, transferService, auditService, vexService, usersService, credentialsService)
	projectService.SetScanner(scaService)
	scaService.SetProjectAnalysisRecorder(projectService)
	scaService.SetProjectAnalysisCompletionTimeout(cfg.ProjectAnalysisCompletionTimeout)
	projectService.SetProjectAnalysisCompletionTimeout(cfg.ProjectAnalysisCompletionTimeout)
	scaService.SetLogger(log)
	sourceArtifacts := sourceartifact.New(cfg.ProjectSourceArtifactDir, cfg.ProjectSourceMaxFileBytes, cfg.ProjectSourceMaxFiles, cfg.ProjectSourceMaxBytes)
	projectService.SetSourceArtifactStore(sourceArtifacts)
	scaService.SetProjectSourceArtifactStore(sourceArtifacts)
	scaService.SetProjectComparisonSource(&gitdiff.ComparisonSource{})
	if cfg.ProjectSourceRetention > 0 {
		if err := sourceArtifacts.CleanupExpired(context.Background(), time.Now().Add(-cfg.ProjectSourceRetention)); err != nil {
			log.Warn("source artifact retention cleanup failed", "err", err)
		}
	}
	log.Info("immutable project source capture ENABLED", "retention", cfg.ProjectSourceRetention)
	router.SetProjects(projectService)
	router.SetQualityGates(qualityGateService)
	router.SetQualityProfiles(qualityProfileService)
	router.SetExploitation(exploitationService) // evidence-gated finding verify endpoint
	// Read-only code-quality dashboard. Server-side analysis is PURE-GO and memory-safe only (pattern
	// rules + duplication + Go-parser inventory); tree-sitter complexity is intentionally NOT wired here
	// so the server never runs C parsers over untrusted source (that stays a local-CLI capability).
	codeQualityService := codequality.New(
		codeanalysis.New(),
		codequality.WithDuplication(duplication.New(0)),
		codequality.WithInventory(codeinventory.New()),
	)
	scaService.SetCodeQuality(codeQualityService)
	if rulesSvc, rerr := rules.NewService(ruleCatalog); rerr != nil {
		log.Error("rules service init failed", "err", rerr)
		os.Exit(1)
	} else {
		router.SetRules(rulesSvc)
	}
	if tmSvc, terr := threatmodeluc.NewService(threatModelStore, auditLog, clock); terr != nil { // architecture threat-model ingest/read
		log.Error("threat-model service init failed", "err", terr)
		os.Exit(1)
	} else {
		router.SetThreatModel(tmSvc)
	}
	var judgmentSvc *analysisuc.Service // shared by the HTTP verify/accept routes + the agent propose tool
	if cfg.JudgmentsEnabled {           // AI judgment lifecycle (verify/accept/list); off by default
		svc, aerr := analysisuc.NewService(judgmentStore, evidenceService, auditLog, clock, ids)
		if aerr != nil {
			log.Error("analysis (judgment) service init failed", "err", aerr)
			os.Exit(1)
		}
		judgmentSvc = svc
		judgmentSvc.SetThreatRecorder(findingsService) // a ratified threat auto-emits a Kind=threat finding
		judgmentSvc.SetSASTRecorder(findingsService)   // a confirmed CapSAST (taint) judgment auto-emits a Kind=sast finding
		judgmentSvc.SetDASTRecorder(findingsService)   // a RUNTIME-confirmed CapSAST judgment auto-emits a Kind=dast finding (via VerifyRuntime)
		router.SetJudgments(judgmentSvc)
		// Automated LLM judgment-verifier: when SYNAPSE_VERIFIER_MODEL names a model DIFFERENT from the
		// agent's model, a distinct verifier independently scores each proposed gated judgment and seals a
		// verdict via the same gate a human uses (verifier identity "llm:<model>", never the proposer, so
		// it can never confirm its own claim). POST .../judgments/auto-verify triggers it. Best-effort.
		if cfg.VerifierModel != "" && cfg.VerifierModel != cfg.LLMModel {
			if vllm, verr := openai.New(cfg.LLMBaseURL, cfg.LLMAPIKey, cfg.VerifierModel, cfg.LLMTimeout); verr != nil {
				log.Warn("automated LLM judgment-verifier DISABLED (LLM unavailable)", "err", verr)
			} else {
				router.SetAutoVerifier(llmverifier.New(vllm, cfg.VerifierModel, judgmentSvc, judgmentStore))
				log.Info("automated LLM judgment-verifier ENABLED (distinct verifier seals verdicts)", "model", cfg.VerifierModel)
			}
		}
		if runtimeVerifierSvc, rerr := dastverifieruc.NewService(judgmentSvc); rerr != nil {
			log.Error("runtime verifier service init failed", "err", rerr)
			os.Exit(1)
		} else {
			router.SetRuntimeVerifier(runtimeVerifierSvc)
			if egressLive {
				// DAST actively probes a URL. Unlike typed runtime-verifier result ingestion,
				// the workflow must never run on the plain ExecRunner because ExecRunner ignores
				// ToolSpec.EgressPolicy. Serve the propose/approve/run routes only when the
				// sandbox can kernel-enforce egress confinement.
				dastRunnerSvc, derr := dastrunneruc.NewService(reconRunner, evidenceService, runtimeVerifierSvc, "curl", 10*time.Second, cfg.ReconMaxOutput)
				if derr != nil {
					log.Error("DAST safe verifier runner init failed", "err", derr)
					os.Exit(1)
				}
				dastWorkflowSvc, werr := dastworkflowuc.NewService(safetyGate, approvalSvc, approvalStore, dastRunnerSvc, clock, ids)
				if werr != nil {
					log.Error("DAST verifier workflow init failed", "err", werr)
					os.Exit(1)
				}
				router.SetDASTWorkflow(dastWorkflowSvc)
				log.Info("DAST verifier workflow ENABLED (sandbox egress-enforced)")
			} else {
				log.Warn("DAST verifier workflow DISABLED: sandbox kernel egress enforcement is unavailable")
			}
		}
		exportService.SetJudgments(judgmentStore) // OpenVEX justification-by-tier from confirmed not_reachable judgments
		reportService.SetJudgments(judgmentStore) // ACCEPTED risk-narrative + correlation → closed report tokens (LLM-free)
		log.Info("AI judgment lifecycle ENABLED (verify/accept/list)")
	}
	// AI-proposed, human-gated finding write-up drafts. The service is shared by the agent's
	// propose_writeup_draft tool (below) and, in a later increment, the human sign-off HTTP routes. Off by
	// default; opt-in. The store is always selected above (a harmless empty table until enabled).
	var writeupDraftSvc *writeupdraftuc.Service
	if cfg.WriteupDraftsEnabled {
		svc, derr := writeupdraftuc.NewService(writeupDraftStore, auditLog, clock, ids)
		if derr != nil {
			log.Error("writeup draft service init failed", "err", derr)
			os.Exit(1)
		}
		writeupDraftSvc = svc
		writeupDraftSvc.SetFindingWriteupApplier(findingsService) // on accept, apply the draft's prose to its finding (validated finding∈engagement + audited)
		router.SetWriteupDrafts(writeupDraftSvc)                  // human sign-off HTTP routes (list/edit/accept/reject; PermReview + SoD + withEngTenant)
		log.Info("writeup draft proposals ENABLED (agent proposes prose; a distinct human signs off)")
	}
	var assetSvc *assetuc.Service
	if cfg.FleetAssetsEnabled {
		svc, derr := assetuc.NewService(assetStore, auditLog, clock, ids)
		if derr != nil {
			log.Error("asset service init failed", "err", derr)
			os.Exit(1)
		}
		assetSvc = svc
		router.SetAssets(assetSvc)
		log.Info("fleet asset model ENABLED (multi-tenant, Postgres RLS-enforced)")

		// Fleet coverage + agent-health views (#413): a read projection over agents, work orders and
		// the asset model. Needs the fleet transport (agent + work-order stores); enabled when both the
		// asset model and the transport are on.
		if cfg.FleetEnabled {
			covSvc, cerr := coverageuc.NewService(fleetAgentStore, workOrderStore, assetStore, clock, cfg.FleetAgentStaleAfter, cfg.FleetCoverageFreshnessTarget)
			if cerr != nil {
				log.Error("fleet coverage service init failed", "err", cerr)
				os.Exit(1)
			}
			router.SetFleetCoverage(covSvc)
			log.Info("fleet coverage + agent-health views ENABLED (no default-to-clean; tenant-scoped)")
		}
	}
	// Third-party SARIF ingest (#415). External findings join the same asset model, prioritisation and
	// governance path as first-party ones, but stay structurally distinguishable and carry NO promotion
	// authority: an external tool's confidence is not a distinct verifier's sealed verdict.
	{
		sarifSvc, serr := sarifingest.NewService(importedFindingStore, findingRepo, repo, auditLog, clock, ids)
		if serr != nil {
			log.Error("sarif ingest init failed", "err", serr)
			os.Exit(1)
		}
		router.SetSARIFIngest(sarifSvc)
		router.SetImportedFindings(importedFindingStore)
		// The ingest writes an append-only audit entry asserting that N external results entered an
		// engagement. Without Postgres those rows live only in this process, so the banner says so
		// rather than letting the audit trail imply a durability the deployment does not have.
		if cfg.DBDSN != "" {
			log.Info("third-party SARIF ingest ENABLED (durable; provenance mandatory; imported findings cannot self-promote)")
		} else {
			log.Warn("third-party SARIF ingest ENABLED but NOT DURABLE - imported findings and their ingest history live in memory and are lost on restart; configure SYNAPSE_DB_DSN for a durable store")
		}
	}

	if cfg.FleetEnabled {
		// SECURITY: a missing/short signer key fails startup closed rather than boot a forgeable
		// work-order signer (worksign.New rejects keys under 32 bytes).
		signer, serr := worksign.New([]byte(cfg.FleetSignerKey))
		if serr != nil {
			log.Error("fleet enabled but the work-order signer key is missing or too short – set SYNAPSE_FLEET_SIGNER_KEY (>=32 bytes)", "err", serr)
			os.Exit(1)
		}
		agentSvc, aerr := fleetagentuc.NewService(fleetAgentStore, auditLog, clock, ids)
		if aerr != nil {
			log.Error("fleet agent service init failed", "err", aerr)
			os.Exit(1)
		}
		workSvc, werr := fleetwork.NewService(workOrderStore, signer, auditLog, clock, ids)
		if werr != nil {
			log.Error("fleet work service init failed", "err", werr)
			os.Exit(1)
		}
		// Revoking an agent cancels its in-flight work orders (#408).
		agentSvc.SetWorkOrders(workOrderStore)
		// Optional certificate identity (#408): when a control-plane CA is configured, enrolment
		// with a CSR issues a client certificate. Fail closed on a misconfigured CA.
		if cfg.FleetCACertPEM != "" && cfg.FleetCAKeyPEM != "" {
			ca, cerr := fleetca.New([]byte(cfg.FleetCACertPEM), []byte(cfg.FleetCAKeyPEM), cfg.FleetCertTTL)
			if cerr != nil {
				log.Error("fleet CA configured but invalid – check SYNAPSE_FLEET_CA_CERT/KEY", "err", cerr)
				os.Exit(1)
			}
			agentSvc.SetCA(ca)
			log.Info("fleet agent certificate identity ENABLED (CSR enrolment issues client certs)")
		}
		router.SetFleet(agentSvc, workSvc, clock.Now, cfg.FleetClientCertHeader)
		router.SetFleetAdmin(agentSvc)
		// Version skew (#412): refuse work below the configured minimum agent version and advertise the
		// control-plane version + floor to agents. Empty floor = disabled.
		router.SetFleetVersionPolicy(cfg.FleetMinAgentVersion, buildinfo.App())
		if cfg.FleetMinAgentVersion != "" {
			log.Info("fleet version skew ENABLED", "min_supported_agent_version", cfg.FleetMinAgentVersion)
		}
		log.Info("fleet agent transport ENABLED (agent-auth plane; operator agent-admin routes)")

		// Cluster snapshot ingest (#446): agents POST a collected cluster inventory which is persisted
		// into the asset model. Gated by its own flag AND requires the asset model (persistence target).
		if cfg.FleetClusterIngestEnabled {
			if assetSvc == nil {
				log.Error("SYNAPSE_FLEET_CLUSTER_INGEST_ENABLED requires the fleet asset model – set SYNAPSE_FLEET_ASSETS_ENABLED")
				os.Exit(1)
			}
			ciSvc, cierr := clusterinventoryuc.NewService(assetSvc, auditLog, clock)
			if cierr != nil {
				log.Error("cluster inventory ingest init failed", "err", cierr)
				os.Exit(1)
			}
			// Correlate running image digests with prior scans (#446): an unscanned running digest is a
			// coverage gap rather than every digest reported unscanned.
			ciSvc.SetScannedImages(scannedImageStore)
			router.SetFleetClusterInventory(ciSvc)
			log.Info("fleet cluster inventory ingest ENABLED (agents persist snapshots into the asset model)")
		}

		// VM host snapshot ingest (#446): agents POST a collected host inventory persisted as a
		// Kind=host asset. Gated by its own flag AND requires the asset model.
		if cfg.FleetHostIngestEnabled {
			if assetSvc == nil {
				log.Error("SYNAPSE_FLEET_HOST_INGEST_ENABLED requires the fleet asset model – set SYNAPSE_FLEET_ASSETS_ENABLED")
				os.Exit(1)
			}
			hiSvc, hierr := hostinventoryuc.NewService(assetSvc, auditLog, clock)
			if hierr != nil {
				log.Error("host inventory ingest init failed", "err", hierr)
				os.Exit(1)
			}
			router.SetFleetHostInventory(hiSvc)
			log.Info("fleet host inventory ingest ENABLED (VM agents persist host inventories into the asset model)")
		}
	}
	// deterministic Tier-2 reachability proof in the scan pipeline (opt-in). It mints reachability
	// judgments, so it requires the judgment lifecycle. The govulncheck builder shares the SCA sandbox when
	// enabled (so it never runs unsandboxed in production); a no-coverage/un-buildable target is best-effort
	// (the prior tier stands). Injected here at the composition root only – never on an agent-reachable
	// surface (the reachproof architecture tripwire enforces it).
	if cfg.ReachabilityEnabled && requireJudgmentsOrSkip(log, judgmentSvc != nil, "SYNAPSE_REACHABILITY_ENABLED", "reachability") {
		gvBuilder := govulncheck.New(cfg.GovulncheckBin)
		if scaSandbox != nil {
			gvBuilder = gvBuilder.WithRunner(scaSandbox) // same containment as syft/grype; required in production
		} else {
			// dev only (prod forces the sandbox above): govulncheck SOURCE-mode does a real build of the
			// target unsandboxed – make that posture explicit rather than silent.
			log.Warn("reachability: govulncheck runs UNSANDBOXED (sandbox off; dev only) – it builds the target")
		}
		reachSvc, rerr := reachability.NewService(gvBuilder)
		if rerr != nil {
			log.Error("reachability service init failed", "err", rerr)
			os.Exit(1)
		}
		coord, cerr := reachproof.NewCoordinator(reachSvc, judgmentSvc, auditLog, clock)
		if cerr != nil {
			log.Error("reachability coordinator init failed", "err", cerr)
			os.Exit(1)
		}
		scaService.SetReachability(coord)
		log.Info("Tier-2 reachability proof ENABLED (govulncheck call-graph; best-effort, deterministic overrides LLM Tier-1.5)")
	}

	// Deterministic Tier-1 Python import-reachability, opt-in. A SOURCE-ONLY scanner (no compile/execute, so
	// in-process like the lockfile parsers) determines which declared PyPI packages first-party code imports;
	// a dead dependency becomes a not_reachable judgment → an OpenVEX not_affected justification. Requires the
	// judgment lifecycle. Never on an agent-reachable surface (composition-root only).
	if cfg.PyReachabilityEnabled && requireJudgmentsOrSkip(log, judgmentSvc != nil, "SYNAPSE_PYREACH_ENABLED", "python reachability") {
		pyAnalyzer, perr := pyreach.New(pyimports.New())
		if perr != nil {
			log.Error("python reachability analyzer init failed", "err", perr)
			os.Exit(1)
		}
		pyCoord, cerr := reachproof.NewCoordinatorForTier(pyAnalyzer, judgmentSvc, auditLog, clock, judgment.Tier1)
		if cerr != nil {
			log.Error("python reachability coordinator init failed", "err", cerr)
			os.Exit(1)
		}
		scaService.SetPyReachability(pyCoord)
		log.Info("Tier-1 Python import-reachability ENABLED (source-only dead-dependency detection → OpenVEX not_affected; best-effort)")
	}

	// Deterministic Tier-1 JavaScript/TypeScript import-reachability, opt-in. Source-only like the Python
	// path (the scanner only lexes text, so it needs no sandbox), and it answers only for DIRECT
	// dependencies: a first-party import graph cannot prove a TRANSITIVE package unused, because that
	// package is loaded by its parent. Requires the judgment lifecycle. Composition-root only.
	if cfg.JSReachabilityEnabled && requireJudgmentsOrSkip(log, judgmentSvc != nil, "SYNAPSE_JSREACH_ENABLED", "javascript reachability") {
		// One scanner and one resolver serve both tiers: they are stateless, and a second pair would
		// mean a second full lex of the source tree per scan.
		jsScanner, jsResolver := jsimports.New(), jsresolve.NewResolver()
		jsRecorder, jerr := jsreach.NewRecorder(jsScanner, jsResolver, judgmentSvc, auditLog, clock)
		if jerr != nil {
			log.Error("javascript reachability recorder init failed", "err", jerr)
			os.Exit(1)
		}
		scaService.SetJSReachability(jsRecorder)
		log.Info("Tier-1 JavaScript import-reachability ENABLED (source-only, direct dependencies only → OpenVEX not_affected; best-effort)")

		// Tier-2 rides on Tier-1. Every safety statement it makes ends "…leaves the Tier-1 judgment
		// standing", so enabling it alone would leave nothing standing; the dependency is enforced here
		// rather than documented.
		if cfg.JSSymbolReachabilityEnabled {
			jsSymbolRecorder, serr := jsreach.NewSymbolRecorder(jsScanner, jsResolver, judgmentSvc, auditLog, clock)
			if serr != nil {
				log.Error("javascript tier-2 reachability init failed", "err", serr)
				os.Exit(1)
			}
			scaService.SetJSSymbolReachability(jsSymbolRecorder)
			log.Info("javascript TIER-2 affected-export reachability ENABLED (a binding that escapes observation yields no conclusion, never not-reachable)")
		}
	} else if cfg.JSSymbolReachabilityEnabled {
		log.Warn("SYNAPSE_JSREACH_TIER2_ENABLED is set but tier-1 javascript reachability is off - tier-2 is SKIPPED, because a tier-2 refusal is only safe when a tier-1 judgment can stand in its place")
	}

	// Deterministic Tier-1 import-reachability for Rust, PHP and Ruby. Each scanner is SOURCE-ONLY: it
	// lexes text and never runs cargo, composer, bundler or a language runtime, so no sandbox is needed
	// and no dependency is resolved over the network. Each refuses a verdict whenever a dynamic
	// construct (a Rust macro, a PHP variable class name, Ruby metaprogramming) could hide a reference.
	// Composition-root only.
	for _, lang := range []struct {
		enabled  bool
		env      string
		label    string
		purlType string
		scanner  ports.SourceImportScanner
		named    srcreach.CandidateNamer
		language reachproof.Language
	}{
		{cfg.RustReachabilityEnabled, "SYNAPSE_REACH_RUST", "rust reachability", "cargo", srcimports.NewRustScanner(), srcimports.RustCandidates, reachproof.LanguageRust},
		{cfg.PHPReachabilityEnabled, "SYNAPSE_REACH_PHP", "php reachability", "composer", srcimports.NewPHPScanner(), srcimports.PHPCandidates, reachproof.LanguagePHP},
		{cfg.RubyReachabilityEnabled, "SYNAPSE_REACH_RUBY", "ruby reachability", "gem", srcimports.NewRubyScanner(), srcimports.RubyCandidates, reachproof.LanguageRuby},
	} {
		if !lang.enabled || !requireJudgmentsOrSkip(log, judgmentSvc != nil, lang.env, lang.label) {
			continue
		}
		purlType := lang.purlType
		reader := func(ctx context.Context, dir string) (map[string]bool, bool) {
			return srcimports.DirectDependencies(ctx, dir, purlType)
		}
		analyzer, aerr := srcreach.New(lang.scanner, lang.named, reader)
		if aerr != nil {
			log.Error(lang.label+" analyzer init failed", "err", aerr)
			os.Exit(1)
		}
		coord, cerr := reachproof.NewCoordinatorForLanguage(analyzer, judgmentSvc, auditLog, clock, judgment.Tier1, lang.language)
		if cerr != nil {
			log.Error(lang.label+" coordinator init failed", "err", cerr)
			os.Exit(1)
		}
		scaService.SetSourceReachability(lang.purlType, coord)
		log.Info("Tier-1 " + lang.label + " ENABLED (source-only dead-dependency detection → OpenVEX not_affected; best-effort)")
	}

	// Deterministic taint-analysis CapSAST proposals, opt-in. Builds the workspace call
	// graph via the sandboxed synapse-callgraph binary, assembles the taint FlowGraph over the injection
	// catalog, and PROPOSES gated CapSAST judgments (propose-only – a distinct verifier gates them).
	// Composition-root only (the taintscan arch tripwire keeps it off the agent surface). Requires the
	// sandbox: synapse-callgraph compiles the GENERAL target source, so there is NO safe unsandboxed dev
	// fallback (contrast govulncheck's vuln-scan) – refuse rather than build untrusted code on the host.
	if cfg.TaintEnabled {
		if judgmentSvc == nil {
			log.Error("SYNAPSE_TAINT_ENABLED requires SYNAPSE_JUDGMENTS_ENABLED (taint mints judgments)")
			os.Exit(1)
		}
		if scaSandbox == nil {
			log.Error("SYNAPSE_TAINT_ENABLED requires the SCA sandbox (it compiles untrusted target source); enable the sandbox or disable taint")
			os.Exit(1)
		}
		taintBuilder := taintcallgraph.New(cfg.TaintCallgraphBin).WithRunner(scaSandbox)
		taintCoord, terr := taintscan.NewCoordinator(taintBuilder, judgmentSvc, taint.DefaultCatalog(), auditLog, clock)
		if terr != nil {
			log.Error("taint coordinator init failed", "err", terr)
			os.Exit(1)
		}
		scaService.SetTaint(taintCoord)
		log.Info("taint-analysis CapSAST proposals ENABLED (sandboxed call-graph; propose-only, a distinct verifier gates)")
	}

	// Cross-check disagreement judgments, opt-in. Like reachability it mints judgments, so it needs
	// the judgment lifecycle. The coordinator proposes ungated CapCorrelation judgments (system identity) for
	// human review where the run detection sources disagree; composition-root only (the crosscheckjudge arch
	// tripwire keeps it off the agent surface). Best-effort: a recorder error never fails the scan.
	if cfg.CrossCheckEnabled && requireJudgmentsOrSkip(log, judgmentSvc != nil, "SYNAPSE_CROSSCHECK_ENABLED", "cross-check") {
		ccCoord, ccErr := crosscheckjudge.NewCoordinator(judgmentSvc, auditLog, clock)
		if ccErr != nil {
			log.Error("cross-check coordinator init failed", "err", ccErr)
			os.Exit(1)
		}
		scaService.SetCorrelation(ccCoord)
		log.Info("cross-check disagreement judgments ENABLED (owned vs vendor detection sources; ungated, human-reviewed)")
	}

	// SBOM producer cross-check (SBOM side), opt-in. A SECOND SBOM producer runs alongside
	// the primary and components only one producer emits become ungated CapCorrelation judgments (system
	// identity) for human review – detection independence as a feature. Like the advisory cross-check it mints
	// judgments, so it needs the judgment lifecycle; composition-root only (the sbomcrosscheckjudge arch
	// tripwire keeps it off the agent surface). Best-effort: a 2nd-producer error never fails the scan.
	if cfg.SBOMCrossCheckEnabled && requireJudgmentsOrSkip(log, judgmentSvc != nil, "SYNAPSE_SBOM_CROSSCHECK_ENABLED", "SBOM cross-check") {
		// The cross-check producer is whichever Tier-1 producer is NOT the primary, so two INDEPENDENT
		// producers (owned parsers vs Syft) are diffed. Build the owned registry on demand when Syft is primary.
		var secondary ports.SBOMGenerator
		var secondaryName string
		switch cfg.SBOMProducer {
		case "ownsbom":
			secondary, secondaryName = syftGen, "syft"
		default: // "" or "syft" (the producer-select switch above already rejected any other value)
			reg, rerr := ownsbom.DefaultRegistry()
			if rerr != nil {
				log.Error("build ownsbom cross-check producer", "err", rerr)
				os.Exit(1)
			}
			secondary, secondaryName = reg, "ownsbom"
		}
		sbomccCoord, sbomccErr := sbomcrosscheckjudge.NewCoordinator(judgmentSvc, auditLog, clock)
		if sbomccErr != nil {
			log.Error("sbom cross-check coordinator init failed", "err", sbomccErr)
			os.Exit(1)
		}
		scaService.SetSBOMCrossCheck(secondary, sbomccCoord)
		log.Info("SBOM producer cross-check ENABLED (component disagreements → ungated judgments, human-reviewed)", "secondary", secondaryName)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go approvalSvc.RunSweeper(ctx, cfg.ApprovalSweepInterval) // fail-closed HITL approval timeouts for agent + DAST

	// AI agent orchestration. Off unless SYNAPSE_AGENT_ENABLED.
	if cfg.AgentEnabled {
		if cfg.LLMModel == "" {
			log.Error("SYNAPSE_AGENT_ENABLED requires SYNAPSE_LLM_MODEL (and a reachable SYNAPSE_LLM_BASE_URL)")
			os.Exit(1)
		}
		llm, lerr := openai.New(cfg.LLMBaseURL, cfg.LLMAPIKey, cfg.LLMModel, cfg.LLMTimeout)
		if lerr != nil {
			log.Error("llm client init failed", "err", lerr) // never logs the key
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
		// Enable the agent's tools through the SHARED toolset helper so the inline (here) and durable
		// (synapse-worker) catalogs advertise an IDENTICAL tool set — the durable/inline parity guarantee
		// (#161). Planning + findings + hypotheses + reachability are always on; judgments + writeup drafts
		// mirror their feature flags (assigned only when the concrete service is non-nil, to avoid a
		// non-nil interface wrapping a typed-nil pointer).
		toolset := agenttools.AgentToolset{
			Findings:     exploitationService, // record unproven findings (score 0)
			Hypotheses:   exploitationService, // propose attack-chain hypotheses (score 0; gated until human-verified)
			Reachability: scanResultStore,     // read dep-graph reachability facts (T0/T1)
		}
		if judgmentSvc != nil { // PROPOSE reachability/critique/… judgments (score 0); verify stays human-only (PermReview)
			toolset.Judgments = judgmentSvc
		}
		if writeupDraftSvc != nil { // PROPOSE finding write-up drafts (prose); edit/accept stays human-only
			toolset.WriteupDrafts = writeupDraftSvc
		}
		if terr := agentCatalog.EnableAgentToolset(toolset); terr != nil {
			log.Error("agent toolset wiring failed", "err", terr)
			os.Exit(1)
		}
		// The executor drives recon through the SAME dispatcher-backed recon service (in-process
		// pool), so the inline agent never starves a queue claim. A durable agent-on-worker would
		// need a dedicated dispatcher-backed recon service to avoid a poll/claim self-deadlock.
		agentExec, xerr := orchestrator.NewReconExecutor(reconService, evidenceService, clock, 500*time.Millisecond, cfg.ReconTimeout+time.Minute)
		if xerr != nil {
			log.Error("agent executor init failed", "err", xerr)
			os.Exit(1)
		}
		orch, oerr := orchestrator.New(llm, agentCatalog, safetyGate, agentExec, evidenceService, agentSessionStore, approvalStore, auditLog, clock, ids,
			orchestrator.Config{
				Model: cfg.LLMModel, ProviderBase: cfg.LLMBaseURL,
				MaxSteps: cfg.AgentMaxSteps, TokenBudget: cfg.AgentTokenBudget, MaxDuration: cfg.AgentMaxDuration, MaxParallel: cfg.AgentMaxParallel,
			})
		if oerr != nil {
			log.Error("orchestrator init failed", "err", oerr)
			os.Exit(1)
		}
		if agentRunLock != nil {
			orch.SetRunLock(agentRunLock) // advisory session lock – cannot expire mid-LLM-loop
		}
		orch.SetPlanStore(planStore)         // drive a proposed plan DAG (node-CAS idempotency)
		orch.SetDecisionStore(decisionStore) // structured decision-log projection
		// Durable dispatch when SYNAPSE_AGENT_VIA_WORKER (requires the recon worker + Postgres):
		// the API enqueues and synapse-worker drives + survives restart. Otherwise the API runs
		// the agent inline (bounded by AgentConcurrency; NOT durable – a crash strands the run).
		var agentQueue ports.JobQueue
		if cfg.AgentViaWorker {
			if !cfg.ReconViaWorker || reconQueue == nil {
				log.Error("SYNAPSE_AGENT_VIA_WORKER requires SYNAPSE_RECON_VIA_WORKER + Postgres (the durable queue)")
				os.Exit(1)
			}
			agentQueue = reconQueue
		}
		router.EnableAgent(orch, agentSessionStore, approvalSvc, approvalStore, agentQueue, cfg.AgentConcurrency, cfg.AgentQueueDepth)
		router.SetAgentDecisionStore(decisionStore) // GET …/decisions
		router.SetAgentPlanStore(planStore)         // GET …/plan
		router.SetAgentRunContext(ctx)              // inline runs cancel on shutdown
		if agentQueue != nil {
			log.Info("AI agent orchestration ENABLED (durable via synapse-worker)", "model", cfg.LLMModel, "approval_mode", cfg.AgentApprovalMode)
		} else {
			log.Info("AI agent orchestration ENABLED (inline, non-durable; bounded)", "model", cfg.LLMModel, "approval_mode", cfg.AgentApprovalMode, "concurrency", cfg.AgentConcurrency)
		}
	}

	if scaWorker != nil {
		go func() { _ = scaWorker.Run(ctx) }() // in-process SCA worker; drains on shutdown
		// Stale-scan sweeper: reclaim scan jobs a crash left `running` with no live
		// owner (stranded without a dead-letter event). Lease-as-liveness, parity with recon.
		go func() {
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
		}()
	}

	// Leader election (#406): run the fenced-lease elector so a future scheduler can gate periodic
	// dispatch on IsLeader when running more than one instance. Postgres only. The elector resigns
	// on shutdown so a follower takes over without waiting for the term. NOTE: this ships the
	// election mechanism; removing the single-instance lock and gating dispatch on IsLeader (true
	// horizontal scale) is the tracked follow-on.
	if cfg.LeaderElectionEnabled && leaderStore == nil {
		log.Warn("leader election enabled but ignored: it requires Postgres (a single in-memory process is trivially the leader)")
	}
	if cfg.LeaderElectionEnabled && leaderStore != nil {
		elector, eerr := leaderuc.NewElector(leaderStore, auditLog, clock, cfg.LeaderResource, ids.NewID().String(), cfg.LeaderTerm, cfg.LeaderRenew)
		if eerr != nil {
			log.Error("leader election enabled but misconfigured (require 0 < renew < term/2)", "err", eerr)
			os.Exit(1)
		}
		go elector.Run(ctx)
		log.Info("leader election ENABLED", "resource", cfg.LeaderResource, "term", cfg.LeaderTerm, "renew", cfg.LeaderRenew)
	}

	if err := httpserver.Run(ctx, cfg.HTTPAddr, router.Handler(), log); err != nil {
		log.Error("server error", "err", err)
		os.Exit(1)
	}
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
