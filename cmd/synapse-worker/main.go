// Command synapse-worker is the privileged execution worker: it
// claims recon jobs the API enqueued to the durable queue and runs them under the SAME
// gate/audit/evidence invariants as the in-process path, but with the sandbox + kernel
// egress allowlist (it runs with CAP_NET_ADMIN/SYS_ADMIN, which the API lacks). It is a
// composition root only – no business logic. It coexists with the API via a role-scoped
// single-instance lock, and the evidence chain is multi-writer-safe.
package main

import (
	"context"
	"crypto/rand"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/ebpf"
	egressinfra "github.com/KKloudTarus/synapse-ce/internal/infrastructure/egress"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/llm/openai"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/logstream"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	recontools "github.com/KKloudTarus/synapse-ce/internal/infrastructure/recon"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/signing"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/timestamp"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/binregistry"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/platform/jobs"
	"github.com/KKloudTarus/synapse-ce/internal/platform/logging"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/agenttools"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	egresspolicy "github.com/KKloudTarus/synapse-ce/internal/usecase/egress"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	exploitationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/exploitation"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	reconuc "github.com/KKloudTarus/synapse-ce/internal/usecase/recon"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/worker"
)

func main() {
	cfg := config.Load()
	log := logging.New(cfg.LogLevel)
	log.Info("starting synapse-worker", "env", cfg.Environment)

	// The worker shares the API's Postgres (the queue + the recon/evidence repos), so a DSN
	// is required – an in-memory queue is not shared across processes.
	if cfg.DBDSN == "" {
		log.Error("synapse-worker requires SYNAPSE_DB_DSN (the durable queue + repos shared with the API)")
		os.Exit(1)
	}
	clock := idgen.SystemClock{}
	ids := idgen.RandomID{}

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
	// Role-scoped single-instance lock: one worker, coexisting with one API.
	lockConn, ok, lerr := postgres.AcquireSingletonLock(startup, pool, "worker")
	if lerr != nil {
		log.Error("worker single-instance lock check failed", "err", lerr)
		os.Exit(1)
	}
	if !ok {
		log.Error("another synapse-worker holds the single-instance lock – run ONE worker")
		os.Exit(1)
	}
	defer lockConn.Release()

	// Repos shared with the API.
	repo := postgres.NewEngagementRepository(pool)
	reconRunStore := postgres.NewReconRunStore(pool)
	evidenceStore := postgres.NewEvidenceStore(pool)
	auditLog := postgres.NewAuditLog(pool)
	queue := postgres.NewJobQueue(pool, ids)

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

	// The sandbox is REQUIRED here – the worker exists to run recon contained.
	sb, serr := sandbox.NewRunner(cfg.ReconTimeout, cfg.ReconMaxOutput, cfg.SandboxMemMax, cfg.SandboxPidsMax)
	if serr != nil {
		log.Error("synapse-worker requires the sandbox (bubblewrap) – install it", "err", serr)
		os.Exit(1)
	}
	sb.SetVault(credVault)
	sb.SetBinaryRegistry(binregistry.New(cfg.ToolHashes, true)) // F5: refuse a replaced tool binary (TOFU)
	egressLive := false
	if app, aerr := egressinfra.NewApplier(); aerr == nil {
		probeCtx, pcancel := context.WithTimeout(context.Background(), 10*time.Second)
		perr := app.Probe(probeCtx)
		pcancel()
		if perr == nil {
			sb.SetEgress(app)
			sb.SetConnMonitor(ebpf.NewMonitor()) // per-run eBPF connect-log (best-effort)
			egressLive = true
			log.Info("worker: kernel egress enforcement enabled")
		} else {
			log.Warn("worker has no usable egress (needs CAP_NET_ADMIN/SYS_ADMIN) – recon will be network-isolated", "err", perr)
		}
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
	reconService.SetRunLock(postgres.NewLeaseRunLock(pool, ids.NewID().String(), cfg.ReconTimeout+time.Minute)) // row-lease: no pinned conn

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	handlers := map[string]worker.Handler{
		reconuc.JobKind: reconJobHandler{svc: reconService}, // Handle + OnDeadLetter (finalize the run)
	}
	visibility := cfg.ReconTimeout + time.Minute

	// durable agent runs. Register the agent handler with a DEDICATED
	// dispatcher-backed recon service (its own pool, NO SetQueue) – so the agent executor's
	// blocking recon poll never starves THIS worker's recon-claim loop (the self-deadlock the
	// design flags). The agent session lock is the connection-holding advisory RunLock (it must
	// not expire mid-LLM-loop); recon uses the row-lease lock above.
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
		agentCatalog.EnablePlanning() // advertise + dispatch propose_plan (paired with SetPlanStore below)
		if exploitSvc, eerr := exploitationuc.NewService(findingRepo, evidenceService, auditLog, clock, ids); eerr == nil {
			agentCatalog.EnableFindingProposals(exploitSvc) // durable agent can record unproven findings (score 0)
		} else {
			log.Error("exploitation service init failed", "err", eerr)
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
			p, err := orchestrator.ResumeJob(sid, aid)
			if err != nil {
				return err
			}
			_, err = queue.Enqueue(ctx, orchestrator.JobKind, p)
			return err
		})
		go reconciler.Run(ctx, 5*time.Minute)
		go approvalSvc.RunSweeper(ctx, cfg.ApprovalSweepInterval)
		if cfg.AgentMaxDuration+time.Minute > visibility {
			visibility = cfg.AgentMaxDuration + time.Minute
		}
		log.Info("AI agent worker handler ENABLED (durable)", "model", cfg.LLMModel)
	}

	// Stale-run sweeper: reclaim recon runs a crash left `running` with no live owner
	// – i.e. stranded WITHOUT a dead-letter event (the dead-letter hook covers only jobs that
	// dead-letter). Lease-as-liveness: an acquirable lease means no live owner. Immediate pass,
	// then every 5m, until shutdown.
	go func() {
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
	}()

	w := worker.New(queue, handlers, worker.Config{Visibility: visibility, MaxAttempts: 3}, log)
	if err := w.Run(ctx); err != nil && ctx.Err() == nil {
		log.Error("worker exited with error", "err", err)
		os.Exit(1)
	}
	log.Info("synapse-worker stopped")
}

// mustVaultCipher builds the vault cipher from the master key (ephemeral in dev), exiting
// on failure. Mirrors the API so secrets sealed by one resolve in the other – INCLUDING the
// production fail-closed guard: without a configured key the worker would seal/resolve under a
// per-process ephemeral key that diverges from the API's, so every credentialed recon run
// breaks. Fail closed in production rather than fail open to an ephemeral key.
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
type agentJobHandler struct{ orch *orchestrator.Orchestrator }

func (h agentJobHandler) Handle(ctx context.Context, job ports.QueuedJob) error {
	return h.orch.RunJob(ctx, job.Payload)
}

func (h agentJobHandler) OnDeadLetter(ctx context.Context, job ports.QueuedJob, cause error) error {
	return h.orch.FailStrandedJob(ctx, job.Payload, cause)
}
