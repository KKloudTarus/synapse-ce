package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/observability"
	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/accuracyprobe"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/logstream"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	recontools "github.com/KKloudTarus/synapse-ce/internal/infrastructure/recon"
	elastic "github.com/KKloudTarus/synapse-ce/internal/infrastructure/siem/elastic"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/siem/ocsf"
	siemseal "github.com/KKloudTarus/synapse-ce/internal/infrastructure/siem/seal"
	sentinel "github.com/KKloudTarus/synapse-ce/internal/infrastructure/siem/sentinel"
	splunk "github.com/KKloudTarus/synapse-ce/internal/infrastructure/siem/splunk"
	syslogtls "github.com/KKloudTarus/synapse-ce/internal/infrastructure/siem/syslog"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/platform/executionmode"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/accuracyeval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	reconuc "github.com/KKloudTarus/synapse-ce/internal/usecase/recon"
	siemuc "github.com/KKloudTarus/synapse-ce/internal/usecase/siem"
)

// The control singletons that both the `all` and the `control` profile run (#1559). Each builder needs
// only the database, the vault and the queue, so the control role composes them without a sandbox.

// accuracyEvalTask returns the detection-accuracy regression singleton (EPIC #860 D8.6), or nil when it is
// off. It needs leader election: without it every replica would persist a duplicate trend row.
func accuracyEvalTask(cfg config.Config, pool *pgxpool.Pool, clock ports.Clock, ids ports.IDGenerator, log *slog.Logger) func(context.Context) {
	if cfg.AccuracyEvalInterval <= 0 {
		return nil
	}
	if !cfg.LeaderElectionEnabled {
		log.Warn("accuracy regression job requires SYNAPSE_LEADER_ENABLED=true (else replicas write duplicate trend rows); skipping", "interval", cfg.AccuracyEvalInterval)
		return nil
	}
	accuracyStore := postgres.NewAccuracyRunRepository(pool)
	probe := accuracyprobe.New()
	interval := cfg.AccuracyEvalInterval
	log.Info("accuracy regression job ENABLED", "interval", interval)
	return func(taskCtx context.Context) {
		runOnce := func() {
			report, err := accuracyeval.Evaluate(taskCtx, probe)
			if err != nil {
				if taskCtx.Err() == nil {
					log.Warn("accuracy eval failed", "err", err)
				}
				return
			}
			run, err := accuracyeval.ToRun(ids.NewID().String(), clock.Now().UTC(), report)
			if err != nil {
				log.Warn("accuracy run map failed", "err", err)
				return
			}
			if err := accuracyStore.Save(taskCtx, run); err != nil {
				if taskCtx.Err() == nil {
					log.Warn("accuracy run save failed", "err", err)
				}
				return
			}
			log.Info("accuracy run persisted", "cases", run.Cases, "precision", run.Overall.Precision, "recall", run.Overall.Recall, "fp", run.Overall.FalsePositives)
		}
		runOnce() // seed a fresh point at startup rather than waiting a full interval
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-taskCtx.Done():
				return
			case <-ticker.C:
				runOnce()
			}
		}
	}
}

// newAgentApprovalService builds the approval service the agent gate and the approval sweeper share: its
// decisions commit with their audit record, it notifies when notifications are on, and a timed-out
// approval re-enqueues the suspended session.
func newAgentApprovalService(cfg config.Config, pool *pgxpool.Pool, queue ports.JobQueue, sessions ports.AgentSessionStore, auditLog ports.AuditLogger, clock ports.Clock) (*approval.Service, error) {
	approvalSvc, err := approval.NewService(postgres.NewApprovalStore(pool), auditLog, clock, agent.ApprovalMode(cfg.AgentApprovalMode), cfg.AgentApprovalTimeout)
	if err != nil {
		return nil, err
	}
	// A human's approve or deny and its audit record commit together, so an operator is never told the
	// decision failed while the agent acts on it.
	approvalSvc.SetTransactionRunner(postgres.NewTenantTransactionRunner(pool))
	if cfg.NotificationEnabled {
		facts := postgres.NewNotificationLifecycleFactsReader(pool)
		if err := approvalSvc.SetNotifications(postgres.NewTenantTransactionRunner(pool), postgres.NewNotificationOutbox(pool), facts, facts); err != nil {
			return nil, err
		}
	}
	approvalSvc.SetResumeEnqueuer(func(ctx context.Context, sid, aid shared.ID) error {
		sess, err := sessions.GetSession(ctx, sid)
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
	return approvalSvc, nil
}

// agentRecoveryTasks returns the two agent singletons the control role owns: the reconciler that
// re-drives sessions stranded by a crashed execution replica, and the approval-timeout sweeper. Neither
// needs the LLM client or the sandbox; they read sessions and approvals and enqueue resume jobs.
func agentRecoveryTasks(cfg config.Config, pool *pgxpool.Pool, queue ports.JobQueue, auditLog ports.AuditLogger, clock ports.Clock, log *slog.Logger) (reconcile, sweep func(context.Context), err error) {
	sessions := postgres.NewAgentSessionStore(pool)
	approvalSvc, err := newAgentApprovalService(cfg, pool, queue, sessions, auditLog, clock)
	if err != nil {
		return nil, nil, err
	}
	reconciler, err := orchestrator.NewReconciler(sessions, queue, clock, cfg.AgentMaxDuration+5*time.Minute, log)
	if err != nil {
		return nil, nil, err
	}
	return func(ctx context.Context) { reconciler.Run(ctx, 5*time.Minute) },
		func(ctx context.Context) { approvalSvc.RunSweeper(ctx, cfg.ApprovalSweepInterval) },
		nil
}

// startSIEMExport starts the SIEM export loop when SIEM is enabled. Leases, not leader election, decide
// which replica commits a partition. Its counters share registry when one is given; otherwise, with
// metrics on, it opens the worker /metrics listener itself. The returned function closes that listener.
func startSIEMExport(ctx context.Context, stop context.CancelFunc, cfg config.Config, pool *pgxpool.Pool, vaultCipher *vault.Cipher, auditLog ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator, registry *prometheus.Registry, log *slog.Logger) (func(), error) {
	closeMetrics := func() {}
	if !cfg.SIEMEnabled {
		return closeMetrics, nil
	}
	if cfg.MetricsEnabled && registry == nil {
		registry = prometheus.NewRegistry()
		server, err := startWorkerMetrics(ctx, stop, cfg.MetricsAddr, registry, log)
		if err != nil {
			return closeMetrics, err
		}
		closeMetrics = server.close
		log.Info("private worker metrics enabled", "addr", server.address)
	}
	// topology: id=loop:siem-tick
	go func() {
		repository := postgres.NewSIEMRepository(pool)
		schema, schemaErr := ocsf.New()
		if schemaErr != nil {
			log.Error("siem schema init failed", "err", schemaErr)
			return
		}
		service, serviceErr := siemuc.NewService(repository, repository, repository, siemseal.Vault{Cipher: vaultCipher}, map[siem.Provider]ports.SIEMDriver{
			siem.ProviderSplunk:            splunk.New(5*time.Second, true),
			siem.ProviderElasticsearch:     elastic.New(5 * time.Second),
			siem.ProviderMicrosoftSentinel: sentinel.New(5 * time.Second),
			siem.ProviderSyslogTLS:         syslogtls.New(5 * time.Second),
		}, auditLog, clock, ids, schema)
		if serviceErr != nil {
			log.Error("siem worker init failed", "err", serviceErr)
			return
		}
		if err := service.SetPublicBase(cfg.SIEMPublicBaseURL); err != nil {
			log.Error("siem public base URL is invalid", "err", err)
			return
		}
		if cfg.MetricsEnabled {
			service.SetMetrics(observability.NewSIEMMetrics(registry))
		}
		workerID := "siem-" + ids.NewID().String()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			stats, tickErr := service.Tick(ctx, workerID, siemuc.TickBudget{MaxPartitions: 8, Deadline: clock.Now().Add(5 * time.Second)})
			if tickErr != nil && ctx.Err() == nil {
				log.Warn("siem tick failed", "err", tickErr)
			} else if stats.Sent > 0 || stats.Blocked > 0 {
				log.Info("siem tick", "sent", stats.Sent, "blocked", stats.Blocked)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return closeMetrics, nil
}

// staleSweepTask re-runs a stale-work sweep every five minutes. Leases, not this loop, decide which run is
// stranded; the loop only needs to run on one replica, so it is a leader-held singleton.
func staleSweepTask(name string, staleFor time.Duration, sweep func(context.Context, time.Duration) (int, error), log *slog.Logger) func(context.Context) {
	return func(ctx context.Context) {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			if n, err := sweep(ctx, staleFor); err != nil && ctx.Err() == nil {
				log.Warn(name+" sweep failed", "err", err)
			} else if n > 0 {
				log.Info(name+" sweeper reclaimed stranded work", "count", n)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}
}

// dispatchOnlyReconSweeper builds the recon service the control role needs only to reclaim stranded runs.
// Its runner and dispatcher are dispatch-only, so it can finish a run as failed and never execute one.
func dispatchOnlyReconSweeper(cfg config.Config, pool *pgxpool.Pool, repo ports.EngagementRepository, ev *evidenceuc.Service, auditLog ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*reconuc.Service, error) {
	guard, err := execution.NewGuard(repo, clock, auditLog)
	if err != nil {
		return nil, err
	}
	dispatchOnly := executionmode.DispatchOnly{}
	service, err := reconuc.NewService(guard, dispatchOnly, postgres.NewReconRunStore(pool), ev, repo, logstream.NewBroker(0), dispatchOnly, clock, ids,
		recontools.Registry(), cfg.ReconTimeout, cfg.ReconMaxOutput, cfg.ReconAllowCapabilitySensitive)
	if err != nil {
		return nil, err
	}
	service.SetRunLock(postgres.NewLeaseRunLock(pool, ids.NewID().String(), cfg.ReconTimeout+time.Minute))
	return service, nil
}
