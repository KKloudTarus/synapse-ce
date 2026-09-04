package integrations

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type Leadership interface {
	IsLeader() bool
}

type AlwaysLeader struct{}

func (AlwaysLeader) IsLeader() bool { return true }

type SchedulerConfig struct {
	Interval      time.Duration
	DispatchLimit int
	MaxQueueDepth int
}

type Scheduler struct {
	store      ports.IntegrationStore
	tenants    ports.VulnerabilityReconciliationTenantStore
	queue      ports.JobQueue
	service    *Service
	clock      ports.Clock
	leadership Leadership
	config     SchedulerConfig
	log        *slog.Logger
}

func NewScheduler(store ports.IntegrationStore, tenants ports.VulnerabilityReconciliationTenantStore, queue ports.JobQueue, service *Service, clock ports.Clock, leadership Leadership, config SchedulerConfig, log *slog.Logger) (*Scheduler, error) {
	if store == nil || tenants == nil || queue == nil || service == nil || clock == nil || leadership == nil || config.Interval <= 0 || config.DispatchLimit <= 0 || config.MaxQueueDepth <= 0 {
		return nil, fmt.Errorf("%w: integration scheduler configuration is invalid", shared.ErrValidation)
	}
	if log == nil {
		log = slog.Default()
	}
	return &Scheduler{store: store, tenants: tenants, queue: queue, service: service, clock: clock, leadership: leadership, config: config, log: log}, nil
}

func (scheduler *Scheduler) Run(ctx context.Context) {
	scheduler.tick(ctx)
	ticker := time.NewTicker(scheduler.config.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scheduler.tick(ctx)
		}
	}
}

func (scheduler *Scheduler) tick(ctx context.Context) {
	dispatched, err := scheduler.Tick(ctx)
	if err != nil {
		scheduler.log.Error("integration scheduler tick failed", "dispatched", dispatched, "err", err)
	} else if dispatched > 0 {
		scheduler.log.Info("integration scheduler tick completed", "dispatched", dispatched)
	}
}

func (scheduler *Scheduler) Tick(ctx context.Context) (int, error) {
	if !scheduler.leadership.IsLeader() {
		return 0, nil
	}
	tenantIDs, err := scheduler.tenants.ListTenantIDs(ctx)
	if err != nil {
		return 0, err
	}
	dispatched := 0
	for _, tenantID := range tenantIDs {
		if dispatched >= scheduler.config.DispatchLimit || !scheduler.leadership.IsLeader() {
			break
		}
		tenantID = shared.TenantOrDefault(tenantID)
		tenantCtx := shared.WithTenant(ctx, tenantID)
		depth, err := scheduler.queue.Depth(tenantCtx, JobKind)
		if err != nil {
			return dispatched, err
		}
		if depth >= scheduler.config.MaxQueueDepth {
			continue
		}
		due, err := scheduler.store.ListDueIntegrations(tenantCtx, scheduler.clock.Now().UTC(), scheduler.config.DispatchLimit-dispatched)
		if err != nil {
			return dispatched, err
		}
		for _, item := range due {
			if depth >= scheduler.config.MaxQueueDepth || dispatched >= scheduler.config.DispatchLimit || !scheduler.leadership.IsLeader() {
				break
			}
			if _, err := scheduler.service.StartOperation(tenantCtx, tenantID, item.ID, integration.OperationPoll, "system:integration-scheduler"); err != nil {
				scheduler.log.Warn("integration poll dispatch skipped", "provider", item.Provider, "err", err)
				continue
			}
			dispatched++
			depth++
		}
	}
	return dispatched, nil
}
