package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/KKloudTarus/synapse-ce/internal/composition"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/notificationsender"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	docpublishuc "github.com/KKloudTarus/synapse-ce/internal/usecase/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/worker"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

type documentScheduleRuntime struct {
	handlers        map[string]worker.Handler
	maintenance     []func(context.Context)
	metricsRegistry *prometheus.Registry
	close           func()
}

type documentScheduleRuntimeDependencies struct {
	ctx                       context.Context
	stop                      context.CancelFunc
	cfg                       config.Config
	pool                      *pgxpool.Pool
	vaultCipher               *vault.Cipher
	sender                    *notificationsender.Sender
	disabledNotificationTypes []notification.ChannelType
	audit                     ports.AuditLogger
	clock                     ports.Clock
	ids                       ports.IDGenerator
	log                       *slog.Logger
	tenants                   ports.TenantLister
	schedule                  docpublishuc.ScheduleDependencies
}

func configureDocumentScheduleRuntime(deps documentScheduleRuntimeDependencies) (documentScheduleRuntime, error) {
	notifications, err := configureNotificationWorkerRuntime(
		deps.ctx, deps.stop, deps.cfg, deps.pool, deps.vaultCipher, deps.sender, deps.disabledNotificationTypes,
		deps.audit, deps.clock, deps.ids, deps.log,
	)
	if err != nil {
		return documentScheduleRuntime{}, err
	}
	deps.schedule.EmailConfig = notifications.service
	schedules, err := docpublishuc.NewScheduleService(deps.schedule)
	if err != nil {
		notifications.close()
		return documentScheduleRuntime{}, fmt.Errorf("create document schedule service: %w", err)
	}
	runner, err := composition.NewDocumentPublicationRunner(schedules, deps.tenants, deps.log)
	if err != nil {
		notifications.close()
		return documentScheduleRuntime{}, fmt.Errorf("create document schedule runner: %w", err)
	}
	maintenance := append([]func(context.Context){}, notifications.maintenance...)
	maintenance = append(maintenance, runner.Run)
	return documentScheduleRuntime{
		handlers: notifications.handlers, maintenance: maintenance,
		metricsRegistry: notifications.metricsRegistry, close: notifications.close,
	}, nil
}
