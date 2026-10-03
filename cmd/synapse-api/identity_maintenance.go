package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/notificationsender"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	"github.com/KKloudTarus/synapse-ce/internal/platform/buildinfo"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identityrecovery"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5/pgxpool"
)

func runIdentityRecoveryMaintenance(ctx context.Context, recovery *identityrecovery.Service, tenant shared.ID) error {
	if recovery == nil {
		return fmt.Errorf("identity recovery maintenance service is required")
	}
	return recovery.DeliverAlerts(ctx, tenant, 100)
}

func startIdentityMaintenance(ctx context.Context, cfg config.Config, pool *pgxpool.Pool, sender *notificationsender.Sender, clock ports.Clock, ids ports.IDGenerator, log *slog.Logger) {
	if pool == nil {
		return
	}
	store, err := postgres.NewIdentityFoundationStore(pool)
	if err != nil {
		log.Error("identity maintenance initialization failed")
		return
	}
	recovery, err := identityrecovery.NewService(store, clock, ids)
	if err != nil {
		log.Error("identity maintenance initialization failed")
		return
	}
	mailerConfigured := sender != nil && cfg.NotificationSMTPHost != "" && cfg.NotificationSMTPFrom != ""
	if mailerConfigured {
		recovery.SetAlertMailer(sender)
	}
	tenants := append([]string{}, cfg.IdentityCutoverReadTenants...)
	defaultTenant := shared.TenantOrDefault(shared.ID(cfg.OIDCTenantID)).String()
	found := false
	for _, t := range tenants {
		if t == defaultTenant {
			found = true
		}
	}
	if !found {
		tenants = append(tenants, defaultTenant)
	}
	instance := ids.NewID().String()
	for _, tenant := range tenants {
		startIdentityPeriodic(ctx, time.Minute, func() {
			bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
			generation := "legacy:" + buildinfo.App()
			if cfg.IdentityCutoverMutationForTenant(tenant) {
				generation = "shared-authentication:" + buildinfo.App()
			}
			if err := store.RecordCutoverWriterHeartbeat(bounded, shared.ID(tenant), generation, instance, clock.Now().UTC()); err != nil && ctx.Err() == nil {
				log.Warn("identity writer heartbeat failed", "tenant_id", tenant)
			}
			cancel()
		})
	}
	run := func() {
		// Cleanup and retained security delivery are obligations, independent of activation
		// flags. Enumerate global reference IDs, then keep every operation tenant-bound.
		maintenanceTenants, err := store.IdentityMaintenanceTenants(ctx)
		if err != nil {
			if ctx.Err() == nil {
				log.Warn("identity maintenance tenant enumeration failed")
			}
			return
		}
		for _, tenant := range maintenanceTenants {
			bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
			if _, err := store.CleanupIdentityAuthorizations(bounded, tenant, clock.Now().UTC(), 100); err != nil && ctx.Err() == nil {
				log.Warn("identity authorization cleanup failed", "tenant_id", tenant)
			}
			if _, err := store.CleanupEnterpriseSessionRetries(bounded, tenant, clock.Now().UTC(), 100); err != nil && ctx.Err() == nil {
				log.Warn("identity session retry cleanup failed", "tenant_id", tenant)
			}
			if mailerConfigured {
				if err := runIdentityRecoveryMaintenance(bounded, recovery, tenant); err != nil && ctx.Err() == nil {
					log.Warn("identity recovery alert delivery remains pending", "tenant_id", tenant)
				}
			}
			cancel()
			if ctx.Err() != nil {
				return
			}
		}
	}
	startIdentityPeriodic(ctx, time.Minute, run)
}

// Each tenant heartbeat and the delivery pass have independent scheduling. Slow
// database or mail work cannot delay another tenant's writer liveness evidence.
func startIdentityPeriodic(ctx context.Context, interval time.Duration, run func()) {
	go func() {
		if ctx.Err() != nil {
			return
		}
		run()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run()
			}
		}
	}()
}
