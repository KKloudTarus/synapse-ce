package main

import (
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/platform/executionmode"
	integrationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/integrations"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/worker"
)

// integrationsSCAAdapters supplies the fail-closed ports needed to read and
// verify stored report evidence without constructing local scan tooling.
func integrationsSCAAdapters() (ports.Acquirer, ports.SBOMGenerator, []ports.DetectionSource) {
	dispatchOnly := executionmode.DispatchOnly{}
	return dispatchOnly, dispatchOnly, []ports.DetectionSource{dispatchOnly}
}

func integrationsProfile(cfg config.Config) bool {
	return cfg.WorkerProfile == config.WorkerProfileIntegrations
}

func usesDispatchOnlySCA(cfg config.Config) bool {
	return integrationsProfile(cfg)
}

func workerMaintenanceResource(cfg config.Config) string {
	switch cfg.WorkerProfile {
	case config.WorkerProfileNotifications:
		return notificationMaintenanceResource(cfg)
	case config.WorkerProfileIntegrations:
		return cfg.LeaderResource + "-worker-integrations-maintenance"
	case config.WorkerProfileLifecycle:
		return cfg.LeaderResource + "-worker-lifecycle-maintenance"
	default:
		return cfg.LeaderResource + "-worker-maintenance"
	}
}

// integrationsProfileHandlers deliberately claims only integration work plus
// the already-enabled notification handlers. Scan, recon, and lifecycle jobs
// remain for their corresponding workers.
func integrationsProfileHandlers(integration worker.Handler, notifications map[string]worker.Handler) map[string]worker.Handler {
	handlers := map[string]worker.Handler{integrationuc.JobKind: integration}
	for _, kind := range notificationWorkerKinds() {
		if handler := notifications[kind]; handler != nil {
			handlers[kind] = handler
		}
	}
	return handlers
}
