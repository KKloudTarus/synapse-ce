package main

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/platform/executionmode"
	integrationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/integrations"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/worker"
)

func TestIntegrationsProfileUsesDispatchOnlySCAWithSandboxConfigured(t *testing.T) {
	cfg := config.Config{WorkerProfile: config.WorkerProfileIntegrations, SandboxEnabled: true}
	if !usesDispatchOnlySCA(cfg) {
		t.Fatal("integrations profile must not construct local SCA execution adapters")
	}
	if usesDispatchOnlySCA(config.Config{WorkerProfile: config.WorkerProfileAll, SandboxEnabled: true}) {
		t.Fatal("all profile must retain its execution adapter composition")
	}
	acquirer, generator, sources := integrationsSCAAdapters()
	if _, err := acquirer.Acquire(context.Background(), ports.AcquireRequest{}); !errors.Is(err, executionmode.ErrDispatchOnly) {
		t.Fatalf("acquirer error = %v, want dispatch-only refusal", err)
	}
	if _, err := generator.Generate(context.Background(), "workspace"); !errors.Is(err, executionmode.ErrDispatchOnly) {
		t.Fatalf("SBOM generator error = %v, want dispatch-only refusal", err)
	}
	if len(sources) != 1 {
		t.Fatalf("detection sources = %d, want one dispatch-only source", len(sources))
	}
	if _, err := sources[0].Scan(context.Background(), &sbom.SBOM{}); !errors.Is(err, executionmode.ErrDispatchOnly) {
		t.Fatalf("detection source error = %v, want dispatch-only refusal", err)
	}
}

func TestIntegrationsProfileHandlerAllowlist(t *testing.T) {
	handler := worker.HandlerFunc(func(context.Context, ports.QueuedJob) error { return nil })
	notifications := map[string]worker.Handler{
		"unrelated_scan":             handler,
		notificationWorkerKinds()[0]: handler,
		notificationWorkerKinds()[2]: handler,
	}
	handlers := integrationsProfileHandlers(handler, notifications)
	if handlers[integrationuc.JobKind] == nil {
		t.Fatal("integration handler is missing")
	}
	if handlers["unrelated_scan"] != nil {
		t.Fatal("integrations worker must not claim unrelated executable work")
	}
	if len(handlers) != 3 {
		t.Fatalf("handler count = %d, want integration plus enabled notification handlers", len(handlers))
	}
}

func TestWorkerProfilesHaveIndependentMaintenanceLeases(t *testing.T) {
	resources := make(map[string]bool)
	for _, profile := range []config.WorkerProfile{config.WorkerProfileAll, config.WorkerProfileIntegrations, config.WorkerProfileLifecycle, config.WorkerProfileNotifications} {
		resource := workerMaintenanceResource(config.Config{WorkerProfile: profile, LeaderResource: "synapse"})
		if resources[resource] {
			t.Fatalf("profile %s shares maintenance lease %s", profile, resource)
		}
		resources[resource] = true
	}
	if got := workerMaintenanceResource(config.Config{WorkerProfile: config.WorkerProfileAll, LeaderResource: "synapse"}); got != "synapse-worker-maintenance" {
		t.Fatalf("all profile legacy lease changed: %s", got)
	}
}
