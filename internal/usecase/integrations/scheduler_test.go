package integrations

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
)

type schedulerTenants []shared.ID

func (tenants schedulerTenants) ListTenantIDs(context.Context) ([]shared.ID, error) {
	return tenants, nil
}

type schedulerLeadership struct{ leader bool }

func (leadership *schedulerLeadership) IsLeader() bool { return leadership.leader }

type schedulerAdapter struct {
	descriptor integration.ProviderDescriptor
}

func (adapter schedulerAdapter) Descriptor() integration.ProviderDescriptor {
	return adapter.descriptor
}

func TestSchedulerIsLeaderGatedBackpressureAwareAndDispatchBounded(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.ID("tenant-1")
	clock := &integrationTestClock{now: time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)}
	ids := idgen.RandomID{}
	queue := memory.NewJobQueue(ids, clock.Now)
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := memory.NewIntegrationStore(queue, cipher, clock)
	descriptor := integration.ProviderDescriptor{Provider: "fake-ci", Name: "Fake CI", Capabilities: []integration.Capability{integration.CapabilityReadRuns}}
	registry := integration.NewRegistry()
	if err := registry.Register(descriptor, func(integration.Integration, integration.CredentialBundle) (integration.Adapter, error) {
		return schedulerAdapter{descriptor: descriptor}, nil
	}); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, registry, memory.NewProjectRepository(), memory.MissingIntegrationAnalysisMatcher{}, ids, clock, &integrationTestAudit{})
	if err != nil {
		t.Fatal(err)
	}
	for index := range 2 {
		item := integration.Integration{
			ID: shared.ID(string(rune('a'+index)) + "-integration"), TenantID: tenantID, Provider: "fake-ci", Name: "Fake", Endpoint: "https://ci.example.com/" + string(rune('a'+index)),
			Config: []byte(`{}`), PollInterval: time.Minute, Enabled: true, Version: 1, CreatedAt: clock.Now(), UpdatedAt: clock.Now(),
		}
		if err := store.CreateIntegration(shared.WithTenant(ctx, tenantID), item); err != nil {
			t.Fatal(err)
		}
	}
	leadership := &schedulerLeadership{}
	scheduler, err := NewScheduler(store, schedulerTenants{tenantID}, queue, service, clock, leadership, SchedulerConfig{Interval: time.Minute, DispatchLimit: 1, MaxQueueDepth: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if dispatched, err := scheduler.Tick(ctx); err != nil || dispatched != 0 {
		t.Fatalf("non-leader dispatched=%d err=%v", dispatched, err)
	}
	leadership.leader = true
	dummyID, err := queue.Enqueue(shared.WithTenant(ctx, tenantID), JobKind, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if dispatched, err := scheduler.Tick(ctx); err != nil || dispatched != 0 {
		t.Fatalf("backpressured dispatched=%d err=%v", dispatched, err)
	}
	dummy, err := queue.Claim(ctx, time.Minute, JobKind)
	if err != nil || dummy == nil || dummy.ID != dummyID {
		t.Fatalf("claim dummy=%+v err=%v", dummy, err)
	}
	if err := queue.Complete(ctx, dummy.ID, dummy.Fence); err != nil {
		t.Fatal(err)
	}
	if dispatched, err := scheduler.Tick(ctx); err != nil || dispatched != 1 {
		t.Fatalf("leader dispatched=%d err=%v", dispatched, err)
	}
	if depth, err := queue.Depth(ctx, JobKind); err != nil || depth != 1 {
		t.Fatalf("queue depth=%d err=%v", depth, err)
	}
}
