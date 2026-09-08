package responseobserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type observerTestClock struct{ now time.Time }

func (c *observerTestClock) Now() time.Time { return c.now }

type observerTestAudit struct {
	failOnce bool
	entries  []ports.AuditEntry
}

func (a *observerTestAudit) Record(context.Context, ports.AuditEntry) error { return nil }

func (a *observerTestAudit) RecordOnce(_ context.Context, entry ports.AuditEntry) error {
	if a.failOnce {
		a.failOnce = false
		return errors.New("audit unavailable")
	}
	a.entries = append(a.entries, entry)
	return nil
}

func newObserverServiceHarness(t *testing.T) (context.Context, *Service, *memory.ResponseObserverBindingStore, *observerTestClock, *observerTestAudit) {
	t.Helper()
	now := time.Unix(2_000_000, 0).UTC()
	ctx := shared.WithTenant(context.Background(), "tenant-1")
	agents := memory.NewFleetAgentStore()
	agent, err := fleetagent.NewAgent(
		"observer-1", "tenant-1", "observer", "linux", "test", "test",
		[]string{workorder.CapabilityResponseObserve}, "token-hash", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := agents.CreateAgent(ctx, agent); err != nil {
		t.Fatal(err)
	}
	bindings := memory.NewTelemetryTransportStore()
	if err := bindings.BindTelemetryAsset(ctx, ports.TelemetryAssetBinding{
		TenantID: "tenant-1", AgentID: "primary-1", AssetID: "asset-1", UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	store := memory.NewResponseObserverBindingStore()
	clock := &observerTestClock{now: now}
	audit := &observerTestAudit{}
	service, err := NewService(store, agents, bindings, audit, clock)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, service, store, clock, audit
}

func TestAssignCommitsIndependentBindingAndAudit(t *testing.T) {
	ctx, service, store, clock, audit := newObserverServiceHarness(t)
	binding, err := service.Assign(ctx, AssignInput{
		TenantID: "tenant-1", AgentID: "observer-1", AssetID: "asset-1", Actor: "operator-1",
		ExpiresAt: clock.now.Add(time.Hour), ExpectedVersion: 0,
	})
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if binding.Version != 1 || binding.AssignedBy != "operator-1" || len(audit.entries) != 1 {
		t.Fatalf("binding=%+v audit=%+v", binding, audit.entries)
	}
	pending, err := store.ListPendingFleetAudits(ctx)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending audit intents=%+v err=%v", pending, err)
	}
}

func TestAssignExactRetryRepairsFailedAuditDelivery(t *testing.T) {
	ctx, service, store, clock, audit := newObserverServiceHarness(t)
	input := AssignInput{
		TenantID: "tenant-1", AgentID: "observer-1", AssetID: "asset-1", Actor: "operator-1",
		ExpiresAt: clock.now.Add(time.Hour), ExpectedVersion: 0,
	}
	audit.failOnce = true
	if _, err := service.Assign(ctx, input); err == nil {
		t.Fatal("first assignment must surface the audit outage")
	}
	committed, err := store.GetResponseObserverBinding(ctx, "observer-1")
	if err != nil {
		t.Fatalf("binding must commit with its audit obligation: %v", err)
	}
	clock.now = clock.now.Add(time.Minute)
	retried, err := service.Assign(ctx, input)
	if err != nil {
		t.Fatalf("repair exact retry: %v", err)
	}
	if !retried.AssignedAt.Equal(committed.AssignedAt) || len(audit.entries) != 1 {
		t.Fatalf("retry changed server provenance: committed=%+v retry=%+v audit=%+v", committed, retried, audit.entries)
	}
	pending, err := store.ListPendingFleetAudits(ctx)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending audit intents=%+v err=%v", pending, err)
	}
}

func TestAssignRejectsPrimaryOwnerAndMachineActor(t *testing.T) {
	ctx, service, _, clock, _ := newObserverServiceHarness(t)
	primary, err := service.agents.GetAgent(ctx, "tenant-1", "observer-1")
	if err != nil {
		t.Fatal(err)
	}
	primary.ID = "primary-1"
	primary.Name = "primary"
	if err := service.agents.CreateAgent(ctx, primary); err != nil {
		t.Fatal(err)
	}
	base := AssignInput{
		TenantID: "tenant-1", AgentID: "primary-1", AssetID: "asset-1", Actor: "operator-1",
		ExpiresAt: clock.now.Add(time.Hour), ExpectedVersion: 0,
	}
	if _, err := service.Assign(ctx, base); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("primary owner assignment error=%v", err)
	}
	base.AgentID = "observer-1"
	base.Actor = "agent:observer-1"
	if _, err := service.Assign(ctx, base); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("machine assignment error=%v", err)
	}
}
