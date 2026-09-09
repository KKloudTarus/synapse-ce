package responsefleet

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	responseuc "github.com/KKloudTarus/synapse-ce/internal/usecase/response"
)

type observerDispatchClock struct{ now time.Time }

func (c *observerDispatchClock) Now() time.Time { return c.now }

func addObserverAgent(t *testing.T, ctx context.Context, agents *memory.FleetAgentStore, id shared.ID, now time.Time) {
	t.Helper()
	agent, err := fleetagent.NewAgent(
		id, "tenant-1", id.String(), "linux", "test", "test",
		[]string{workorder.CapabilityResponseObserve}, "token-hash", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := agents.CreateAgent(ctx, agent); err != nil {
		t.Fatal(err)
	}
}

func addObserverAssignment(t *testing.T, ctx context.Context, store *memory.ResponseObserverBindingStore, agentID shared.ID, now time.Time) {
	t.Helper()
	binding := fleetagent.ResponseObserverBinding{
		TenantID: "tenant-1", AgentID: agentID, AssetID: "asset-1", AssignedBy: "operator-1",
		AssignedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Version: 1,
	}
	intentID := "observer-assignment:" + agentID.String()
	if _, _, err := store.SaveResponseObserverBindingWithAudit(ctx, binding, 0, ports.FleetAuditIntent{
		ID: intentID, Entry: ports.AuditEntry{
			Actor: "operator-1", Action: "fleet.response_observer.assigned", Target: agentID.String(), At: binding.AssignedAt,
			Metadata: map[string]string{"idempotency_key": intentID},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func observerVerificationRequest(h executorHarness) responseuc.VerificationRequest {
	return responseuc.VerificationRequest{
		TenantID: "tenant-1", EngagementID: h.req.EngagementID, Action: h.req.Action, Target: h.req.Fingerprint,
		ExecutorID: "agent:agent-1:response-executor", ExecutorAgentID: "agent-1", AttemptKey: h.req.IdempotencyKey,
		VerificationChallenge: strings.Repeat("a", 64), AttemptedAt: h.req.IssuedAt, DeadlineAt: h.req.DeadlineAt,
	}
}

func attachReceiptBuilder(t *testing.T, dispatcher *ObserverDispatcher, h executorHarness, clock ports.Clock) {
	t.Helper()
	builder, err := NewTargetEvidenceReceiptBuilder(h.executor.bindings, memory.NewEndpointTimelineStore(), memory.NewCoverageWindowStore(), memory.NewResponseVerificationStore(), clock)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.SetTargetEvidenceReceiptBuilder(builder)
}

func TestObserverDispatcherIssuesAddressedOrderIdempotently(t *testing.T) {
	h := newExecutorHarness(t)
	agents := h.executor.agents.(*memory.FleetAgentStore)
	bindings := memory.NewResponseObserverBindingStore()
	addObserverAgent(t, h.ctx, agents, "observer-1", h.req.IssuedAt)
	addObserverAssignment(t, h.ctx, bindings, "observer-1", h.req.IssuedAt)
	clock := &observerDispatchClock{now: h.req.IssuedAt}
	dispatcher, err := NewObserverDispatcher(h.work, agents, bindings, clock, time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	attachReceiptBuilder(t, dispatcher, h, clock)
	req := observerVerificationRequest(h)
	if err := dispatcher.EnsureObservation(h.ctx, req); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	clock.now = clock.now.Add(10 * time.Second)
	if err := dispatcher.EnsureObservation(h.ctx, req); err != nil {
		t.Fatalf("idempotent dispatch: %v", err)
	}
	orders, err := h.workStore.ListByTenant(h.ctx, "tenant-1")
	if err != nil || len(orders) != 1 {
		t.Fatalf("orders=%+v err=%v", orders, err)
	}
	order := orders[0]
	if order.AgentID != "observer-1" || order.Capability != workorder.CapabilityResponseObserve ||
		order.Priority != workorder.ResponseObservePriority || order.ResponseObserve == nil ||
		order.ResponseObserve.ObserverAgentID != order.AgentID || order.ResponseObserve.Target != req.Target {
		t.Fatalf("observer order=%+v", order)
	}
}

func TestObserverDispatcherFailsClosedOnMultipleObservers(t *testing.T) {
	h := newExecutorHarness(t)
	agents := h.executor.agents.(*memory.FleetAgentStore)
	bindings := memory.NewResponseObserverBindingStore()
	for _, id := range []shared.ID{"observer-1", "observer-2"} {
		addObserverAgent(t, h.ctx, agents, id, h.req.IssuedAt)
		addObserverAssignment(t, h.ctx, bindings, id, h.req.IssuedAt)
	}
	clock := &observerDispatchClock{now: h.req.IssuedAt}
	dispatcher, err := NewObserverDispatcher(h.work, agents, bindings, clock, time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	attachReceiptBuilder(t, dispatcher, h, clock)
	if err := dispatcher.EnsureObservation(h.ctx, observerVerificationRequest(h)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("multiple observer error=%v", err)
	}
}

func TestObserverDispatcherRejectsExpiredAttemptDeadline(t *testing.T) {
	h := newExecutorHarness(t)
	agents := h.executor.agents.(*memory.FleetAgentStore)
	bindings := memory.NewResponseObserverBindingStore()
	addObserverAgent(t, h.ctx, agents, "observer-1", h.req.IssuedAt)
	addObserverAssignment(t, h.ctx, bindings, "observer-1", h.req.IssuedAt)
	clock := &observerDispatchClock{now: h.req.DeadlineAt}
	dispatcher, err := NewObserverDispatcher(h.work, agents, bindings, clock, time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	attachReceiptBuilder(t, dispatcher, h, clock)
	if err := dispatcher.EnsureObservation(h.ctx, observerVerificationRequest(h)); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("expired observation dispatch error=%v, want forbidden", err)
	}
	orders, err := h.workStore.ListByTenant(h.ctx, "tenant-1")
	if err != nil || len(orders) != 0 {
		t.Fatalf("expired attempt issued observation orders=%+v err=%v", orders, err)
	}
}
