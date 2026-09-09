package responsefleet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/responsekey"
	"github.com/KKloudTarus/synapse-ce/internal/platform/worksign"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetwork"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	responseuc "github.com/KKloudTarus/synapse-ce/internal/usecase/response"
)

type testClock struct{ now time.Time }

func (c testClock) Now() time.Time { return c.now }

type testIDs struct{ n atomic.Int64 }

func (i *testIDs) NewID() shared.ID { return shared.ID(fmt.Sprintf("id-%d", i.n.Add(1))) }

type testAudit struct{}

func (testAudit) Record(context.Context, ports.AuditEntry) error     { return nil }
func (testAudit) RecordOnce(context.Context, ports.AuditEntry) error { return nil }
func (testAudit) Authorize(context.Context, ports.ExecutionRequest) (time.Time, error) {
	return time.Now().UTC(), nil
}

type executorHarness struct {
	ctx       context.Context
	executor  *Executor
	work      *fleetwork.Service
	workStore *memory.WorkOrderStore
	req       responseuc.ExecRequest
}

func newExecutorHarness(t *testing.T) executorHarness {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	clock := testClock{now: now}
	ctx := shared.WithTenant(context.Background(), "tenant-1")
	agentStore := memory.NewFleetAgentStore()
	agent, err := fleetagent.NewAgent(
		"agent-1", "tenant-1", "endpoint-1", "linux", "test", "test",
		[]string{workorder.CapabilityResponseProcess}, "token-hash", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := agentStore.CreateAgent(ctx, agent); err != nil {
		t.Fatal(err)
	}
	bindings := memory.NewTelemetryTransportStore()
	if err := bindings.BindTelemetryAsset(ctx, ports.TelemetryAssetBinding{
		TenantID: "tenant-1", AgentID: agent.ID, AssetID: "asset-1", UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	workStore := memory.NewWorkOrderStore()
	workSigner, err := worksign.New([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	work, err := fleetwork.NewService(workStore, workSigner, testAudit{}, clock, &testIDs{})
	if err != nil {
		t.Fatal(err)
	}
	work.SetExecutionAuthorizer(testAudit{})
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	commandSigner, err := responsekey.NewSigner(private, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := New(work, agentStore, bindings, commandSigner, clock, Config{
		CommandTTL: time.Minute, PollInterval: time.Millisecond, AgentStaleAfter: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	action, err := rdom.NewAction("action-1", rdom.KindStopProcess, "process-1")
	if err != nil {
		t.Fatal(err)
	}
	req := responseuc.ExecRequest{
		TenantID: "tenant-1", EngagementID: "engagement-1", ActionID: action.ID, AgentID: agent.ID,
		Action: action, Argv: append([]string(nil), action.Argv...), Target: action.Target,
		AuthorizationTarget: engagement.Target{Kind: engagement.TargetDomain, Value: action.Target.String()},
		Fingerprint: responsesaga.TargetFingerprint{
			Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: action.Target,
		},
		IdempotencyKey: "attempt-1", Declared: action.BlastRadius,
		VerificationChallenge: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		IssuedAt:              now,
		DeadlineAt:            now.Add(time.Minute),
	}
	return executorHarness{ctx: ctx, executor: executor, work: work, workStore: workStore, req: req}
}

func TestExecutorDispatchesSignedWorkAndReturnsDurableResult(t *testing.T) {
	h := newExecutorHarness(t)
	done := make(chan error, 1)
	go func() {
		for {
			orders, err := h.workStore.ListByTenant(h.ctx, "tenant-1")
			if err != nil {
				done <- err
				return
			}
			if len(orders) == 0 {
				time.Sleep(time.Millisecond)
				continue
			}
			order := orders[0]
			if order.ResponseCommand == nil || order.ResponseCommand.Signature == "" || order.AgentID != h.req.AgentID ||
				!order.ResponseCommand.NotAfter.Equal(h.req.DeadlineAt) || !order.NotAfter.Equal(h.req.DeadlineAt) {
				done <- fmt.Errorf("issued response order is incomplete: %+v", order)
				return
			}
			claimed, err := h.work.Claim(h.ctx, "agent-1", "tenant-1", "agent-1", 1)
			if err != nil || len(claimed) != 1 {
				done <- fmt.Errorf("claim=%+v: %w", claimed, err)
				return
			}
			if err := h.work.Transition(h.ctx, "agent-1", "tenant-1", order.ID, claimed[0].LeaseID, workorder.StateRunning, ""); err != nil {
				done <- err
				return
			}
			result := fleetagent.ResponseExecutionResult{
				AttemptKey: h.req.IdempotencyKey, CommandDigest: fleetagent.ResponseCommandDigest(*order.ResponseCommand),
				LeaseID: claimed[0].LeaseID, State: fleetagent.ResponseExecutionApplied,
				ObservedRadius: h.req.Declared, AffectedCount: 1, CompletedAt: h.req.IssuedAt.Add(time.Second),
			}
			done <- h.work.CompleteResponse(h.ctx, "agent-1", "tenant-1", order.ID, result, "applied")
			return
		}
	}()
	outcome, err := h.executor.Execute(h.ctx, h.req)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("endpoint completion: %v", err)
	}
	if outcome.ObservedRadius != h.req.Declared || outcome.AffectedCount != 1 || outcome.EnforcedHaltGeneration != h.req.HaltGeneration {
		t.Fatalf("outcome=%+v", outcome)
	}
}

func TestExecutorMapsAmbiguousEndpointResultToError(t *testing.T) {
	h := newExecutorHarness(t)
	done := make(chan error, 1)
	go func() {
		for {
			orders, err := h.workStore.ListByTenant(h.ctx, "tenant-1")
			if err != nil {
				done <- err
				return
			}
			if len(orders) == 0 {
				time.Sleep(time.Millisecond)
				continue
			}
			order := orders[0]
			claimed, err := h.work.Claim(h.ctx, "agent-1", "tenant-1", "agent-1", 1)
			if err != nil || len(claimed) != 1 {
				done <- fmt.Errorf("claim=%+v: %w", claimed, err)
				return
			}
			if err := h.work.Transition(h.ctx, "agent-1", "tenant-1", order.ID, claimed[0].LeaseID, workorder.StateRunning, ""); err != nil {
				done <- err
				return
			}
			result := fleetagent.ResponseExecutionResult{
				AttemptKey: h.req.IdempotencyKey, CommandDigest: fleetagent.ResponseCommandDigest(*order.ResponseCommand),
				LeaseID: claimed[0].LeaseID, State: fleetagent.ResponseExecutionOutcomeUnknown,
				CompletedAt: h.req.IssuedAt.Add(time.Second),
			}
			done <- h.work.CompleteResponse(h.ctx, "agent-1", "tenant-1", order.ID, result, "unknown")
			return
		}
	}()
	if _, err := h.executor.Execute(h.ctx, h.req); !errors.Is(err, ErrEndpointOutcomeUnknown) {
		t.Fatalf("ambiguous execute error=%v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("endpoint completion: %v", err)
	}
}

func TestResolveAgentFailsClosedWhenCapabilityIsStale(t *testing.T) {
	h := newExecutorHarness(t)
	h.executor.config.AgentStaleAfter = -time.Second
	if _, err := h.executor.ResolveAgent(h.ctx, "tenant-1", h.req.Fingerprint); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("stale response agent error=%v", err)
	}
}

func TestHaltIssuesHighestPrioritySignedFenceIdempotently(t *testing.T) {
	h := newExecutorHarness(t)
	// The harness agent predates the halt capability; advertise the complete response boundary.
	agents := h.executor.agents.(*memory.FleetAgentStore)
	agent, err := agents.GetAgent(h.ctx, "tenant-1", "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := agents.Heartbeat(h.ctx, "tenant-1", agent.ID, agent.Platform, agent.OSVersion, agent.AgentVersion,
		[]string{workorder.CapabilityResponseProcess, workorder.CapabilityResponseHalt}, h.req.IssuedAt); err != nil {
		t.Fatal(err)
	}
	if err := h.executor.Halt(h.ctx, "tenant-1", 2); err != nil {
		t.Fatalf("halt: %v", err)
	}
	if err := h.executor.Halt(h.ctx, "tenant-1", 2); err != nil {
		t.Fatalf("idempotent halt: %v", err)
	}
	orders, err := h.workStore.ListByTenant(h.ctx, "tenant-1")
	if err != nil || len(orders) != 1 {
		t.Fatalf("halt orders=%+v err=%v", orders, err)
	}
	order := orders[0]
	if order.Capability != workorder.CapabilityResponseHalt || order.Priority != workorder.ResponseHaltPriority ||
		order.ResponseHalt == nil || order.ResponseHalt.Generation != 2 || order.ResponseHalt.Signature == "" {
		t.Fatalf("halt order=%+v", order)
	}
}
