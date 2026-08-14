package promotion

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type reconciliationScopeReaderStub struct {
	scopes []ports.PromotionReconciliationScope
	err    error
}

func (s reconciliationScopeReaderStub) ListPromotionReconciliationScopes(context.Context) ([]ports.PromotionReconciliationScope, error) {
	return s.scopes, s.err
}

type reconciliationStub struct {
	calls  []ports.PromotionReconciliationScope
	fail   shared.ID
	cancel context.CancelFunc
}

type evaluationStub struct {
	calls []ports.PromotionReconciliationScope
}

func (e *evaluationStub) Evaluate(ctx context.Context, engagementID shared.ID) (int, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return 0, errors.New("missing tenant context")
	}
	e.calls = append(e.calls, ports.PromotionReconciliationScope{TenantID: tenantID, EngagementID: engagementID})
	return 0, nil
}

var _ ports.PromotionEvaluator = (*evaluationStub)(nil)

func (r *reconciliationStub) Reconcile(ctx context.Context, engagementID shared.ID) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return errors.New("missing tenant context")
	}
	r.calls = append(r.calls, ports.PromotionReconciliationScope{TenantID: tenantID, EngagementID: engagementID})
	if r.cancel != nil {
		r.cancel()
	}
	if engagementID == r.fail {
		return errors.New("reconcile failure")
	}
	return nil
}

func newReconciliationRunner(t *testing.T, scopes ports.PromotionReconciliationScopeReader, evaluator ports.PromotionEvaluator, reconciler ports.PromotionReconciler) *ReconciliationRunner {
	t.Helper()
	runner, err := NewReconciliationRunner(scopes, evaluator, reconciler, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func TestReconciliationRunnerBindsEveryScopeTenant(t *testing.T) {
	reconciler := &reconciliationStub{}
	evaluator := &evaluationStub{}
	runner := newReconciliationRunner(t, reconciliationScopeReaderStub{scopes: []ports.PromotionReconciliationScope{
		{TenantID: "tenant-a", EngagementID: "eng-a"},
		{TenantID: "tenant-b", EngagementID: "eng-b"},
	}}, evaluator, reconciler)
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	want := []ports.PromotionReconciliationScope{{TenantID: "tenant-a", EngagementID: "eng-a"}, {TenantID: "tenant-b", EngagementID: "eng-b"}}
	if len(reconciler.calls) != len(want) {
		t.Fatalf("reconciliation calls = %#v, want %#v", reconciler.calls, want)
	}
	for i := range want {
		if evaluator.calls[i] != want[i] || reconciler.calls[i] != want[i] {
			t.Fatalf("scope %d evaluated=%#v reconciled=%#v, want %#v", i, evaluator.calls[i], reconciler.calls[i], want[i])
		}
	}
}

func TestReconciliationRunnerContinuesAfterScopeFailure(t *testing.T) {
	reconciler := &reconciliationStub{fail: "eng-a"}
	evaluator := &evaluationStub{}
	runner := newReconciliationRunner(t, reconciliationScopeReaderStub{scopes: []ports.PromotionReconciliationScope{
		{TenantID: "tenant-a", EngagementID: "eng-a"},
		{TenantID: "tenant-b", EngagementID: "eng-b"},
	}}, evaluator, reconciler)
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(reconciler.calls) != 2 || reconciler.calls[1].EngagementID != "eng-b" {
		t.Fatalf("calls after failed scope = %#v, want both scopes", reconciler.calls)
	}
}

func TestReconciliationRunnerHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reconciler := &reconciliationStub{cancel: cancel}
	evaluator := &evaluationStub{}
	runner := newReconciliationRunner(t, reconciliationScopeReaderStub{scopes: []ports.PromotionReconciliationScope{
		{TenantID: "tenant-a", EngagementID: "eng-a"},
		{TenantID: "tenant-b", EngagementID: "eng-b"},
	}}, evaluator, reconciler)
	if err := runner.RunOnce(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunOnce error = %v, want context.Canceled", err)
	}
	if len(reconciler.calls) != 1 {
		t.Fatalf("calls after cancellation = %#v, want first scope only", reconciler.calls)
	}
}
