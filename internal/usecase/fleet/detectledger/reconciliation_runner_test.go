package detectledger

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type detectionTenantStoreStub struct {
	tenants []shared.ID
	err     error
}

func (s detectionTenantStoreStub) ListTenantIDs(context.Context) ([]shared.ID, error) {
	return append([]shared.ID(nil), s.tenants...), s.err
}

type pendingDetectionReconcilerStub struct {
	calls  []shared.ID
	fail   shared.ID
	cancel context.CancelFunc
	done   chan struct{}
}

func (r *pendingDetectionReconcilerStub) ReconcilePendingDetections(ctx context.Context) (int, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return 0, errors.New("missing tenant context")
	}
	r.calls = append(r.calls, tenantID)
	if r.cancel != nil {
		r.cancel()
	}
	if r.done != nil {
		select {
		case r.done <- struct{}{}:
		default:
		}
	}
	if tenantID == r.fail {
		return 0, errors.New("reconcile failure")
	}
	return 1, nil
}

func testDetectionReconciliationLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newDetectionReconciliationRunner(
	t *testing.T,
	tenants ports.DetectionReconciliationTenantStore,
	reconciler ports.PendingDetectionReconciler,
) *ReconciliationRunner {
	t.Helper()
	runner, err := NewReconciliationRunner(tenants, reconciler, testDetectionReconciliationLogger())
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func TestNewReconciliationRunnerRejectsMissingDependencies(t *testing.T) {
	tenants := detectionTenantStoreStub{}
	reconciler := &pendingDetectionReconcilerStub{}
	for _, tc := range []struct {
		name       string
		tenants    ports.DetectionReconciliationTenantStore
		reconciler ports.PendingDetectionReconciler
		log        *slog.Logger
	}{
		{name: "tenant store", reconciler: reconciler, log: testDetectionReconciliationLogger()},
		{name: "reconciler", tenants: tenants, log: testDetectionReconciliationLogger()},
		{name: "logger", tenants: tenants, reconciler: reconciler},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewReconciliationRunner(tc.tenants, tc.reconciler, tc.log); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("NewReconciliationRunner() error = %v, want validation", err)
			}
		})
	}
}

func TestReconciliationRunnerBindsEveryTenant(t *testing.T) {
	reconciler := &pendingDetectionReconcilerStub{}
	runner := newDetectionReconciliationRunner(t, detectionTenantStoreStub{tenants: []shared.ID{"tenant-a", "tenant-b"}}, reconciler)
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if want := []shared.ID{"tenant-a", "tenant-b"}; !reflect.DeepEqual(reconciler.calls, want) {
		t.Fatalf("reconciliation calls = %#v, want %#v", reconciler.calls, want)
	}
}

func TestReconciliationRunnerReturnsTenantDiscoveryFailure(t *testing.T) {
	want := errors.New("tenant discovery failure")
	runner := newDetectionReconciliationRunner(t, detectionTenantStoreStub{err: want}, &pendingDetectionReconcilerStub{})
	if err := runner.RunOnce(context.Background()); !errors.Is(err, want) {
		t.Fatalf("RunOnce() error = %v, want discovery failure", err)
	}
}

func TestReconciliationRunnerContinuesAfterTenantFailureAndSkipsZeroTenant(t *testing.T) {
	reconciler := &pendingDetectionReconcilerStub{fail: "tenant-a"}
	runner := newDetectionReconciliationRunner(t, detectionTenantStoreStub{tenants: []shared.ID{"tenant-a", "", "tenant-b"}}, reconciler)
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if want := []shared.ID{"tenant-a", "tenant-b"}; !reflect.DeepEqual(reconciler.calls, want) {
		t.Fatalf("calls after failed and invalid tenants = %#v, want %#v", reconciler.calls, want)
	}
}

func TestReconciliationRunnerHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reconciler := &pendingDetectionReconcilerStub{cancel: cancel}
	runner := newDetectionReconciliationRunner(t, detectionTenantStoreStub{tenants: []shared.ID{"tenant-a", "tenant-b"}}, reconciler)
	if err := runner.RunOnce(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunOnce() error = %v, want context.Canceled", err)
	}
	if want := []shared.ID{"tenant-a"}; !reflect.DeepEqual(reconciler.calls, want) {
		t.Fatalf("calls after cancellation = %#v, want %#v", reconciler.calls, want)
	}
}

func TestReconciliationRunnerRejectsCanceledContextBeforeDiscovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := newDetectionReconciliationRunner(t, detectionTenantStoreStub{tenants: []shared.ID{"tenant-a"}}, &pendingDetectionReconcilerStub{})
	if err := runner.RunOnce(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunOnce() error = %v, want context.Canceled", err)
	}
}

func TestReconciliationRunnerPeriodicStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reconciler := &pendingDetectionReconcilerStub{done: make(chan struct{}, 1)}
	runner := newDetectionReconciliationRunner(t, detectionTenantStoreStub{tenants: []shared.ID{"tenant-a"}}, reconciler)
	stopped := make(chan struct{})
	go func() {
		runner.RunPeriodic(ctx, time.Millisecond)
		close(stopped)
	}()
	select {
	case <-reconciler.done:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("periodic reconciliation did not run")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("periodic reconciliation did not stop after cancellation")
	}
}
