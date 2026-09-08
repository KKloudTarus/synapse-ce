package response

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type responseTenantListerStub struct {
	tenants []shared.ID
	err     error
}

func (s responseTenantListerStub) ListTenantIDs(context.Context) ([]shared.ID, error) {
	return s.tenants, s.err
}

type pendingResponseReconcilerStub struct {
	tenants []shared.ID
	fail    shared.ID
}

type incidentLinkReconcilerStub struct {
	tenants []shared.ID
	fail    shared.ID
}

func (s *incidentLinkReconcilerStub) ReconcileIncidentLinks(ctx context.Context) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return shared.ErrValidation
	}
	s.tenants = append(s.tenants, tenantID)
	if tenantID == s.fail {
		return errors.New("incident linkage unavailable")
	}
	return nil
}

func (s *pendingResponseReconcilerStub) ReconcilePending(ctx context.Context) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return shared.ErrValidation
	}
	s.tenants = append(s.tenants, tenantID)
	if tenantID == s.fail {
		return errors.New("reconciliation unavailable")
	}
	return nil
}

func TestResponseReconciliationRunnerBindsEveryTenant(t *testing.T) {
	reconciler := &pendingResponseReconcilerStub{fail: "tenant-a"}
	runner, err := NewReconciliationRunner(
		responseTenantListerStub{tenants: []shared.ID{"tenant-a", "", "tenant-b"}},
		reconciler,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("run once must report tenant and reconciliation failures")
	}
	if len(reconciler.tenants) != 2 || reconciler.tenants[0] != "tenant-a" || reconciler.tenants[1] != "tenant-b" {
		t.Fatalf("reconciled tenants = %v, want tenant-a and tenant-b", reconciler.tenants)
	}
}

func TestResponseReconciliationRunnerAlsoReconcilesIncidentLinks(t *testing.T) {
	responses := &pendingResponseReconcilerStub{}
	links := &incidentLinkReconcilerStub{}
	runner, err := NewReconciliationRunner(
		responseTenantListerStub{tenants: []shared.ID{"tenant-a", "tenant-b"}},
		responses,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		links,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("run once: %v", err)
	}
	if len(links.tenants) != 2 || links.tenants[0] != "tenant-a" || links.tenants[1] != "tenant-b" {
		t.Fatalf("incident links reconciled in tenants %v", links.tenants)
	}
}

func TestResponseReconciliationRunnerReturnsDiscoveryFailure(t *testing.T) {
	want := errors.New("tenant store unavailable")
	runner, err := NewReconciliationRunner(
		responseTenantListerStub{err: want},
		&pendingResponseReconcilerStub{},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.RunOnce(context.Background()); !errors.Is(err, want) {
		t.Fatalf("RunOnce() error = %v, want %v", err, want)
	}
}
