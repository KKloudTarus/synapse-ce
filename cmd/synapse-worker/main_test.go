package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityreconcile"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/vulnerabilitycorrelation"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/vulnerabilityreconciliation"
)

type readinessWaiterFunc func(context.Context, time.Duration) error

func (f readinessWaiterFunc) WaitReady(ctx context.Context, interval time.Duration) error {
	return f(ctx, interval)
}

func TestWaitForEgressBrokerPreservesParentCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()

	err := waitForEgressBroker(parent, readinessWaiterFunc(func(ctx context.Context, interval time.Duration) error {
		if interval != 100*time.Millisecond {
			t.Fatalf("interval = %s, want 100ms", interval)
		}
		<-ctx.Done()
		return ctx.Err()
	}))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("wait error = %v, want context canceled", err)
	}
}

func TestVulnerabilityReconcileJobHandlerExecutesDurableRun(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "worker-tenant")
	now := time.Now().UTC().Add(-time.Minute)
	engagements := memory.NewEngagementRepository()
	target, err := engagement.New("worker-engagement", "worker-tenant", "worker target", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := engagements.Create(ctx, target); err != nil {
		t.Fatal(err)
	}
	materializer := memory.NewAdvisoryMaterializer()
	item := advisory.Advisory{ID: "CVE-2026-WORKER", Affected: []advisory.AffectedPackage{{Ecosystem: "Go", Package: "example.com/worker", Versions: []string{"1.0.0"}}}}
	if _, err := materializer.Materialize(context.Background(), []advisory.ObservationRecord{{Observation: advisory.Observation{SourceType: "osv", SourceID: "worker-source", RecordID: item.ID, Status: advisory.StatusActive, Advisory: item}, ObservedAt: now}}); err != nil {
		t.Fatal(err)
	}
	inventory := memory.NewComponentInventoryStore(sbom.ComponentRecord{
		TenantID: "worker-tenant", EngagementID: "worker-engagement", SBOMID: "worker-sbom", ComponentID: "worker-component",
		Name: "example.com/worker", Version: "1.0.0", PURL: "pkg:golang/example.com/worker@1.0.0", Ecosystem: "Go", Package: "example.com/worker",
		IdentityHash: "worker-component-fingerprint", IdentityStatus: sbom.IdentityResolved, CPEStatus: sbom.IdentityUnsupported, SBOMCreatedAt: now,
	})
	occurrences := memory.NewVulnerabilityOccurrenceStore()
	correlator, err := vulnerabilitycorrelation.NewService(inventory, materializer, occurrences)
	if err != nil {
		t.Fatal(err)
	}
	ids, clock := idgen.RandomID{}, idgen.SystemClock{}
	runs := memory.NewVulnerabilityReconcileRunStore(ids, clock, memory.NewJobQueue(ids, clock.Now))
	service, err := vulnerabilityreconciliation.NewService(runs, engagements, materializer, materializer, occurrences, correlator, materializer, 10)
	if err != nil {
		t.Fatal(err)
	}
	service.SetRunLock(memory.NewRunLock())
	run, created, err := service.Start(ctx, vulnerabilityreconciliation.StartRequest{Scope: vulnerabilityreconcile.ScopeAdvisory, AdvisoryID: item.ID, ClientIdempotencyKey: "worker-handler-test"})
	if err != nil || !created {
		t.Fatalf("start run=%+v created=%v err=%v", run, created, err)
	}
	handler := vulnerabilityReconcileJobHandler{svc: service}
	if err := handler.Handle(ctx, ports.QueuedJob{ID: run.DurableJobID, TenantID: "worker-tenant", Kind: vulnerabilityreconcile.JobKind}); err != nil {
		t.Fatal(err)
	}
	finished, err := runs.Get(ctx, run.ID)
	if err != nil || finished.State != vulnerabilityreconcile.StateSucceeded {
		t.Fatalf("worker run=%+v err=%v", finished, err)
	}
	found, err := occurrences.ListByEngagement(ctx, "worker-tenant", "worker-engagement", nil)
	if err != nil || len(found) != 1 || found[0].AdvisoryID != item.ID {
		t.Fatalf("worker occurrences=%+v err=%v", found, err)
	}
}
