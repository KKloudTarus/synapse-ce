package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type workerSLASCAClock struct{ now time.Time }

func (c workerSLASCAClock) Now() time.Time { return c.now }

type workerSLASCAIDs struct{ next int }

func (ids *workerSLASCAIDs) NewID() shared.ID {
	ids.next++
	return shared.ID(fmt.Sprintf("worker-sla-%d", ids.next))
}

type workerSLASCAWiring struct{ assessor ports.FindingSLAAssessor }

func (w *workerSLASCAWiring) SetSLAAssessor(assessor ports.FindingSLAAssessor) {
	w.assessor = assessor
}

func TestConfigureWorkerSCASLAAssessor_EnabledPersistsAssessmentForQueuedSCAFinding(t *testing.T) {
	store := memory.NewSLAStore()
	wiring := &workerSLASCAWiring{}
	clock := workerSLASCAClock{now: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	if err := configureWorkerSCASLAAssessor(config.Config{SLAEnabled: true}, wiring, store, clock, &workerSLASCAIDs{}); err != nil {
		t.Fatal(err)
	}
	if wiring.assessor == nil {
		t.Fatal("enabled worker did not wire an SCA SLA assessor")
	}
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	view, err := wiring.assessor.AssessFinding(ctx, "tenant-a", finding.Finding{
		ID: "finding-sca", EngagementID: "eng-sca", Kind: finding.KindSCA,
		Severity: shared.SeverityCritical, DedupKey: "vuln:CVE-2021-44228:log4j-core:2.14.1",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
	})
	if err != nil {
		t.Fatal(err)
	}
	if view.Assessment.FindingID != "finding-sca" || view.Lifecycle.Status == "" {
		t.Fatalf("unexpected SCA SLA view: %+v", view)
	}
	current, err := store.Current(ctx, "tenant-a", "eng-sca", "finding-sca")
	if err != nil {
		t.Fatal(err)
	}
	if current.Assessment.ID != view.Assessment.ID {
		t.Fatalf("persisted assessment=%q, want %q", current.Assessment.ID, view.Assessment.ID)
	}
}

func TestConfigureWorkerSCASLAAssessor_DisabledLeavesSCAUnwired(t *testing.T) {
	store := memory.NewSLAStore()
	wiring := &workerSLASCAWiring{}
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	if err := configureWorkerSCASLAAssessor(config.Config{}, wiring, store, workerSLASCAClock{}, &workerSLASCAIDs{}); err != nil {
		t.Fatal(err)
	}
	if wiring.assessor != nil {
		t.Fatal("disabled worker wired an SCA SLA assessor")
	}
	policies, err := store.PolicyHistory(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 0 {
		t.Fatalf("disabled worker created SLA policy: %+v", policies)
	}
}
