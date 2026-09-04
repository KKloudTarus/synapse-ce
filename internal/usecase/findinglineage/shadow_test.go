package findinglineage

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

func TestShadowProjectorProjectsManualFindingOnSnapshotWithReadsIndependent(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 4, 9, 0, 0, 0, time.UTC)
	lineageRepository := memory.NewFindingLineageRepository()
	lineage, err := NewService(lineageRepository, memory.NewTenantTransactionRunner(), &collectingAudit{}, fixedClock{now: now}, &sequenceIDs{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	findings := memory.NewFindingRepository()
	item, err := finding.NewManual("finding-shadow", "assessment-shadow", finding.ManualInput{Title: "manual issue", Severity: shared.SeverityHigh}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := findings.Upsert(shared.WithTenant(ctx, "tenant-shadow"), []finding.Finding{item}); err != nil {
		t.Fatal(err)
	}
	scaFinding := finding.Finding{
		ID: "finding-sca-shadow", EngagementID: item.EngagementID, Title: "dependency issue", Severity: shared.SeverityHigh,
		Status: finding.StatusOpen, Kind: finding.KindSCA, AdvisoryID: "CVE-2026-1234", ComponentFingerprint: "pkg:npm/example@1.0.0",
		DedupKey: "CVE-2026-1234|example@1.0.0", Version: 1, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
	if err := findings.Upsert(shared.WithTenant(ctx, "tenant-shadow"), []finding.Finding{scaFinding}); err != nil {
		t.Fatal(err)
	}
	projector, err := NewShadowProjector(lineage, memory.NewAssessmentCycleRepository(), memory.NewAssessmentSnapshotRepository(), findings, func(tenant string) bool {
		return tenant == "tenant-shadow"
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &assessmentsnapshot.Snapshot{TenantID: "tenant-shadow", ID: "snapshot-shadow", CycleID: "cycle-shadow", AssessmentID: item.EngagementID}
	if err := projector.AssessmentSnapshotFinalized(ctx, snapshot, "system:shadow"); err != nil {
		t.Fatal(err)
	}
	if err := projector.AssessmentSnapshotFinalized(ctx, snapshot, "system:shadow"); err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	observations, err := lineageRepository.ListObservationsBySnapshot(ctx, "tenant-shadow", "cycle-shadow", "snapshot-shadow")
	if err != nil || len(observations) != 2 {
		t.Fatalf("observations=%+v err=%v", observations, err)
	}
	bySource := map[string]string{}
	for _, observation := range observations {
		bySource[observation.SourceFindingID] = observation.FindingKind
	}
	if bySource[item.ID.String()] != string(ManualFindingNative) || bySource[scaFinding.ID.String()] != "vulnerability" {
		t.Fatalf("unexpected shadow kinds: %+v", bySource)
	}

	disabled := *snapshot
	disabled.TenantID, disabled.ID = "tenant-read-disabled", "snapshot-disabled"
	if err := projector.AssessmentSnapshotFinalized(ctx, &disabled, "system:shadow"); err != nil {
		t.Fatal(err)
	}
	disabledObservations, err := lineageRepository.ListObservationsBySnapshot(ctx, disabled.TenantID, disabled.CycleID, disabled.ID)
	if err != nil || len(disabledObservations) != 0 {
		t.Fatalf("disabled observations=%+v err=%v", disabledObservations, err)
	}
}
