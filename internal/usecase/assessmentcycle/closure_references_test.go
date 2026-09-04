package assessmentcycle

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	lineagedom "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	lineageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestClosureDecisionReaderBindsAndResolvesImmutableObservationAndRetest(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	tenantID, cycleID := shared.ID("tenant-reference"), shared.ID("cycle-reference")
	snapshots := memory.NewAssessmentSnapshotRepository()
	root := closureReferenceSnapshot(t, tenantID, cycleID, "assessment-root", "snapshot-root", now)
	final := closureReferenceSnapshot(t, tenantID, cycleID, "assessment-final", "snapshot-final", now.Add(time.Minute))
	if _, _, err := snapshots.CreateFinalizedCAS(ctx, root, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := snapshots.CreateFinalizedCAS(ctx, final, 0); err != nil {
		t.Fatal(err)
	}
	lineageRepository := memory.NewFindingLineageRepository()
	lineage, err := lineageuc.NewService(lineageRepository, memory.NewTenantTransactionRunner(), &relationshipAudit{}, relationshipClock{now: now}, &relationshipIDs{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lineage.CorrelateNativeManual(ctx, lineageuc.NativeManualInput{
		TenantID: tenantID, CycleID: cycleID, SnapshotID: final.ID, AssessmentID: final.AssessmentID,
		IdentityID: "identity-reference", FindingClass: lineageuc.ManualFindingNative, Actor: "reviewer",
		Observation: lineageuc.ObservationInput{ID: "observation-reference", SourceFindingID: "finding-reference", Severity: shared.SeverityHigh, ObservedAt: now, ScannerProvenance: lineagedom.ScannerProvenance{ToolName: "native-manual"}},
	}); err != nil {
		t.Fatal(err)
	}
	retests := memory.NewRetestRepository()
	retest, err := finding.NewRetest("retest-reference", final.AssessmentID, "finding-reference", finding.RetestRemediated, "sensitive detail remains in the immutable source only", "reviewer", now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := retests.Add(ctx, retest); err != nil {
		t.Fatal(err)
	}
	reader, err := NewClosureDecisionReader(lineageRepository, snapshots, retests, memory.NewSLAStore())
	if err != nil {
		t.Fatal(err)
	}
	query := ports.AssessmentClosureReferenceQuery{CycleID: cycleID, SnapshotIDs: []shared.ID{root.ID, final.ID}, VerificationIDs: []shared.ID{retest.ID}, AsOfAt: now.Add(3 * time.Minute)}
	references, err := reader.ListAssessmentClosureReferences(ctx, tenantID, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(references) != 2 || references[0].Kind != closureReferenceFindingObservation || references[1].Kind != closureReferenceRetestDecision {
		t.Fatalf("references=%+v", references)
	}
	for _, reference := range references {
		if strings.Contains(string(reference.Metadata), retest.Note) {
			t.Fatalf("sensitive retest note leaked into reference metadata: %s", reference.Metadata)
		}
		if err := reader.ResolveAssessmentClosureReference(ctx, tenantID, query, reference); err != nil {
			t.Fatalf("resolve %+v: %v", reference, err)
		}
	}
	tampered := references[1]
	tampered.ContentHash = strings.Repeat("f", 64)
	if err := reader.ResolveAssessmentClosureReference(ctx, tenantID, query, tampered); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("tampered reference error=%v", err)
	}
}

func closureReferenceSnapshot(t *testing.T, tenantID, cycleID, assessmentID, snapshotID shared.ID, now time.Time) *assessmentsnapshot.Snapshot {
	t.Helper()
	snapshot, err := assessmentsnapshot.NewFinalized(tenantID, snapshotID, cycleID, assessmentID, assessmentsnapshot.Boundary{Kind: assessmentcycle.BoundaryStandalone}, "request-"+snapshotID.String(), "system:test", now, []assessmentsnapshot.SelectedRun{{
		ID: "run-" + snapshotID.String(), ManifestHash: strings.Repeat("a", 64), Provenance: scanrun.ProvenanceLegacy, TerminalStatus: scanrun.StatusSucceeded,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
