package httpapi

import (
	"strings"

	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	snapshotdom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	snapshotuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentsnapshot"
)

// seedEngmiscSnapshots gives the snapshot routes a tenantA snapshot whose response carries a marker.
//
// The harness already wires a real snapshot service, but its snapshot is attributed to the generic
// principal "p", so the list answers tenantA a body that names nothing of tenantA's and the sweep can
// only call that route vacuous. The repositories behind the harness's service are not reachable from a
// seed, so this builds a second service of the same shape over its own repositories, keeps the
// snapshot id "snapshot-A" the hand-written cross-tenant cases already address, and attributes it to
// the marker. The service reads the engagement through the shared repository, so the tenant check of
// the engagement still comes from the world the route table is built against.
func seedEngmiscSnapshots(w *harnessWorld) {
	ctx := engmiscTenantCtx()
	cycles := memory.NewAssessmentCycleRepository()
	snapshots := memory.NewAssessmentSnapshotRepository()
	transactions := memory.NewTenantTransactionRunner()

	cycle, err := cycledom.NewAssessmentCycle("engmisc-cycle", "tenantA", "cycle "+engmiscMarker, cycledom.BoundaryStandalone, "", "", engmiscEngagement, engmiscMarker, engmiscNow)
	if err != nil {
		w.t.Fatalf("build snapshot cycle: %v", err)
	}
	member, err := cycledom.NewInitialMember("tenantA", cycle.ID, engmiscEngagement, engmiscMarker, engmiscNow)
	if err != nil {
		w.t.Fatalf("build snapshot cycle member: %v", err)
	}
	if err := cycles.CreateCycle(ctx, cycle); err != nil {
		w.t.Fatalf("store snapshot cycle: %v", err)
	}
	if err := cycles.CreateMember(ctx, member); err != nil {
		w.t.Fatalf("store snapshot cycle member: %v", err)
	}

	snapshot, err := snapshotdom.NewFinalized("tenantA", "snapshot-A", cycle.ID, engmiscEngagement,
		snapshotdom.Boundary{Kind: cycledom.BoundaryStandalone}, "legacy-"+engmiscMarker, engmiscMarker, engmiscNow,
		[]snapshotdom.SelectedRun{{
			ID: "legacy-run-A", ManifestHash: strings.Repeat("a", 64), Provenance: scanrun.ProvenanceLegacy, TerminalStatus: scanrun.StatusUnknown,
		}})
	if err != nil {
		w.t.Fatalf("build assessment snapshot: %v", err)
	}
	if _, _, err := snapshots.CreateLegacyProjection(ctx, snapshot); err != nil {
		w.t.Fatalf("store assessment snapshot: %v", err)
	}

	service, err := snapshotuc.NewService(snapshots, cycles, w.engagements, memory.NewScanRunStore(), transactions, &engmiscIDs{}, engmiscClock{}, &harnessAudit{})
	if err != nil {
		w.t.Fatalf("assessment snapshot service: %v", err)
	}
	w.rt.SetAssessmentSnapshots(service)
}
