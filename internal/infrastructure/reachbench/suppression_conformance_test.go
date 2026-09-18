package reachbench

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

func TestSuppressionConformanceUsesIsolatedNormalCoordinators(t *testing.T) {
	factories := map[string]suppressionCoordinatorFactory{
		"go/source_tier2":           newGoSuppressionCoordinator,
		"python/import":             newPythonImportSuppressionCoordinator,
		"python/semantic":           newPythonSemanticSuppressionCoordinator,
		"dotnet/build_aware_import": newDotNetSuppressionCoordinator,
	}
	specs, err := suppressionConformanceSpecs()
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range specs {
		spec := spec
		t.Run(spec.cohortID+"/"+spec.modeID, func(t *testing.T) {
			cell := suppressionConformanceCell(spec)
			subjects := []ports.ReachabilitySubject{{FindingID: shared.ID(cell.SubjectID), PackagePURL: "pkg:generic/reachbench@1", Symbols: []string{"affected.symbol"}}}
			analysis := &reachability.Analysis{
				Entrypoints: []string{"fixture://root/entry"},
				Results:     []reachability.Result{{Symbol: "affected.symbol", Reachable: false}},
			}
			control, err := captureSuppressionConformance(context.Background(), CaptureRequest{Cell: cell}, execution{
				analyzer: &recordingAnalyzer{symbols: []string{"affected.symbol"}, result: analysis},
				subjects: subjects, conformanceCoordinator: factories[spec.cohortID+"/"+spec.modeID],
			})
			if err != nil {
				t.Fatal(err)
			}
			if !control.Passed || control.FailureCode != "" || control.Judgment == nil {
				t.Fatalf("conformance control = %+v, want pass", control)
			}
			if !control.Judgment.Claim.SuppressesFinding() || control.Judgment.Claim.Tier != spec.tier {
				t.Fatalf("conformance judgment = %+v, want suppressing tier %s", control.Judgment.Claim, spec.tier)
			}

			lifecycle, err := newCaptureLifecycle()
			if err != nil {
				t.Fatal(err)
			}
			outcome := measurement.OutcomePresentUnreached
			observation, err := (&ProductionCapture{}).observation(context.Background(), CaptureRequest{
				Cell: cell, Analyzer: RevisionIdentity{Commit: "candidate", Tree: "tree"},
			}, lifecycle, execution{invoked: true, coverage: completeCoverage(), analyzer: &recordingAnalyzer{result: analysis}, outcome: &outcome})
			if err != nil {
				t.Fatal(err)
			}
			if observation.Suppression.Claim != measurement.SuppressionNone || len(observation.Suppression.Effects) != 0 {
				t.Fatalf("primary observation fabricated suppression: %+v", observation.Suppression)
			}
			judgments, err := lifecycle.judgments.List(context.Background(), productionCaptureEngagementID)
			if err != nil {
				t.Fatal(err)
			}
			if len(judgments) != 0 {
				t.Fatalf("isolated conformance leaked %d judgments into the raise-only lifecycle", len(judgments))
			}
		})
	}
}

func TestSuppressionConformanceFailsClosedForIncompleteOrPositiveAnalysis(t *testing.T) {
	specs, err := suppressionConformanceSpecs()
	if err != nil {
		t.Fatal(err)
	}
	var semantic suppressionConformanceSpec
	for _, spec := range specs {
		if spec.cohortID == "python" && spec.modeID == "semantic" {
			semantic = spec
		}
	}
	cell := suppressionConformanceCell(semantic)
	subjects := []ports.ReachabilitySubject{{FindingID: shared.ID(cell.SubjectID), Symbols: []string{"affected.symbol"}}}
	for name, analysis := range map[string]*reachability.Analysis{
		"reachable":      {Entrypoints: []string{"entry"}, Results: []reachability.Result{{Symbol: "affected.symbol", Reachable: true, Path: []string{"entry", "affected.symbol"}}}},
		"no entrypoints": {Results: []reachability.Result{{Symbol: "affected.symbol", Reachable: false}}},
		"blind":          {Entrypoints: []string{"entry"}, Results: []reachability.Result{{Symbol: "affected.symbol", Reachable: false}}, BlindConstructs: []string{"dynamic_dispatch"}},
	} {
		t.Run(name, func(t *testing.T) {
			control, err := captureSuppressionConformance(context.Background(), CaptureRequest{Cell: cell}, execution{
				analyzer: &recordingAnalyzer{symbols: []string{"affected.symbol"}, result: analysis}, subjects: subjects,
				conformanceCoordinator: newPythonSemanticSuppressionCoordinator,
			})
			if err != nil {
				t.Fatal(err)
			}
			if control.Passed || control.FailureCode == "" {
				t.Fatalf("control = %+v, want closed failure", control)
			}
		})
	}
}

func suppressionConformanceCell(spec suppressionConformanceSpec) ExecutionCell {
	return ExecutionCell{
		CaseID: spec.caseID, CohortID: spec.cohortID, ModeID: spec.modeID,
		BindingID: "api", AnalyzerID: "candidate", SubjectID: "reachbench-control-finding",
		Configuration: measurement.ArtifactReference{ID: "config", Digest: benchmark.SHA256Digest([]byte("config"))},
		Fixture:       measurement.ArtifactReference{ID: "fixture", Digest: benchmark.SHA256Digest([]byte("fixture"))},
		BoundaryID:    "boundary",
	}
}

func TestSuppressionConformancePlanRequiresExactlyFourUniqueControls(t *testing.T) {
	specs, err := suppressionConformanceSpecs()
	if err != nil {
		t.Fatal(err)
	}
	cells := make([]ExecutionCell, 0, len(specs))
	for _, spec := range specs {
		cells = append(cells, suppressionConformanceCell(spec))
	}
	selected, err := suppressionConformancePlan(cells)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 4 {
		t.Fatalf("selected controls = %d, want 4", len(selected))
	}
	for name, invalid := range map[string][]ExecutionCell{
		"missing":   cells[:len(cells)-1],
		"duplicate": append(append([]ExecutionCell(nil), cells...), cells[0]),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := suppressionConformancePlan(invalid); err == nil {
				t.Fatal("invalid conformance plan was accepted")
			}
		})
	}
}

func TestSuppressionConformanceAuthorityInventoryIsExact(t *testing.T) {
	specs, err := suppressionConformanceSpecs()
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 4 {
		t.Fatalf("eligible conformance controls = %d, want 4", len(specs))
	}
	for _, spec := range specs {
		if spec.proposer == "" || spec.verifier == "" || spec.proposer == spec.verifier {
			t.Fatalf("invalid actor pair for %s/%s: %q/%q", spec.cohortID, spec.modeID, spec.proposer, spec.verifier)
		}
		if spec.tier != judgment.Tier1 && spec.tier != judgment.Tier2 {
			t.Fatalf("invalid tier for %s/%s: %s", spec.cohortID, spec.modeID, spec.tier)
		}
	}
}
