package assessmentsnapshot

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
)

func TestSnapshotHashIsStableAcrossInputOrder(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	left, err := NewFinalized("tenant", "snapshot-a", "cycle", "assessment", Boundary{Kind: assessmentcycle.BoundaryStandalone}, "request-a", "operator", now, []SelectedRun{
		selectedRun("run-b", "producer-b", "secret", "sast"),
		selectedRun("run-a", "producer-a", "vulnerability", "license"),
	})
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewFinalized("tenant", "snapshot-b", "cycle", "assessment", Boundary{Kind: assessmentcycle.BoundaryStandalone}, "request-b", "operator", now.Add(time.Hour), []SelectedRun{
		selectedRun("run-a", "producer-a", "license", "vulnerability"),
		selectedRun("run-b", "producer-b", "sast", "secret"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if left.ContentHash != right.ContentHash {
		t.Fatalf("canonical hash changed across order/time/id variation: %s != %s", left.ContentHash, right.ContentHash)
	}
}

func TestCoverageAndDirectionalComparability(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	baseline, err := NewFinalized("tenant", "baseline", "cycle", "assessment-a", Boundary{Kind: assessmentcycle.BoundaryStandalone}, "request-a", "operator", now, []SelectedRun{selectedRun("run-a", "sca", "vulnerability")})
	if err != nil {
		t.Fatal(err)
	}
	current, err := NewFinalized("tenant", "current", "cycle", "assessment-b", Boundary{Kind: assessmentcycle.BoundaryStandalone}, "request-b", "operator", now, []SelectedRun{selectedRun("run-b", "sca", "vulnerability")})
	if err != nil {
		t.Fatal(err)
	}
	comparisons, err := Compare(baseline, current)
	if err != nil {
		t.Fatal(err)
	}
	if len(comparisons) != 1 || comparisons[0].Comparability != Comparable || comparisons[0].ReasonCode != CompareCompleteReevaluation {
		t.Fatalf("comparison = %+v", comparisons)
	}

	current.Dimensions[0].State = CoverageUnknown
	current.Dimensions[0].ReasonCode = ReasonRunFailed
	comparisons, err = Compare(baseline, current)
	if err != nil {
		t.Fatal(err)
	}
	if comparisons[0].Comparability != NotComparable || comparisons[0].ReasonCode != CompareCurrentUnknown {
		t.Fatalf("unknown current coverage upgraded: %+v", comparisons[0])
	}
}

func TestCoverageDecisionReasonTable(t *testing.T) {
	base := selectedRun("run", "sca", "vulnerability")
	baseLane := base.Lanes[0]
	cases := []struct {
		name   string
		run    SelectedRun
		lane   scanrun.Lane
		state  CoverageState
		reason string
	}{
		{"complete", base, baseLane, CoverageComplete, ReasonTrustedTerminalLane},
		{"legacy", func() SelectedRun { item := base; item.Provenance = scanrun.ProvenanceLegacy; return item }(), baseLane, CoverageUnknown, ReasonLegacyProvenance},
		{"run partial", func() SelectedRun { item := base; item.TerminalStatus = scanrun.StatusPartial; return item }(), baseLane, CoveragePartial, ReasonRunPartial},
		{"run failed", func() SelectedRun { item := base; item.TerminalStatus = scanrun.StatusFailed; return item }(), baseLane, CoverageUnknown, ReasonRunFailed},
		{"run cancelled", func() SelectedRun { item := base; item.TerminalStatus = scanrun.StatusCancelled; return item }(), baseLane, CoverageUnknown, ReasonRunCancelled},
		{"lane partial", base, func() scanrun.Lane { item := baseLane; item.TerminalStatus = scanrun.StatusPartial; return item }(), CoveragePartial, ReasonLanePartial},
		{"lane failed", base, func() scanrun.Lane { item := baseLane; item.TerminalStatus = scanrun.StatusFailed; return item }(), CoverageUnknown, ReasonLaneFailed},
		{"lane cancelled", base, func() scanrun.Lane { item := baseLane; item.TerminalStatus = scanrun.StatusCancelled; return item }(), CoverageUnknown, ReasonLaneCancelled},
		{"stage failed", base, func() scanrun.Lane {
			item := baseLane
			item.Stages = []scanrun.LaneStage{{StageKey: "scan", Status: scanrun.StageFailed, StartedAt: item.StartedAt}}
			return item
		}(), CoveragePartial, ReasonStageFailed},
		{"stage skipped", base, func() scanrun.Lane {
			item := baseLane
			item.Stages = []scanrun.LaneStage{{StageKey: "scan", Status: scanrun.StageSkipped, StartedAt: item.StartedAt}}
			return item
		}(), CoveragePartial, ReasonStageSkipped},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			state, reason := coverageDecision(testCase.run, testCase.lane)
			if state != testCase.state || reason != testCase.reason {
				t.Fatalf("coverage=(%s,%s), want (%s,%s)", state, reason, testCase.state, testCase.reason)
			}
		})
	}
}

func TestComparabilityReasonTable(t *testing.T) {
	base := Dimension{
		ExcludedScope: []string{"vendor/**"}, FindingKind: "vulnerability", IncludedScope: []string{"src/**"},
		Producer: "sca", State: CoverageComplete,
		Target: Target{Kind: scanrun.TargetRepository, SchemaVersion: 1, Canonical: "https://example.com/repo"},
		Versions: []Version{
			{Kind: scanrun.VersionRulePack, Name: "rules", Version: "1"},
			{Kind: scanrun.VersionProfile, Name: "profile", Version: "1"},
			{Kind: scanrun.VersionAdvisoryDB, Name: "advisories", Version: "1"},
			{Kind: scanrun.VersionScanner, Name: "scanner", Version: "1"},
		},
	}
	clone := func(dimension Dimension) Dimension {
		dimension.IncludedScope = append([]string(nil), dimension.IncludedScope...)
		dimension.ExcludedScope = append([]string(nil), dimension.ExcludedScope...)
		dimension.Versions = append([]Version(nil), dimension.Versions...)
		return dimension
	}
	setVersion := func(dimension *Dimension, kind scanrun.VersionKind, version string) {
		for index := range dimension.Versions {
			if dimension.Versions[index].Kind == kind {
				dimension.Versions[index].Version = version
				return
			}
		}
	}
	cases := []struct {
		name   string
		mutate func(*Dimension, *[]Dimension)
		state  Comparability
		reason string
	}{
		{"complete", func(_ *Dimension, _ *[]Dimension) {}, Comparable, CompareCompleteReevaluation},
		{"baseline incomplete", func(baseline *Dimension, _ *[]Dimension) { baseline.State = CoveragePartial }, PartiallyComparable, CompareBaselineIncomplete},
		{"current partial", func(_ *Dimension, current *[]Dimension) { (*current)[0].State = CoveragePartial }, PartiallyComparable, CompareCurrentPartial},
		{"current unknown", func(_ *Dimension, current *[]Dimension) { (*current)[0].State = CoverageUnknown }, NotComparable, CompareCurrentUnknown},
		{"scope changed", func(_ *Dimension, current *[]Dimension) { (*current)[0].IncludedScope = []string{"cmd/**"} }, PartiallyComparable, CompareScopeChanged},
		{"rule changed", func(_ *Dimension, current *[]Dimension) { setVersion(&(*current)[0], scanrun.VersionRulePack, "2") }, NotComparable, CompareRuleOrProfileChanged},
		{"profile changed", func(_ *Dimension, current *[]Dimension) { setVersion(&(*current)[0], scanrun.VersionProfile, "2") }, NotComparable, CompareRuleOrProfileChanged},
		{"advisory database changed", func(_ *Dimension, current *[]Dimension) {
			setVersion(&(*current)[0], scanrun.VersionAdvisoryDB, "2")
		}, PartiallyComparable, CompareAdvisoryDatabaseChanged},
		{"scanner changed", func(_ *Dimension, current *[]Dimension) { setVersion(&(*current)[0], scanrun.VersionScanner, "2") }, PartiallyComparable, CompareProducerVersionChanged},
		{"target mismatch", func(_ *Dimension, current *[]Dimension) { (*current)[0].Target.Canonical = "https://example.com/other" }, NotComparable, CompareTargetMismatch},
		{"dimension missing", func(_ *Dimension, current *[]Dimension) { *current = nil }, NotComparable, CompareCurrentDimensionMissing},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			baselineDimension := clone(base)
			currentDimensions := []Dimension{clone(base)}
			testCase.mutate(&baselineDimension, &currentDimensions)
			comparisons, err := Compare(
				&Snapshot{TenantID: "tenant", CycleID: "cycle", Lifecycle: LifecycleFinalized, Dimensions: []Dimension{baselineDimension}},
				&Snapshot{TenantID: "tenant", CycleID: "cycle", Lifecycle: LifecycleFinalized, Dimensions: currentDimensions},
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(comparisons) != 1 || comparisons[0].Comparability != testCase.state || comparisons[0].ReasonCode != testCase.reason {
				t.Fatalf("comparison=%+v, want (%s,%s)", comparisons, testCase.state, testCase.reason)
			}
		})
	}
}

func TestUntrustedNativeRunCannotFinalize(t *testing.T) {
	run := selectedRun("run", "sca", "vulnerability")
	run.Trusted = false
	if _, err := NewFinalized("tenant", "snapshot", "cycle", "assessment", Boundary{Kind: assessmentcycle.BoundaryStandalone}, "request", "operator", time.Now().UTC(), []SelectedRun{run}); err == nil {
		t.Fatal("untrusted native run produced a finalized snapshot")
	}
}

func selectedRun(id, producer string, findingKinds ...string) SelectedRun {
	finished := time.Date(2026, 8, 31, 11, 5, 0, 0, time.UTC)
	lane := scanrun.Lane{
		TenantID: "tenant", EngagementID: "assessment", ScanRunID: id,
		LaneKey: id + "-lane", Producer: producer, TerminalStatus: scanrun.StatusSucceeded,
		Target:                    scanrun.TargetIdentity{TargetKind: scanrun.TargetRepository, TargetIdentitySchemaVersion: 1, TargetIdentityCanonical: "https://example.com/repo", EvaluatedRevision: "0123456789abcdef0123456789abcdef01234567"},
		AuthoritativeFindingKinds: findingKinds, IncludedScope: []string{"src/**"}, ExcludedScope: []string{"vendor/**"},
		StartedAt: finished.Add(-time.Minute), FinishedAt: &finished, ResultRef: "result:" + id, EvidenceRef: "evidence:" + id,
		ResultSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestSchemaVersion: 1,
		Versions: []scanrun.LaneVersion{{VersionKind: scanrun.VersionScanner, Name: "sca", Version: "1"}, {VersionKind: scanrun.VersionRulePack, Name: "rules", Version: "1"}},
		Stages:   []scanrun.LaneStage{{StageKey: "scan", Status: scanrun.StageSucceeded, StartedAt: finished.Add(-time.Minute), FinishedAt: &finished}},
	}
	lane.SealedAt = &finished
	manifestHash, err := scanrun.ComputeManifestHash(lane)
	if err != nil {
		panic(err)
	}
	lane.ManifestHash = manifestHash
	return SelectedRun{ID: id, ManifestHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusSucceeded, Trusted: true, Lanes: []scanrun.Lane{lane}}
}
