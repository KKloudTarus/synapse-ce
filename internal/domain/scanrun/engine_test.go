package scanrun_test

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
)

func engineLane(t *testing.T) scanrun.Lane {
	t.Helper()
	target, err := scanrun.CanonicalizeRepositoryTarget("https://github.com/org/repo", "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04")
	if err != nil {
		t.Fatal(err)
	}
	return scanrun.Lane{
		TenantID: "tenant", EngagementID: "assessment", ScanRunID: "run", LaneKey: "sast", Producer: "sast",
		Target: target, TerminalStatus: scanrun.StatusSucceeded, AuthoritativeFindingKinds: []string{"sast"},
		StartedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), ManifestSchemaVersion: 1,
	}
}

func TestHistoricalManifestGolden(t *testing.T) {
	lane := engineLane(t)
	const want = "94880c365c27586b86de6c54b3440a5a384fb753d59d15eba9ee7dff5b6cb21f"
	for _, version := range []int{1, 0} {
		lane.ManifestSchemaVersion = version
		got, err := scanrun.ComputeManifestHash(lane)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("version %d historic hash = %s, want %s", version, got, want)
		}
	}
}

func TestEngineCoverageRequiredPlan(t *testing.T) {
	complete := scanrun.EngineOutcome{Engine: "sast", Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Required: true, Counts: map[scanrun.EngineMeasure]int64{scanrun.MeasureFindings: 0}}
	for _, tt := range []struct {
		name     string
		outcomes []scanrun.EngineOutcome
		want     scanrun.CoverageStatus
	}{
		{"historical missing", nil, scanrun.CoverageUnknown},
		{"zero findings", []scanrun.EngineOutcome{complete}, scanrun.CoverageComplete},
		{"truncated", []scanrun.EngineOutcome{{Engine: "sast", Execution: scanrun.EngineCompleted, Coverage: scanrun.CoveragePartial, Reason: scanrun.ReasonTruncated, Required: true}}, scanrun.CoveragePartial},
		{"deadline", []scanrun.EngineOutcome{{Engine: "sast", Execution: scanrun.EngineTimedOut, Coverage: scanrun.CoverageUnknown, Reason: scanrun.ReasonDeadlineExceeded, Required: true}}, scanrun.CoveragePartial},
		{"later not started", []scanrun.EngineOutcome{{Engine: "secrets", Execution: scanrun.EngineNotRun, Coverage: scanrun.CoverageUnknown, Reason: scanrun.ReasonBudgetExhausted, Required: true}}, scanrun.CoverageUnknown},
		{"optional disabled", []scanrun.EngineOutcome{complete, {Engine: "history", Execution: scanrun.EngineNotRun, Coverage: scanrun.CoverageNotApplicable, Reason: scanrun.ReasonDisabled}}, scanrun.CoverageComplete},
		{"unavailable required", []scanrun.EngineOutcome{complete, {Engine: "iac", Execution: scanrun.EngineNotRun, Coverage: scanrun.CoverageUnknown, Reason: scanrun.ReasonUnavailable, Required: true}}, scanrun.CoverageUnknown},
		{"untrusted duplicate", []scanrun.EngineOutcome{complete, complete}, scanrun.CoverageUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := scanrun.ComputeEngineCoverage(tt.outcomes)
			if got.Status != tt.want {
				t.Fatalf("coverage = %+v, want %s", got, tt.want)
			}
		})
	}
}

func TestEngineOutcomeRejectsFalseCoverage(t *testing.T) {
	for _, outcome := range []scanrun.EngineOutcome{
		{Engine: "sast", Execution: scanrun.EngineNotRun, Coverage: scanrun.CoverageComplete, Required: true},
		{Engine: "sast", Execution: scanrun.EngineNotRun, Coverage: scanrun.CoverageNotApplicable, Required: true},
		{Engine: "sast", Execution: scanrun.EngineTimedOut, Coverage: scanrun.CoverageUnknown},
		{Engine: "sast", Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Reason: "raw tool stderr"},
		{Engine: "sast", Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Reason: scanrun.ReasonUnavailable},
		{Engine: "sast", Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Counts: map[scanrun.EngineMeasure]int64{scanrun.MeasureFilesUnscanned: 1}},
		{Engine: "sast", Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Counts: map[scanrun.EngineMeasure]int64{"raw source": 1}},
		{Engine: "sast", Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Counts: map[scanrun.EngineMeasure]int64{scanrun.MeasureFindings: -1}},
	} {
		if err := outcome.Validate(); err == nil {
			t.Fatalf("accepted false outcome %+v", outcome)
		}
	}
}

func TestEngineFactsAreCanonicalAndSealed(t *testing.T) {
	lane := engineLane(t)
	lane.ManifestSchemaVersion = scanrun.CurrentManifestSchemaVersion
	lane.EngineOutcomes = []scanrun.EngineOutcome{
		{Engine: "secrets", Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Required: true},
		{Engine: "sast", Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Required: true, Counts: map[scanrun.EngineMeasure]int64{scanrun.MeasureFindings: 0}},
	}
	baseline, err := scanrun.ComputeManifestHash(lane)
	if err != nil {
		t.Fatal(err)
	}
	reversed := lane
	reversed.EngineOutcomes = []scanrun.EngineOutcome{lane.EngineOutcomes[1], lane.EngineOutcomes[0]}
	if got, err := scanrun.ComputeManifestHash(reversed); err != nil || got != baseline {
		t.Fatalf("ordering changed hash: %s %v", got, err)
	}
	for _, mutate := range []func(*scanrun.EngineOutcome){
		func(o *scanrun.EngineOutcome) { o.Engine = "iac" },
		func(o *scanrun.EngineOutcome) { o.Required = false },
		func(o *scanrun.EngineOutcome) {
			o.Coverage = scanrun.CoveragePartial
			o.Reason = scanrun.ReasonTruncated
		},
		func(o *scanrun.EngineOutcome) {
			o.Execution = scanrun.EngineTimedOut
			o.Coverage = scanrun.CoveragePartial
			o.Reason = scanrun.ReasonDeadlineExceeded
		},
		func(o *scanrun.EngineOutcome) { o.Counts[scanrun.MeasureFindings] = 1 },
	} {
		changed := lane
		changed.EngineOutcomes = scanrun.CloneEngineOutcomes(lane.EngineOutcomes)
		mutate(&changed.EngineOutcomes[1])
		got, err := scanrun.ComputeManifestHash(changed)
		if err != nil || got == baseline {
			t.Fatalf("engine fact not sealed: %s %v", got, err)
		}
	}
	canonical, err := scanrun.CanonicalEngineOutcomes(lane.EngineOutcomes)
	if err != nil {
		t.Fatal(err)
	}
	canonical[0].Counts[scanrun.MeasureFindings] = 42
	if lane.EngineOutcomes[1].Counts[scanrun.MeasureFindings] != 0 {
		t.Fatal("canonicalization aliases caller measurements")
	}
	lane.ManifestSchemaVersion = 1
	if _, err := scanrun.ComputeManifestHash(lane); err == nil {
		t.Fatal("accepted engine facts in an unsigned historic schema")
	}
}

func TestNativeProofRejectsIncompleteEngineFacts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		outcome scanrun.EngineOutcome
		want    bool
	}{
		{"complete zero findings", scanrun.EngineOutcome{Engine: "sast", Required: true, Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete}, true},
		{"truncated", scanrun.EngineOutcome{Engine: "sast", Required: true, Execution: scanrun.EngineCompleted, Coverage: scanrun.CoveragePartial, Reason: scanrun.ReasonTruncated}, false},
		{"unavailable", scanrun.EngineOutcome{Engine: "sast", Required: true, Execution: scanrun.EngineNotRun, Coverage: scanrun.CoverageUnknown, Reason: scanrun.ReasonUnavailable}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lane := engineLane(t)
			lane.ManifestSchemaVersion = scanrun.CurrentManifestSchemaVersion
			lane.EngineOutcomes = []scanrun.EngineOutcome{tc.outcome}
			lane.SealedAt = &lane.StartedAt
			var err error
			lane.ManifestHash, err = scanrun.ComputeManifestHash(lane)
			if err != nil {
				t.Fatal(err)
			}
			hash, err := scanrun.ComputeRunManifestHash([]scanrun.Lane{lane})
			if err != nil {
				t.Fatal(err)
			}
			run := scanrun.ScanRun{TenantID: lane.TenantID, EngagementID: lane.EngagementID, ID: lane.ScanRunID, Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusSucceeded, ManifestSchemaVersion: lane.ManifestSchemaVersion, ManifestHash: hash, SealedAt: lane.SealedAt, Lanes: []scanrun.Lane{lane}}
			if run.IsCompleteCoverage() != tc.want {
				t.Fatalf("sealed proof complete=%t, want %t", run.IsCompleteCoverage(), tc.want)
			}
			lane.EngineOutcomes[0].Required = !lane.EngineOutcomes[0].Required
			run.Lanes = []scanrun.Lane{lane}
			if run.IsCompleteCoverage() {
				t.Fatal("accepted engine metadata tampering without resealing")
			}
		})
	}
}
