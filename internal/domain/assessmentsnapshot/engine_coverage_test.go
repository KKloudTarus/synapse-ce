package assessmentsnapshot

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
)

func TestEngineCoverageCannotUpgradeSnapshotDimension(t *testing.T) {
	run := selectedRun("run", "sca", "vulnerability")
	for _, tc := range []struct {
		name     string
		outcomes []scanrun.EngineOutcome
		state    CoverageState
		reason   string
	}{
		{"historical native proof", nil, CoverageComplete, ReasonTrustedTerminalLane},
		{"complete zero findings", []scanrun.EngineOutcome{{Engine: "sast", Required: true, Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete}}, CoverageComplete, ReasonTrustedTerminalLane},
		{"truncated", []scanrun.EngineOutcome{{Engine: "sast", Required: true, Execution: scanrun.EngineCompleted, Coverage: scanrun.CoveragePartial, Reason: scanrun.ReasonTruncated}}, CoveragePartial, ReasonEnginePartial},
		{"required unavailable", []scanrun.EngineOutcome{{Engine: "sast", Required: true, Execution: scanrun.EngineNotRun, Coverage: scanrun.CoverageUnknown, Reason: scanrun.ReasonUnavailable}}, CoverageUnknown, ReasonEngineUnknown},
		{"invalid claim", []scanrun.EngineOutcome{{Engine: "sast", Required: true, Execution: scanrun.EngineNotRun, Coverage: scanrun.CoverageComplete}}, CoverageUnknown, ReasonEngineUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lane := run.Lanes[0]
			lane.EngineOutcomes = tc.outcomes
			state, reason := coverageDecision(run, lane)
			if state != tc.state || reason != tc.reason {
				t.Fatalf("coverage %s/%s, want %s/%s", state, reason, tc.state, tc.reason)
			}
		})
	}
}
