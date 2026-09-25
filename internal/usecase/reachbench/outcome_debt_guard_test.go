package reachbench

import (
	"strings"
	"testing"
)

func TestSuccessorOutcomeDebtGuardRejectsNegativeRegressionDespiteC2Gain(t *testing.T) {
	input := fixtureInput(t)
	for index := range input.Observations {
		if input.Observations[index].CaseID == "go-conditional" {
			input.Observations[index].Outcome = OutcomeNoAnalysis
		}
	}
	baseline, err := EvaluateMeasurement(input)
	if err != nil {
		t.Fatalf("EvaluateMeasurement(baseline): %v", err)
	}
	candidate := candidateInput(t, input, baseline)
	for index := range candidate.Observations {
		switch candidate.Observations[index].CaseID {
		case "go-conditional":
			candidate.Observations[index].Outcome = OutcomeConditionallyReachable
		case "go-unreached":
			candidate.Observations[index].Outcome = OutcomeNoAnalysis
		}
	}
	report, err := EvaluateMeasurement(candidate)
	if err != nil {
		t.Fatalf("EvaluateMeasurement(candidate): %v", err)
	}
	if !strictlyGreaterC2(report.C2, baseline.C2) || containsReason(report.Candidate.Reasons, "outcome debt regression") {
		t.Fatalf("v2 did not expose the aggregate-only counterexample: baseline=%+v candidate=%+v", baseline.C2, report.Candidate)
	}

	reasons := checkSuccessorOutcomeDebt(report, &baseline, input.Oracle)
	if !containsReason(reasons, "outcome debt regression at go/source_tier2/api/go-unreached") {
		t.Fatalf("negative regression was allowed to offset C2 gain: %v", reasons)
	}
}

func TestSuccessorOutcomeDebtGuardAllowsReviewedNoAnalysisDebt(t *testing.T) {
	input := fixtureInput(t)
	for index := range input.Observations {
		if input.Observations[index].CaseID == "go-conditional" {
			input.Observations[index].Outcome = OutcomeNoAnalysis
		}
	}
	baseline, err := EvaluateMeasurement(input)
	if err != nil {
		t.Fatalf("EvaluateMeasurement(baseline): %v", err)
	}
	candidate := candidateInput(t, input, baseline)
	report, err := EvaluateMeasurement(candidate)
	if err != nil {
		t.Fatalf("EvaluateMeasurement(candidate): %v", err)
	}
	if reasons := checkSuccessorOutcomeDebt(report, &baseline, input.Oracle); len(reasons) != 0 {
		t.Fatalf("unchanged reviewed no_analysis debt was rejected: %v", reasons)
	}
}

func TestSuccessorOutcomeDebtGuardFailsClosedWithoutBaseline(t *testing.T) {
	reasons := checkSuccessorOutcomeDebt(MeasurementReport{}, nil, ReachabilityOracle{})
	if !containsReason(reasons, "successor candidate acceptance requires replayed baseline context") {
		t.Fatalf("missing replayed baseline context was accepted: %v", reasons)
	}
}

func TestSuccessorLowLevelRatchetCheckCannotBypassBaselineContext(t *testing.T) {
	candidate := MeasurementReport{Policy: ArtifactReference{ID: goBinaryVersionedProfileID + "-policy"}}
	reasons := CheckCandidateAcceptance(candidate, CandidateRatchet{}, ExceptionManifest{})
	if !containsReason(reasons, "successor acceptance requires baseline and oracle context") {
		t.Fatalf("low-level ratchet check bypassed successor context: %v", reasons)
	}
}

func TestPendingSuccessorProfileCannotBecomeAccepted(t *testing.T) {
	input, err := GoBinaryVersionedBaselineMeasurementInput()
	if err != nil {
		t.Fatalf("GoBinaryVersionedBaselineMeasurementInput: %v", err)
	}
	baseline, err := EvaluateMeasurement(input)
	if err != nil {
		t.Fatalf("EvaluateMeasurement(baseline): %v", err)
	}
	candidate := candidateInput(t, input, baseline)
	report, err := EvaluateMeasurement(candidate)
	if err != nil {
		t.Fatalf("EvaluateMeasurement(candidate): %v", err)
	}
	if report.Candidate.Accepted || !containsReason(report.Candidate.Reasons, "successor reachability profile is pending independent review") {
		t.Fatalf("pending successor profile became acceptance authority: %+v", report.Candidate)
	}
}

func TestSuccessorOutcomeDebtGuardRejectsMixedProfileTuple(t *testing.T) {
	input := fixtureInput(t)
	input.Policy.ID = goBinaryVersionedProfileID + "-policy"
	reasons := successorCandidateAcceptanceReasons(input, MeasurementReport{})
	if !containsReason(reasons, "successor candidate acceptance does not match the registered profile") {
		t.Fatalf("mixed tuple claiming successor authority was accepted: %v", reasons)
	}
}

func containsReason(reasons []string, wanted string) bool {
	for _, reason := range reasons {
		if strings.Contains(reason, wanted) {
			return true
		}
	}
	return false
}
