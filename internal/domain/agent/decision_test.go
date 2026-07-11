package agent

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var decNow = time.Unix(1_700_000_500, 0).UTC()

func TestNewStepDecision_Valid(t *testing.T) {
	d, err := NewStepDecision("s1", "e1", OutcomeExecuted, "act-1", "start_recon", "recon.subfinder", "app.acme.io", RiskActive, "auto",
		AgentReason{WhyTool: "enumerate"}, AgentEvidenceRefs{StepHash: "h1", AdmissionHash: "h2"}, "agent:s1", decNow)
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != DecisionStep || d.Outcome != OutcomeExecuted || d.Refs.StepHash != "h1" {
		t.Fatalf("unexpected decision: %+v", d)
	}
}

func TestNewStepDecision_Validation(t *testing.T) {
	if _, err := NewStepDecision("", "e1", OutcomeExecuted, "a", "t", "", "", "", "", AgentReason{}, AgentEvidenceRefs{}, "agent:s1", decNow); !errors.Is(err, shared.ErrValidation) {
		t.Error("missing session must fail")
	}
	if _, err := NewStepDecision("s1", "e1", StepOutcome("bogus"), "a", "t", "", "", "", "", AgentReason{}, AgentEvidenceRefs{}, "agent:s1", decNow); !errors.Is(err, shared.ErrValidation) {
		t.Error("unknown outcome must fail")
	}
	if _, err := NewStepDecision("s1", "e1", OutcomeRead, "", "t", "", "", "", "", AgentReason{}, AgentEvidenceRefs{}, "", decNow); !errors.Is(err, shared.ErrValidation) {
		t.Error("missing created_by must fail")
	}
}

func TestNewStopDecision_RequiresClosedReason(t *testing.T) {
	if _, err := NewStopDecision("s1", "e1", StopGoalReached, "done", "agent:s1", decNow); err != nil {
		t.Fatalf("valid stop: %v", err)
	}
	if _, err := NewStopDecision("s1", "e1", StopReason("freeform"), "x", "agent:s1", decNow); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("an unknown (free-prose) stop reason must be rejected – the set is closed")
	}
}

func TestStopReason_ClosedSet(t *testing.T) {
	for _, r := range []StopReason{StopGoalReached, StopMaxSteps, StopBudget, StopWallClock, StopError, StopPlanSettled} {
		if !r.valid() {
			t.Fatalf("%s should be valid", r)
		}
	}
	if StopReason("").valid() {
		t.Fatal("empty stop reason must be invalid")
	}
}
