package judgment

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"
)

func TestInvestigationClaimValidate(t *testing.T) {
	ok := InvestigationClaim{
		IncidentID: "inc-1", Tactic: TacticLateralMovement, Confidence: 70,
		Drivers: []string{"new_exec_paths", "network_fanout_spike"}, RelevantEventIDs: []shared.ID{"event-1"},
		SuggestedNextStep: NextRetroHuntSimilar,
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid claim rejected: %v", err)
	}
	if ok.Capability() != CapInvestigation {
		t.Fatalf("capability = %q, want investigation", ok.Capability())
	}
	if !CapInvestigation.Gated() {
		t.Fatal("investigation must require a distinct verifier's evidence-gated verdict")
	}
	if !CapInvestigation.Valid() {
		t.Fatal("CapInvestigation must be a known capability")
	}
	for name, c := range map[string]InvestigationClaim{
		"no incident":  {Tactic: TacticBenign, Confidence: 10},
		"bad tactic":   {IncidentID: "inc-1", Tactic: "made_up", Confidence: 10},
		"bad conf":     {IncidentID: "inc-1", Tactic: TacticBenign, Confidence: 101},
		"prose driver": {IncidentID: "inc-1", Tactic: TacticBenign, Confidence: 10, Drivers: []string{"this is free prose"}},
		"bad event":    {IncidentID: "inc-1", Tactic: TacticBenign, Confidence: 10, RelevantEventIDs: []shared.ID{""}},
		"bad next step": {IncidentID: "inc-1", Tactic: TacticBenign, Confidence: 10,
			SuggestedNextStep: "isolate_host"},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestInvestigationHypothesisNeedsDistinctVerifier(t *testing.T) {
	now := time.Unix(2_000_000, 0).UTC()
	j, err := New("judgment-1", "eng-1", CapInvestigation, SubjectIncident, "inc-1", InvestigationClaim{
		IncidentID: "inc-1", Tactic: TacticExecution, Confidence: 75,
	}, "agent:session-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Accept("analyst-1", now); err == nil {
		t.Fatal("a gated investigation hypothesis must reject the ungated acceptance path")
	}
	if _, err := j.ApplyVerdict(verdict.Verdict{Score: 90, Verifier: "agent:session-1", Rationale: "same actor"}, now); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("self-verification must fail closed, got %v", err)
	}
	confirmed, err := j.ApplyVerdict(verdict.Verdict{Score: 90, Verifier: "analyst-1", Rationale: "events corroborated"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if confirmed.State != StateConfirmed || !confirmed.Publishable() || confirmed.EvidenceScore != 90 {
		t.Fatalf("distinct above-threshold verdict did not confirm: %+v", confirmed)
	}
}

func TestInvestigationClaimRoundTrips(t *testing.T) {
	data, err := MarshalClaim(InvestigationClaim{
		IncidentID: "inc-9", Tactic: TacticDataExfiltration, Confidence: 88,
		RelevantEventIDs: []shared.ID{"event-9"}, SuggestedNextStep: NextInspectNetworkActivity,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	c, err := UnmarshalClaim(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	ic, ok := c.(InvestigationClaim)
	if !ok || ic.Tactic != TacticDataExfiltration || ic.IncidentID != shared.ID("inc-9") ||
		len(ic.RelevantEventIDs) != 1 || ic.SuggestedNextStep != NextInspectNetworkActivity {
		t.Fatalf("round-trip wrong: %+v ok=%v", c, ok)
	}
}
