package judgment

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestInvestigationClaimValidate(t *testing.T) {
	ok := InvestigationClaim{IncidentID: "inc-1", Tactic: TacticLateralMovement, Confidence: 70, Drivers: []string{"new_exec_paths", "network_fanout_spike"}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid claim rejected: %v", err)
	}
	if ok.Capability() != CapInvestigation {
		t.Fatalf("capability = %q, want investigation", ok.Capability())
	}
	if CapInvestigation.Gated() {
		t.Fatal("investigation must be UNGATED (advisory hypothesis, human-accepted)")
	}
	if !CapInvestigation.Valid() {
		t.Fatal("CapInvestigation must be a known capability")
	}
	for name, c := range map[string]InvestigationClaim{
		"no incident":  {Tactic: TacticBenign, Confidence: 10},
		"bad tactic":   {IncidentID: "inc-1", Tactic: "made_up", Confidence: 10},
		"bad conf":     {IncidentID: "inc-1", Tactic: TacticBenign, Confidence: 101},
		"prose driver": {IncidentID: "inc-1", Tactic: TacticBenign, Confidence: 10, Drivers: []string{"this is free prose"}},
		// A hypothesis with nothing behind it is the one this claim must not carry: at confidence 95 it
		// accuses an incident of a tactic while showing an analyst no signal to weigh.
		"no drivers":    {IncidentID: "inc-1", Tactic: TacticDataExfiltration, Confidence: 95},
		"empty drivers": {IncidentID: "inc-1", Tactic: TacticDataExfiltration, Confidence: 95, Drivers: []string{}},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestInvestigationClaimRoundTrips(t *testing.T) {
	data, err := MarshalClaim(InvestigationClaim{IncidentID: "inc-9", Tactic: TacticDataExfiltration, Confidence: 88, Drivers: []string{"network_fanout_spike"}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	c, err := UnmarshalClaim(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	ic, ok := c.(InvestigationClaim)
	if !ok || ic.Tactic != TacticDataExfiltration || ic.IncidentID != shared.ID("inc-9") || len(ic.Drivers) != 1 {
		t.Fatalf("round-trip wrong: %+v ok=%v", c, ok)
	}
}
