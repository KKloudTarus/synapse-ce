package rulepack

import (
	"testing"

	rulepackdomain "github.com/KKloudTarus/synapse-ce/internal/domain/rulepack"
)

func TestATTACKCoverageThresholdIsRespected(t *testing.T) {
	p := gatePack(t)
	p.ATTACKMappings = append(p.ATTACKMappings, rulepackdomain.ATTACKMapping{RuleID: "det.test", TechniqueID: "T1105"})
	var err error
	p.Digest, err = rulepackdomain.ComputeDigest(p)
	if err != nil {
		t.Fatal(err)
	}
	in := goodGateInput(p)
	in.Policy.MinimumATTACKCoverageBPS = 5_000
	in.Purple = in.Purple[:1]
	report, err := Evaluate(p, in)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Stages[5].Pass || report.ATTACKCoverageBPS != 5_000 {
		t.Fatalf("50%% coverage should satisfy a 50%% policy: %+v", report.Stages[5])
	}

	in.Policy.MinimumATTACKCoverageBPS = 10_000
	report, err = Evaluate(p, in)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stages[5].Pass {
		t.Fatal("50% coverage must fail a 100% policy")
	}
}
