package benchcore

import (
	"strings"
	"testing"
)

func controlManifest(t *testing.T) ClosureManifest {
	t.Helper()
	return sampleManifest(t)
}

// TestControlSuitesPassOnTheCurrentScorer: the scorer reproduces every hand-derived expected cell and is
// invariant to engine identity and order.
func TestControlSuitesPassOnTheCurrentScorer(t *testing.T) {
	results, receipts, err := RunControlSuites(controlManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %+v", results)
	}
	for i, r := range results {
		if !r.Passed {
			t.Fatalf("%s failed: %+v", r.ID, receipts[i].Outcomes)
		}
	}
	if len(receipts[0].Outcomes) != 15 || len(receipts[1].Outcomes) != 12 {
		t.Fatalf("outcome counts = %d, %d", len(receipts[0].Outcomes), len(receipts[1].Outcomes))
	}
}

// TestControlSuitesDetectAScorerChange: a fixture whose expected cell disagrees with the scorer fails the
// known-outcome suite, and a manifest that froze other expected outcomes fails before any case runs.
func TestControlSuitesDetectAScorerChange(t *testing.T) {
	fixture, _, err := KnownOutcomeFixture()
	if err != nil {
		t.Fatal(err)
	}
	fixture.Cases[1].ExpectedCells[0].EndToEnd.FalseNegatives = 0 // claim a missed positive is not a miss
	outcomes := knownOutcomes(fixture)
	if outcomes[1].Passed || !strings.Contains(outcomes[1].Detail, "got") {
		t.Fatalf("tampered expectation passed: %+v", outcomes[1])
	}
	m := controlManifest(t)
	m.ControlSuites[0].ExpectedOutcomeDigest = "sha256:other"
	results, _, err := RunControlSuites(m)
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Passed || !results[1].Passed {
		t.Fatalf("results = %+v", results)
	}
}

// TestScorecardIsInvalidWithoutPassingControls: a scorecard bound with failed controls is an invalid
// measurement and grades nothing, whatever the engine scored.
func TestScorecardIsInvalidWithoutPassingControls(t *testing.T) {
	m := controlManifest(t)
	m.ControlSuites[0].ExpectedOutcomeDigest = "sha256:other"
	receipt, err := NewRunStartReceipt(m, RunStart{ProfileID: "sca.v1", RunKey: "run", ImplementationCommit: "abc", RunnerIdentity: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	obs := []Observation{observation("owned", "s1", find("pkg:npm/a@1", "CVE-1"), find("pkg:npm/b@1", "CVE-2")), observation("owned", "s2")}
	card, err := BindScorecard(m, receipt, Binding{Engine: obs[0].Engine, Truth: sampleTruth(), Observations: obs})
	if err != nil {
		t.Fatal(err)
	}
	if card.Validity.Status != "invalid" || card.EngineGrade != GradeUngraded {
		t.Fatalf("validity %+v grade %s", card.Validity, card.EngineGrade)
	}
}
