package promotion

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func sastFlowJudgment(id string, correlated ...string) judgment.Judgment {
	links := make([]judgment.SASTFindingCorrelation, len(correlated))
	for i, f := range correlated {
		links[i] = judgment.SASTFindingCorrelation{FindingID: shared.ID(f), SinkSymbol: "pkg.Vuln", AffectedSymbol: "pkg.Vuln"}
	}
	return judgment.Judgment{
		ID: shared.ID(id), Capability: judgment.CapSAST, SubjectKind: judgment.SubjectDataFlow, SubjectID: shared.ID("flow-" + id),
		State: judgment.StateConfirmed, EvidenceScore: 100,
		Claim: judgment.SASTClaim{CWE: "CWE-89", Location: "app/x.go:1", Rule: "taint-sqli", Correlations: links},
	}
}

// TestIndexTaintExploitPaths: a PUBLISHABLE CapSAST taint-flow judgment correlated to a finding produces a
// taint escalation signal for it; a proposed (unpublishable) flow does not; the lowest judgment id wins per
// finding (deterministic, no churn); a non-SAST judgment is ignored.
func TestIndexTaintExploitPaths(t *testing.T) {
	proposed := sastFlowJudgment("z-proposed", "f1")
	proposed.State = judgment.StateProposed // not publishable -> must not signal
	js := []judgment.Judgment{
		sastFlowJudgment("j2", "f1"),
		sastFlowJudgment("j1", "f1", "f2"), // lower id: wins for f1, and also signals f2
		proposed,
		{ID: "r1", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "f1", State: judgment.StateConfirmed},
	}
	out := indexTaintExploitPaths(js)

	if sig, ok := out["f1"]; !ok || sig.ID != "j1" || sig.Kind != judgment.PromotionInputReachability {
		t.Fatalf("f1 must take the lowest-id publishable flow (j1), got %+v ok=%v", out["f1"], ok)
	}
	if sig, ok := out["f2"]; !ok || sig.ID != "j1" {
		t.Fatalf("f2 must be signaled by j1, got %+v ok=%v", out["f2"], ok)
	}
	if len(out) != 2 {
		t.Fatalf("only f1 and f2 have publishable correlated flows, got %d: %+v", len(out), out)
	}
}
