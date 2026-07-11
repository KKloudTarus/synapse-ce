package httpapi

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/compliance"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type critiqueJudgments struct{ js []judgment.Judgment }

func (c *critiqueJudgments) List(context.Context, shared.ID) ([]judgment.Judgment, error) {
	return c.js, nil
}

func (c *critiqueJudgments) Verify(context.Context, string, shared.ID, shared.ID, int, string, int) (judgment.Judgment, error) {
	return judgment.Judgment{}, nil
}

func (c *critiqueJudgments) Accept(context.Context, string, shared.ID, shared.ID, int) (judgment.Judgment, error) {
	return judgment.Judgment{}, nil
}

func critJ(subj string, st judgment.State, score int, capb judgment.Capability, claim judgment.Claim) judgment.Judgment {
	return judgment.Judgment{
		Capability: capb, SubjectKind: judgment.SubjectFinding, SubjectID: shared.ID(subj),
		State: st, EvidenceScore: score, Claim: claim,
	}
}

// TestSuspectedFP: only a CONFIRMED, publishable, "refuted" CRITIQUE flags a finding as
// suspected-FP – proposed/non-refuted/other-capability judgments never do.
func TestSuspectedFP(t *testing.T) {
	rt := &Router{judgments: &critiqueJudgments{js: []judgment.Judgment{
		critJ("f1", judgment.StateConfirmed, 90, judgment.CapCritique, judgment.CritiqueClaim{Verdict: judgment.CritiqueRefuted, Driver: "not_reachable", Confidence: 90}),     // flagged
		critJ("f2", judgment.StateProposed, 0, judgment.CapCritique, judgment.CritiqueClaim{Verdict: judgment.CritiqueRefuted, Driver: "x", Confidence: 90}),                   // not publishable → ignored
		critJ("f3", judgment.StateConfirmed, 90, judgment.CapCritique, judgment.CritiqueClaim{Verdict: judgment.CritiqueSound, Driver: "x", Confidence: 90}),                   // not a refutation → ignored
		critJ("f4", judgment.StateConfirmed, 90, judgment.CapReachability, judgment.ReachabilityClaim{Reachable: judgment.NotReachable, Tier: judgment.Tier1, Confidence: 90}), // wrong capability → ignored
	}}}

	fp := rt.suspectedFP(context.Background(), "e1")
	if !fp["f1"] {
		t.Error("f1 (confirmed refuted critique) must be flagged suspected-FP")
	}
	if fp["f2"] || fp["f3"] || fp["f4"] {
		t.Errorf("only a confirmed refuted critique flags; got %v", fp)
	}
	// judgments disabled ⇒ nil set, no panic (best-effort, never breaks the finding list)
	if (&Router{}).suspectedFP(context.Background(), "e1") != nil {
		t.Error("nil judgments must yield a nil set")
	}
}

// TestFindingViewsAttachCompliance: the findings list annotates each finding with the curated
// compliance controls its CWE maps to – a mapped CWE carries its controls (alongside the suspected-FP
// flag), while an empty or unmapped CWE carries none (compliance.ControlsFor fail-open).
func TestFindingViewsAttachCompliance(t *testing.T) {
	list := []finding.Finding{
		{ID: "f1", CWE: "CWE-89"},    // SQL injection → mapped (OWASP A03 + PCI 6.2.4 + ISO A.8.28)
		{ID: "f2", CWE: ""},          // no CWE → no controls
		{ID: "f3", CWE: "CWE-99999"}, // unmapped → no controls
	}
	views := findingViews(list, map[shared.ID]bool{"f1": true})

	if len(views) != 3 {
		t.Fatalf("want 3 views, got %d", len(views))
	}
	if len(views[0].Compliance) == 0 {
		t.Error("f1 (CWE-89) must carry compliance controls")
	}
	if !views[0].SuspectedFP {
		t.Error("f1 must keep its suspected-FP flag alongside the compliance controls")
	}
	if !hasFramework(views[0].Compliance, "OWASP-2021") {
		t.Errorf("f1 controls must include an OWASP-2021 mapping, got %+v", views[0].Compliance)
	}
	if len(views[1].Compliance) != 0 || len(views[2].Compliance) != 0 {
		t.Errorf("empty/unmapped CWE must carry no controls; got f2=%v f3=%v", views[1].Compliance, views[2].Compliance)
	}
}

func hasFramework(cs []compliance.Control, fw string) bool {
	for _, c := range cs {
		if c.Framework == fw {
			return true
		}
	}
	return false
}
