package reachproof

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

// blindConstructs is the suppression-discipline surface EPIC #1042 #1065 hardens against: an analysis blind
// to any of these near the reachable code cannot soundly prove a symbol UNreachable, so a not_reachable that
// hits one must never suppress a finding (never become an OpenVEX not_affected).
var blindConstructs = []string{"reflection", "dependency_injection", "dynamic_dispatch", "cgo", "generated_code"}

func tierCoord(t *testing.T, tier judgment.ReachabilityTier, a analyzer, rec recorder) *Coordinator {
	t.Helper()
	c, err := NewCoordinatorForTier(a, rec, &fakeAudit{}, fakeClock{}, tier)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func recordOne(t *testing.T, c *Coordinator) *fakeRecorder {
	t.Helper()
	rec, ok := c.recorder.(*fakeRecorder)
	if !ok {
		t.Fatal("coordinator recorder is not a *fakeRecorder")
	}
	if _, err := c.Record(context.Background(), "eng-1", "/work",
		[]ports.ReachabilitySubject{{FindingID: "f1", Symbols: []string{"dep.vuln"}}}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	return rec
}

// TestAdversarialFN_BlindConstructNeverSuppresses is the core cross-engine guard: for every blind construct,
// on both a suppression-capable Tier-1 (import) and Tier-2 (call-graph, with entry points) engine, a
// not_reachable verdict on that blind surface must NOT be a suppressing verdict. The suite FAILS if any
// minted claim reports SuppressesFinding()==true while a blind construct is present.
func TestAdversarialFN_BlindConstructNeverSuppresses(t *testing.T) {
	for _, bc := range blindConstructs {
		bc := bc
		t.Run("per-symbol/"+bc, func(t *testing.T) {
			for _, tier := range []judgment.ReachabilityTier{judgment.Tier1, judgment.Tier2} {
				rec := &fakeRecorder{}
				a := fakeAnalyzer{res: []reachability.Result{{Symbol: "dep.vuln", Reachable: false, BlindConstructs: []string{bc}}}}
				got := recordOne(t, tierCoord(t, tier, a, rec))
				assertNoSuppression(t, got, tier, bc)
			}
		})
		t.Run("analysis-wide/"+bc, func(t *testing.T) {
			for _, tier := range []judgment.ReachabilityTier{judgment.Tier1, judgment.Tier2} {
				rec := &fakeRecorder{}
				a := fakeAnalyzer{res: []reachability.Result{{Symbol: "dep.vuln", Reachable: false}}, blind: []string{bc}}
				got := recordOne(t, tierCoord(t, tier, a, rec))
				assertNoSuppression(t, got, tier, bc)
			}
		})
	}
}

func assertNoSuppression(t *testing.T, rec *fakeRecorder, tier judgment.ReachabilityTier, bc string) {
	t.Helper()
	// The mint path must actually run: a suppression-capable engine mints exactly one not_reachable claim
	// here, so an empty proposes list would be a vacuous pass (the whole point is that the minted claim does
	// NOT suppress). This guards against the test silently exercising nothing.
	var notReachable []proposeCall
	for _, p := range rec.proposes {
		if p.claim.Reachable == judgment.NotReachable {
			notReachable = append(notReachable, p)
		}
	}
	if len(notReachable) != 1 {
		t.Fatalf("tier %s must mint exactly one not_reachable claim to exercise the suppression path, got %d (%+v)", tier, len(notReachable), rec.proposes)
	}
	claim := notReachable[0].claim
	if len(claim.BlindConstructs) == 0 {
		t.Fatalf("tier %s minted a not_reachable without recording the %q blind construct: %+v", tier, bc, claim)
	}
	if claim.SuppressesFinding() {
		t.Fatalf("tier %s minted a SUPPRESSING not_reachable on a %q surface (false-negative risk): %+v", tier, bc, claim)
	}
}

// TestAdversarialFN_CleanProofStillSuppresses is the discrimination control: WITHOUT a blind construct, a
// complete Tier-1 not_reachable IS a sound suppression. This proves the suite fails for the right reason (a
// blind construct), not because suppression is universally disabled.
func TestAdversarialFN_CleanProofStillSuppresses(t *testing.T) {
	rec := &fakeRecorder{}
	a := fakeAnalyzer{res: []reachability.Result{{Symbol: "dep.vuln", Reachable: false}}}
	got := recordOne(t, tierCoord(t, judgment.Tier1, a, rec))
	if len(got.proposes) != 1 {
		t.Fatalf("want 1 minted not_reachable, got %d", len(got.proposes))
	}
	if !got.proposes[0].claim.SuppressesFinding() {
		t.Fatalf("a clean Tier-1 not_reachable must suppress; suite would never detect a regression otherwise: %+v", got.proposes[0].claim)
	}
}

// TestAdversarialFN_RaiseOnlyNeverSuppresses: a raise-only engine (Rust/PHP/Ruby/JS-symbol) must mint NOTHING
// on a not_reachable blind surface, so it can never suppress regardless of blindness.
func TestAdversarialFN_RaiseOnlyNeverSuppresses(t *testing.T) {
	for _, bc := range blindConstructs {
		rec := &fakeRecorder{}
		a := fakeAnalyzer{res: []reachability.Result{{Symbol: "dep.vuln", Reachable: false, BlindConstructs: []string{bc}}}}
		c := tierCoord(t, judgment.Tier2, a, rec).WithRaiseOnly()
		if _, err := c.Record(context.Background(), "eng-1", "/work",
			[]ports.ReachabilitySubject{{FindingID: "f1", Symbols: []string{"dep.vuln"}}}); err != nil {
			t.Fatal(err)
		}
		if len(rec.proposes) != 0 {
			t.Fatalf("raise-only must mint nothing on a %q not_reachable surface, got %+v", bc, rec.proposes)
		}
	}
}

// TestAdversarialFN_Tier15NeverSuppresses: the JVM class-closure tier is reflection-blind by construction, so
// even a not_reachable verdict it records must never be a suppressing one.
func TestAdversarialFN_Tier15NeverSuppresses(t *testing.T) {
	rec := &fakeRecorder{}
	c, err := NewJVMVerdictCoordinator(rec, &fakeAudit{}, fakeClock{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.RecordVerdicts(context.Background(), "eng-1", []ports.JVMReachabilityVerdict{{FindingID: "f1", Reachable: false}}); err != nil {
		t.Fatal(err)
	}
	for _, p := range rec.proposes {
		if p.claim.SuppressesFinding() {
			t.Fatalf("Tier-1.5 (reflection-blind) must never suppress: %+v", p.claim)
		}
	}
}

// TestAdversarialFN_ReachableOnBlindSurfaceStillRaises: blindness must not block a proven reachable. A
// reachable verdict on a subject whose OTHER symbols are blind must still raise (mint reachable), because
// raising urgency is always sound.
func TestAdversarialFN_ReachableOnBlindSurfaceStillRaises(t *testing.T) {
	rec := &fakeRecorder{}
	a := fakeAnalyzer{res: []reachability.Result{
		{Symbol: "dep.reached", Reachable: true, Path: []string{"app.main", "dep.reached"}},
		{Symbol: "dep.blind", Reachable: false, BlindConstructs: []string{"reflection"}},
	}}
	c := tierCoord(t, judgment.Tier2, a, rec)
	if _, err := c.Record(context.Background(), "eng-1", "/work",
		[]ports.ReachabilitySubject{{FindingID: "f1", Symbols: []string{"dep.reached", "dep.blind"}}}); err != nil {
		t.Fatal(err)
	}
	if len(rec.proposes) != 1 || rec.proposes[0].claim.Reachable != judgment.Reachable {
		t.Fatalf("a reachable symbol must still raise despite a blind sibling, got %+v", rec.proposes)
	}
}
