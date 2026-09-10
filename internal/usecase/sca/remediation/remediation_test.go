package remediation

import (
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestSolveDiamondReturnsBothIntroducers(t *testing.T) {
	// root deps A and B both pull the vulnerable transitive V; C is unrelated.
	deps := []sbom.Dependency{
		{Ref: "A", DependsOn: []string{"V"}},
		{Ref: "B", DependsOn: []string{"V"}},
		{Ref: "C", DependsOn: []string{"D"}},
	}
	plan, ok := Solve(deps, "V", "2.0.0")
	if !ok {
		t.Fatal("V is in the graph, so a plan must be returned")
	}
	if plan.FixedVersion != "2.0.0" || plan.Vulnerable != "V" {
		t.Fatalf("plan context wrong: %+v", plan)
	}
	// Minimal set: BOTH A and B must be bumped (dropping either leaves the other's path to V).
	if !reflect.DeepEqual(plan.DirectBumps, []string{"A", "B"}) {
		t.Fatalf("DirectBumps = %v, want [A B]", plan.DirectBumps)
	}
}

func TestSolveDirectVulnerabilityBumpsItself(t *testing.T) {
	// V is itself a direct (top-level) dependency: the only bump is V.
	deps := []sbom.Dependency{{Ref: "V", DependsOn: []string{"W"}}}
	plan, ok := Solve(deps, "V", "")
	if !ok || !reflect.DeepEqual(plan.DirectBumps, []string{"V"}) {
		t.Fatalf("a direct vuln must bump itself, got ok=%v plan=%+v", ok, plan)
	}
}

func TestSolveNotInGraphReturnsFalse(t *testing.T) {
	deps := []sbom.Dependency{{Ref: "A", DependsOn: []string{"B"}}}
	if _, ok := Solve(deps, "Z", "1.0.0"); ok {
		t.Fatal("a component absent from the graph has no remediation plan")
	}
}

func TestSolveDeepTransitiveWalksToTheDirectRoot(t *testing.T) {
	// A -> M -> V: the direct bump is A (the top-level root of V's only path), not M.
	deps := []sbom.Dependency{
		{Ref: "A", DependsOn: []string{"M"}},
		{Ref: "M", DependsOn: []string{"V"}},
	}
	plan, ok := Solve(deps, "V", "3.1.0")
	if !ok || !reflect.DeepEqual(plan.DirectBumps, []string{"A"}) {
		t.Fatalf("deep transitive must resolve to the direct root A, got ok=%v plan=%+v", ok, plan)
	}
}

// TestSolveSharedIntermediateStillNeedsBothRoots: A -> M -> V and B -> M -> V share the intermediate M, but M
// is not directly bumpable, so removing V still requires bumping BOTH direct roots A and B.
func TestSolveSharedIntermediateStillNeedsBothRoots(t *testing.T) {
	deps := []sbom.Dependency{
		{Ref: "A", DependsOn: []string{"M"}},
		{Ref: "B", DependsOn: []string{"M"}},
		{Ref: "M", DependsOn: []string{"V"}},
	}
	plan, ok := Solve(deps, "V", "1.2.3")
	if !ok || !reflect.DeepEqual(plan.DirectBumps, []string{"A", "B"}) {
		t.Fatalf("a shared intermediate still needs both direct roots, got ok=%v plan=%+v", ok, plan)
	}
}
