package sbom

import (
	"reflect"
	"sort"
	"testing"
)

func scopesOf(m map[string]map[string]bool, node string) []string {
	out := make([]string, 0, len(m[node]))
	for s := range m[node] {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func TestReachableScopesNarrowsAlongTestEdges(t *testing.T) {
	// root -> app (compile) -> lib (compile)      [production path to lib]
	// root -> testkit (test) -> lib (compile)     [test path to lib]
	// root -> testkit (test) -> mockonly (compile)[test-only, no production path]
	deps := []Dependency{
		{Ref: "root", DependsOn: []string{"app"}, Scope: "compile"},
		{Ref: "root", DependsOn: []string{"testkit"}, Scope: "test"},
		{Ref: "app", DependsOn: []string{"lib"}, Scope: "compile"},
		{Ref: "testkit", DependsOn: []string{"lib", "mockonly"}, Scope: "compile"},
	}
	got := ReachableScopes(deps)

	// lib is reachable BOTH production (via app) and test (via testkit).
	if want := []string{ScopeProduction, ScopeTest}; !reflect.DeepEqual(scopesOf(got, "lib"), want) {
		t.Errorf("lib scopes = %v, want %v", scopesOf(got, "lib"), want)
	}
	// mockonly is reachable ONLY through the test edge -> test-only.
	if want := []string{ScopeTest}; !reflect.DeepEqual(scopesOf(got, "mockonly"), want) {
		t.Errorf("mockonly scopes = %v, want %v", scopesOf(got, "mockonly"), want)
	}
	// root and app are production.
	if want := []string{ScopeProduction}; !reflect.DeepEqual(scopesOf(got, "app"), want) {
		t.Errorf("app scopes = %v, want %v", scopesOf(got, "app"), want)
	}

	prod := ProductionReachable(deps)
	if !prod["lib"] {
		t.Errorf("lib must be production-reachable (via app)")
	}
	if prod["mockonly"] {
		t.Errorf("mockonly must NOT be production-reachable (test-only), so it can be deprioritized")
	}
	if !prod["root"] || !prod["app"] {
		t.Errorf("roots and production nodes must be production-reachable")
	}
}

func TestReachableScopesProvidedIsNotProduction(t *testing.T) {
	deps := []Dependency{
		{Ref: "root", DependsOn: []string{"servlet"}, Scope: "provided"},
	}
	if ProductionReachable(deps)["servlet"] {
		t.Errorf("a provided-only dependency must not be production-reachable")
	}
	if want := []string{"provided"}; !reflect.DeepEqual(scopesOf(ReachableScopes(deps), "servlet"), want) {
		t.Errorf("servlet scopes = %v, want [provided]", scopesOf(ReachableScopes(deps), "servlet"))
	}
}

func TestReachableScopesEmptyScopeIsProduction(t *testing.T) {
	// A parser that records no scope must default to production, so nothing regresses.
	deps := []Dependency{{Ref: "root", DependsOn: []string{"child"}}}
	if !ProductionReachable(deps)["child"] {
		t.Errorf("empty edge scope must be treated as production")
	}
}

func TestReachableScopesCycleSafe(t *testing.T) {
	deps := []Dependency{
		{Ref: "a", DependsOn: []string{"b"}, Scope: "compile"},
		{Ref: "b", DependsOn: []string{"a"}, Scope: "compile"},
		{Ref: "root", DependsOn: []string{"a"}, Scope: "compile"},
	}
	got := ReachableScopes(deps) // must terminate
	if !got["a"][ScopeProduction] || !got["b"][ScopeProduction] {
		t.Errorf("cycle members reachable from a root must still be scored: %v", got)
	}
}

func TestReachableScopesRootlessCycleNotOmitted(t *testing.T) {
	// A cycle with no external root: every node has a dependent, so there is no BFS seed. The nodes must
	// still appear (as production, the conservative choice), never be silently omitted.
	deps := []Dependency{
		{Ref: "a", DependsOn: []string{"b"}, Scope: "compile"},
		{Ref: "b", DependsOn: []string{"a"}, Scope: "compile"},
	}
	got := ReachableScopes(deps)
	if got["a"] == nil || got["b"] == nil {
		t.Fatalf("rootless-cycle nodes omitted: %v", got)
	}
	if !ProductionReachable(deps)["a"] || !ProductionReachable(deps)["b"] {
		t.Errorf("rootless-cycle nodes must default to production (conservative), not be omitted")
	}
}
