package sbom

import "testing"

func TestPathToRoot(t *testing.T) {
	deps := []Dependency{
		{Ref: "app", DependsOn: []string{"a"}},
		{Ref: "a", DependsOn: []string{"b"}},
		{Ref: "b", DependsOn: []string{"c"}},
	}
	if got := PathToRoot(deps, "c"); len(got) != 4 || got[0] != "app" || got[3] != "c" {
		t.Errorf("transitive: PathToRoot(c) = %v, want [app a b c]", got)
	}
	if got := PathToRoot(deps, "a"); len(got) != 2 || got[0] != "app" || got[1] != "a" {
		t.Errorf("direct: PathToRoot(a) = %v, want [app a]", got)
	}
	if got := PathToRoot(deps, "app"); len(got) != 1 || got[0] != "app" {
		t.Errorf("root: PathToRoot(app) = %v, want [app]", got)
	}
	if got := PathToRoot(deps, "zzz"); got != nil {
		t.Errorf("absent: PathToRoot(zzz) = %v, want nil", got)
	}
}

func TestPathToRootCycleTerminates(t *testing.T) {
	deps := []Dependency{{Ref: "x", DependsOn: []string{"y"}}, {Ref: "y", DependsOn: []string{"x"}}}
	if got := PathToRoot(deps, "x"); len(got) == 0 {
		t.Error("a cycle with no root must still return a path, not empty/hang")
	}
}

func TestComponentID(t *testing.T) {
	if ComponentID("a", "1", "pkg:npm/a@1") != "pkg:npm/a@1" {
		t.Error("PURL should win")
	}
	if ComponentID("a", "1", "") != "a@1" {
		t.Error("name@version fallback")
	}
	if ComponentID("a", "", "") != "a" {
		t.Error("name-only fallback")
	}
}

func TestIntroducedBy(t *testing.T) {
	// Diamond: root1 and root2 both reach target via mid. Both are introducers.
	deps := []Dependency{
		{Ref: "root1", DependsOn: []string{"mid"}},
		{Ref: "root2", DependsOn: []string{"mid"}},
		{Ref: "mid", DependsOn: []string{"target"}},
		// a decoy top-level dep that does NOT reach target
		{Ref: "root3", DependsOn: []string{"other"}},
	}
	got := IntroducedBy(deps, "target")
	if len(got) != 2 || got[0] != "root1" || got[1] != "root2" {
		t.Errorf("IntroducedBy(target) = %v, want [root1 root2]", got)
	}
	// A direct/top-level dep introduces itself.
	if got := IntroducedBy(deps, "root1"); len(got) != 1 || got[0] != "root1" {
		t.Errorf("IntroducedBy(root1) = %v, want [root1]", got)
	}
	// A target not in the graph -> nil.
	if got := IntroducedBy(deps, "ghost"); got != nil {
		t.Errorf("IntroducedBy(ghost) = %v, want nil", got)
	}
	// Also reachable directly from a root AND transitively.
	deps2 := []Dependency{
		{Ref: "a", DependsOn: []string{"t", "b"}},
		{Ref: "b", DependsOn: []string{"t"}},
	}
	// a is the only root; b has a dependent (a). t is introduced by a only.
	if got := IntroducedBy(deps2, "t"); len(got) != 1 || got[0] != "a" {
		t.Errorf("IntroducedBy(t) = %v, want [a]", got)
	}
	// A pure cycle with no root above target -> nil (no clean introducer); must terminate.
	cyc := []Dependency{
		{Ref: "x", DependsOn: []string{"y"}},
		{Ref: "y", DependsOn: []string{"x"}},
	}
	if got := IntroducedBy(cyc, "x"); got != nil {
		t.Errorf("IntroducedBy on a pure cycle = %v, want nil", got)
	}
}
