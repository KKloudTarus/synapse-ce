package projectuc

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

func TestBuildProjectDependencyGraphUsesProductionReachability(t *testing.T) {
	c := func(name, scope string) sbom.Component { return component(name, "1", "pkg:generic/"+name+"@1", scope) }
	d := func(from, scope string, to ...string) sbom.Dependency {
		targets := make([]string, len(to))
		for i, name := range to {
			targets[i] = "pkg:generic/" + name + "@1"
		}
		return sbom.Dependency{Ref: "pkg:generic/" + from + "@1", DependsOn: targets, Scope: scope}
	}
	tests := []struct {
		name       string
		components []sbom.Component
		deps       []sbom.Dependency
		target     string
		want       string
	}{
		{"dev-only transitive", []sbom.Component{c("root", sbom.ScopeProduction), c("leaf", sbom.ScopeProduction)}, []sbom.Dependency{d("root", sbom.ScopeDevelopment, "leaf")}, "leaf", sbom.ScopeDevelopment},
		{"production path wins diamond", []sbom.Component{c("root", sbom.ScopeProduction), c("p", sbom.ScopeProduction), c("d", sbom.ScopeProduction), c("leaf", sbom.ScopeProduction)}, []sbom.Dependency{d("root", sbom.ScopeProduction, "p"), d("root", sbom.ScopeDevelopment, "d"), d("p", sbom.ScopeProduction, "leaf"), d("d", sbom.ScopeProduction, "leaf")}, "leaf", sbom.ScopeProduction},
		{"rootless cycle conservative", []sbom.Component{c("a", sbom.ScopeProduction), c("b", sbom.ScopeProduction)}, []sbom.Dependency{d("a", sbom.ScopeDevelopment, "b"), d("b", sbom.ScopeDevelopment, "a")}, "b", sbom.ScopeProduction},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			graph, err := buildProjectDependencyGraph("analysis", scauc.ScanResult{SBOM: &sbom.SBOM{Components: tt.components, Dependencies: tt.deps}})
			if err != nil {
				t.Fatal(err)
			}
			got := graphNodesByID(graph.Nodes)["pkg:generic/"+tt.target+"@1"].Scope
			if got != tt.want {
				t.Fatalf("scope = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDependencySubtreePreservesEdgeMetadata(t *testing.T) {
	a := component("a", "1", "pkg:generic/a@1", sbom.ScopeProduction)
	b := component("b", "1", "pkg:generic/b@1", sbom.ScopeDevelopment)
	doc := &sbom.SBOM{Components: []sbom.Component{a, b}, Dependencies: []sbom.Dependency{{Ref: a.PURL, DependsOn: []string{b.PURL}, Scope: sbom.ScopeDevelopment, Optional: true}}}
	got, err := dependencySubtree(doc, a.PURL)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Dependencies) != 1 || got.Dependencies[0].Scope != sbom.ScopeDevelopment || !got.Dependencies[0].Optional {
		t.Fatalf("edge metadata lost from subtree: %+v", got.Dependencies)
	}
	cloned := cloneDependencies(doc.Dependencies)
	if cloned[0].Scope != sbom.ScopeDevelopment || !cloned[0].Optional {
		t.Fatalf("edge metadata lost from clone: %+v", cloned)
	}
}
