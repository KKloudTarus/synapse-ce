package sca

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

func TestClassifyVulnsGraphScopeRefinement(t *testing.T) {
	component := func(name string, scope string) sbom.Component {
		return sbom.Component{Name: name, Version: "1.0.0", PURL: "pkg:generic/" + name + "@1.0.0", Scope: scope}
	}
	dep := func(from string, scope string, to ...string) sbom.Dependency {
		targets := make([]string, len(to))
		for i, name := range to {
			targets[i] = "pkg:generic/" + name + "@1.0.0"
		}
		return sbom.Dependency{Ref: "pkg:generic/" + from + "@1.0.0", DependsOn: targets, Scope: scope}
	}

	tests := []struct {
		name       string
		components []sbom.Component
		deps       []sbom.Dependency
		target     string
		want       string
	}{
		{
			name:       "dev-only transitive is downgraded",
			components: []sbom.Component{component("root", sbom.ScopeProduction), component("leaf", sbom.ScopeProduction)},
			deps:       []sbom.Dependency{dep("root", sbom.ScopeDevelopment, "leaf")}, target: "leaf", want: sbom.ScopeDevelopment,
		},
		{
			name:       "production path wins a mixed diamond",
			components: []sbom.Component{component("root", sbom.ScopeProduction), component("prod", sbom.ScopeProduction), component("dev", sbom.ScopeProduction), component("leaf", sbom.ScopeProduction)},
			deps: []sbom.Dependency{
				dep("root", sbom.ScopeProduction, "prod"), dep("root", sbom.ScopeDevelopment, "dev"),
				dep("prod", sbom.ScopeProduction, "leaf"), dep("dev", sbom.ScopeProduction, "leaf"),
			}, target: "leaf", want: sbom.ScopeProduction,
		},
		{
			name:       "provided-only Maven-style path is actionable development",
			components: []sbom.Component{component("root", sbom.ScopeProduction), component("leaf", sbom.ScopeProduction)},
			deps:       []sbom.Dependency{dep("root", "provided", "leaf")}, target: "leaf", want: sbom.ScopeDevelopment,
		},
		{
			name:       "background graph evidence is monotonically clamped",
			components: []sbom.Component{component("root", sbom.ScopeProduction), component("leaf", sbom.ScopeProduction)},
			deps:       []sbom.Dependency{dep("root", sbom.ScopeTest, "leaf")}, target: "leaf", want: sbom.ScopeDevelopment,
		},
		{
			name:       "rootless cycle remains conservative production",
			components: []sbom.Component{component("a", sbom.ScopeProduction), component("b", sbom.ScopeProduction)},
			deps:       []sbom.Dependency{dep("a", sbom.ScopeDevelopment, "b"), dep("b", sbom.ScopeDevelopment, "a")}, target: "b", want: sbom.ScopeProduction,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := &sbom.SBOM{Components: tt.components, Dependencies: tt.deps}
			vulns := []vulnerability.Vulnerability{{ID: "CVE-TEST-0001", Component: tt.target, Version: "1.0.0", Severity: shared.SeverityHigh}}
			classifyVulns(doc, vulns)
			if got := vulns[0].Scope; got != tt.want {
				t.Fatalf("scope = %q, want %q", got, tt.want)
			}
			if tt.name == "background graph evidence is monotonically clamped" && sbom.IsBackgroundScope(vulns[0].Scope) {
				t.Fatalf("graph refinement moved shipping vuln into background scope %q", vulns[0].Scope)
			}
		})
	}
}
