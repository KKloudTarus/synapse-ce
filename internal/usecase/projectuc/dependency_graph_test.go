package projectuc

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

func TestBuildProjectDependencyGraphProjectsRiskAndDepth(t *testing.T) {
	root := component("app", "1.0.0", "pkg:generic/app@1.0.0", sbom.ScopeProduction)
	direct := component("spring-web", "6.1.0", "pkg:maven/org.springframework/spring-web@6.1.0", sbom.ScopeProduction)
	transitive := component("log4j-core", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", sbom.ScopeProduction)
	transitive.Reachability = sbom.ReachabilityReachable
	transitive.Licenses = []sbom.License{{SPDXID: "LGPL-2.1-only", Name: "GNU LGPL 2.1", Category: sbom.LicenseWeakCopyleft}}
	scan := scauc.ScanResult{
		SBOM: &sbom.SBOM{
			Components: []sbom.Component{transitive, root, direct},
			Dependencies: []sbom.Dependency{
				{Ref: root.PURL, DependsOn: []string{direct.PURL}},
				{Ref: direct.PURL, DependsOn: []string{transitive.PURL}},
			},
		},
		Vulnerabilities: []vulnerability.Vulnerability{{
			ID: "CVE-2021-44228", Source: "osv", Severity: shared.SeverityCritical,
			Component: transitive.Name, Version: transitive.Version, PackagePURL: transitive.PURL, FixedVersion: "2.17.1",
		}},
		Licenses: []ports.LicenseFinding{{
			License: "LGPL-2.1-only", Category: sbom.LicenseWeakCopyleft, Verdict: ports.LicenseWarn,
			Components: []string{transitive.Name + "@" + transitive.Version},
		}},
	}

	graph, err := buildProjectDependencyGraph("analysis-1", scan)
	if err != nil {
		t.Fatal(err)
	}
	if graph.AnalysisID != "analysis-1" || len(graph.Roots) != 1 || graph.Roots[0] != root.PURL {
		t.Fatalf("identity/roots = %+v", graph)
	}
	if graph.Summary.Components != 3 || graph.Summary.Direct != 1 || graph.Summary.Transitive != 2 || graph.Summary.Vulnerable != 1 || graph.Summary.LicenseRisk != 1 || graph.Summary.Edges != 2 {
		t.Fatalf("summary = %+v", graph.Summary)
	}
	byID := graphNodesByID(graph.Nodes)
	got := byID[transitive.PURL]
	if got.Depth != 2 || got.Direct || got.Reachability != sbom.ReachabilityReachable || got.VulnerabilityCount != 1 || got.WorstSeverity != "critical" || !got.LicenseRisk || got.LicenseVerdict != "warn" {
		t.Fatalf("transitive node = %+v", got)
	}
	if len(got.Vulnerabilities) != 1 || got.Vulnerabilities[0].ID != "CVE-2021-44228" || got.Vulnerabilities[0].FixedVersion != "2.17.1" {
		t.Fatalf("vulnerabilities = %+v", got.Vulnerabilities)
	}
	if len(got.Licenses) != 1 || got.Licenses[0].ID != "LGPL-2.1-only" {
		t.Fatalf("licenses = %+v", got.Licenses)
	}
}

func TestBuildProjectDependencyGraphIsDeterministicAndCycleHonest(t *testing.T) {
	a := component("a", "1", "pkg:generic/a@1", sbom.ScopeUnknown)
	b := component("b", "1", "pkg:generic/b@1", sbom.ScopeUnknown)
	scan := scauc.ScanResult{SBOM: &sbom.SBOM{
		Components:   []sbom.Component{b, a},
		Dependencies: []sbom.Dependency{{Ref: b.PURL, DependsOn: []string{a.PURL}}, {Ref: a.PURL, DependsOn: []string{b.PURL}}},
	}}
	one, err := buildProjectDependencyGraph("a", scan)
	if err != nil {
		t.Fatal(err)
	}
	scan.SBOM.Components[0], scan.SBOM.Components[1] = scan.SBOM.Components[1], scan.SBOM.Components[0]
	scan.SBOM.Dependencies[0], scan.SBOM.Dependencies[1] = scan.SBOM.Dependencies[1], scan.SBOM.Dependencies[0]
	two, err := buildProjectDependencyGraph("a", scan)
	if err != nil {
		t.Fatal(err)
	}
	oneJSON, _ := json.Marshal(one)
	twoJSON, _ := json.Marshal(two)
	if string(oneJSON) != string(twoJSON) {
		t.Fatalf("projection is order-dependent:\n%s\n%s", oneJSON, twoJSON)
	}
	if len(one.Roots) != 0 || one.Nodes[0].Depth != -1 || one.Nodes[1].Depth != -1 || one.Summary.Direct != 0 {
		t.Fatalf("rootless cycle was mislabelled: %+v", one)
	}
}

func TestDependencySubtreeKeepsOnlyDescendants(t *testing.T) {
	a := component("a", "1", "pkg:generic/a@1", sbom.ScopeProduction)
	b := component("b", "1", "pkg:generic/b@1", sbom.ScopeProduction)
	c := component("c", "1", "pkg:generic/c@1", sbom.ScopeProduction)
	doc := &sbom.SBOM{Raw: []byte("secret raw producer document"), Components: []sbom.Component{a, b, c}, Dependencies: []sbom.Dependency{
		{Ref: a.PURL, DependsOn: []string{b.PURL}}, {Ref: b.PURL, DependsOn: []string{c.PURL}},
	}}

	got, err := dependencySubtree(doc, b.PURL)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Components) != 2 || got.Components[0].PURL != b.PURL || got.Components[1].PURL != c.PURL || len(got.Dependencies) != 1 || got.Dependencies[0].Ref != b.PURL || got.Raw != nil {
		t.Fatalf("subtree = %+v", got)
	}
	if _, err := dependencySubtree(doc, "pkg:generic/missing@1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing root error = %v", err)
	}
}

func TestResolveLicenseComponentIDsSupportsScopedNames(t *testing.T) {
	c := component("@scope/pkg", "1.2.3", "pkg:npm/%40scope/pkg@1.2.3", sbom.ScopeDevelopment)
	byID := map[string]sbom.Component{c.PURL: c}
	byName := map[string][]string{c.Name: {c.PURL}}
	byNV := map[string][]string{c.Name + "\x00" + c.Version: {c.PURL}}
	for _, token := range []string{c.PURL, c.Name, c.Name + "@" + c.Version} {
		got := resolveLicenseComponentIDs(token, byID, byName, byNV)
		if len(got) != 1 || got[0] != c.PURL {
			t.Fatalf("token %q resolved to %v", token, got)
		}
	}
}

func TestBuildProjectDependencyGraphNormalizesUnknownRiskFacts(t *testing.T) {
	c := component("legacy", "1", "pkg:generic/legacy@1", sbom.ScopeProduction)
	c.Licenses = []sbom.License{{Name: "unclassified"}}
	graph, err := buildProjectDependencyGraph("analysis", scauc.ScanResult{
		SBOM:            &sbom.SBOM{Components: []sbom.Component{c}},
		Vulnerabilities: []vulnerability.Vulnerability{{ID: "CVE-unknown", Component: c.Name, Version: c.Version}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := graph.Nodes[0]
	if len(got.Licenses) != 1 || got.Licenses[0].Category != "unknown" || !got.LicenseRisk {
		t.Fatalf("unknown license was not normalized as risk: %+v", got)
	}
	if len(got.Vulnerabilities) != 1 || got.Vulnerabilities[0].Severity != "unknown" || got.WorstSeverity != "unknown" {
		t.Fatalf("unknown vulnerability severity was not normalized: %+v", got.Vulnerabilities)
	}
}

func component(name, version, purl, scope string) sbom.Component {
	return sbom.Component{Name: name, Version: version, PURL: purl, Scope: scope}
}

func graphNodesByID(nodes []DependencyGraphNode) map[string]DependencyGraphNode {
	out := make(map[string]DependencyGraphNode, len(nodes))
	for _, node := range nodes {
		out[node.ID] = node
	}
	return out
}
