package gradleresolve

import (
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// The init script prints one SYNAPSE_DEP per resolved module and one SYNAPSE_EDGE per resolution-graph edge
// (parent|child), with SYNAPSE_ROOT as the parent of a direct dependency. A platform/BOM never becomes a
// SYNAPSE_DEP, so an edge to it is dropped.
const gradleFixture = `SYNAPSE_DEP org.springframework:spring-core:5.3.20
SYNAPSE_DEP org.springframework:spring-jcl:5.3.20
SYNAPSE_DEP org.yaml:snakeyaml:1.30
SYNAPSE_EDGE SYNAPSE_ROOT|org.springframework:spring-core:5.3.20
SYNAPSE_EDGE SYNAPSE_ROOT|org.yaml:snakeyaml:1.30
SYNAPSE_EDGE org.springframework:spring-core:5.3.20|org.springframework:spring-jcl:5.3.20
SYNAPSE_EDGE org.springframework:spring-core:5.3.20|com.example:platform-bom:1.0
`

func TestParseGradleGraphEdgesAndRootless(t *testing.T) {
	comps, deps, unresolved := parseGradleGraph([]byte(gradleFixture))
	if len(unresolved) != 0 {
		t.Fatalf("unexpected unresolved: %v", unresolved)
	}
	if len(comps) != 3 {
		t.Fatalf("want 3 components, got %d", len(comps))
	}
	core := "pkg:maven/org.springframework/spring-core@5.3.20"
	jcl := "pkg:maven/org.springframework/spring-jcl@5.3.20"

	// The transitive spring-jcl has a path to its direct introducer spring-core (D3.5 headline).
	if path := sbom.PathToRoot(deps, jcl); !reflect.DeepEqual(path, []string{core, jcl}) {
		t.Errorf("PathToRoot(spring-jcl) = %v, want [spring-core spring-jcl]", path)
	}
	// spring-core is direct; spring-jcl is transitive.
	ids := map[string]bool{}
	for _, c := range comps {
		ids[c.PURL] = true
	}
	if !sbom.IsDirect(deps, ids, core) {
		t.Errorf("spring-core must be direct")
	}
	if sbom.IsDirect(deps, ids, jcl) {
		t.Errorf("spring-jcl must be transitive")
	}
	// The edge to the platform-bom (never a SYNAPSE_DEP) must be dropped.
	for _, d := range deps {
		for _, c := range d.DependsOn {
			if c == "pkg:maven/com.example/platform-bom@1.0" {
				t.Errorf("edge to a non-component platform must be dropped")
			}
		}
	}
	// Every edge is runtime/production scope, so ReachableScopes keeps them production.
	if !sbom.ProductionReachable(deps)[jcl] {
		t.Errorf("runtime-scope transitive must be production-reachable")
	}
}

func TestParseGradleGraphIntroducersDiamond(t *testing.T) {
	fixture := `SYNAPSE_DEP com.example:mod-a:1.0
SYNAPSE_DEP com.example:mod-b:1.0
SYNAPSE_DEP org.apache.commons:commons-lang3:3.12.0
SYNAPSE_EDGE SYNAPSE_ROOT|com.example:mod-a:1.0
SYNAPSE_EDGE SYNAPSE_ROOT|com.example:mod-b:1.0
SYNAPSE_EDGE com.example:mod-a:1.0|org.apache.commons:commons-lang3:3.12.0
SYNAPSE_EDGE com.example:mod-b:1.0|org.apache.commons:commons-lang3:3.12.0
`
	_, deps, _ := parseGradleGraph([]byte(fixture))
	got := sbom.IntroducedBy(deps, "pkg:maven/org.apache.commons/commons-lang3@3.12.0")
	want := []string{"pkg:maven/com.example/mod-a@1.0", "pkg:maven/com.example/mod-b@1.0"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("IntroducedBy = %v, want both direct introducers %v", got, want)
	}
}

func TestParseGradleGraphChildlessDirectInGraph(t *testing.T) {
	fixture := `SYNAPSE_DEP com.google.guava:guava:31.1-jre
SYNAPSE_EDGE SYNAPSE_ROOT|com.google.guava:guava:31.1-jre
`
	comps, deps, _ := parseGradleGraph([]byte(fixture))
	ids := map[string]bool{}
	for _, c := range comps {
		ids[c.PURL] = true
	}
	if !sbom.IsDirect(deps, ids, "pkg:maven/com.google.guava/guava@31.1-jre") {
		t.Errorf("childless direct guava must be reported direct; deps=%v", deps)
	}
}
