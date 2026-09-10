package mavenresolve

import (
	"reflect"
	"sort"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// A realistic `mvn dependency:tree` capture: the [INFO] logger prefix, compile/runtime/provided/test scopes,
// and two levels of nesting. snakeyaml and a provided tomcat-embed-el are transitive under the starter; the
// junit subtree is test-scoped and dropped.
const treeFixture = `[INFO] --- maven-dependency-plugin:3.6.1:tree ---
[INFO] com.example:myapp:jar:1.0.0
[INFO] +- org.springframework.boot:spring-boot-starter:jar:2.7.5:compile
[INFO] |  +- org.springframework.boot:spring-boot:jar:2.7.5:compile
[INFO] |  +- org.yaml:snakeyaml:jar:1.30:compile
[INFO] |  \- org.apache.tomcat:tomcat-embed-el:jar:9.0.68:provided
[INFO] +- org.postgresql:postgresql:jar:42.5.0:runtime
[INFO] \- org.junit.jupiter:junit-jupiter:jar:5.8.2:test
[INFO]    \- org.apiguardian:apiguardian-api:jar:1.1.2:test
[INFO] ------------------------------------------------------------------------
`

func names(comps []sbom.Component) []string {
	out := make([]string, 0, len(comps))
	for _, c := range comps {
		out = append(out, c.Name+"@"+c.Version)
	}
	sort.Strings(out)
	return out
}

func TestParseDependencyTreeEdgesScopesAndTestDrop(t *testing.T) {
	comps, deps := parseDependencyTree([]byte(treeFixture))

	wantComps := []string{
		"org.apache.tomcat:tomcat-embed-el@9.0.68",
		"org.postgresql:postgresql@42.5.0",
		"org.springframework.boot:spring-boot-starter@2.7.5",
		"org.springframework.boot:spring-boot@2.7.5",
		"org.yaml:snakeyaml@1.30",
	}
	if got := names(comps); !reflect.DeepEqual(got, wantComps) {
		t.Fatalf("components = %v\nwant %v", got, wantComps)
	}
	for _, c := range comps {
		if c.Name == "com.example:myapp" {
			t.Errorf("project root must not be a component")
		}
		if c.Name == "org.junit.jupiter:junit-jupiter" || c.Name == "org.apiguardian:apiguardian-api" {
			t.Errorf("test-scope node %s must be dropped", c.Name)
		}
	}

	starter := "pkg:maven/org.springframework.boot/spring-boot-starter@2.7.5"
	snakeyaml := "pkg:maven/org.yaml/snakeyaml@1.30"

	// D3.2 headline: the transitive snakeyaml has a path up to its direct introducer (the starter).
	if path := sbom.PathToRoot(deps, snakeyaml); !reflect.DeepEqual(path, []string{starter, snakeyaml}) {
		t.Errorf("PathToRoot(snakeyaml) = %v, want [starter snakeyaml]", path)
	}
	// The starter is a direct dependency (a graph root); snakeyaml is not.
	componentIDs := map[string]bool{}
	for _, c := range comps {
		componentIDs[c.PURL] = true
	}
	if !sbom.IsDirect(deps, componentIDs, starter) {
		t.Errorf("starter must be reported direct")
	}
	if sbom.IsDirect(deps, componentIDs, snakeyaml) {
		t.Errorf("snakeyaml is transitive, must not be direct")
	}

	// Per-edge scope on a TRANSITIVE edge: tomcat-embed-el is pulled in provided.
	scopeOf := func(child string) string {
		for _, d := range deps {
			for _, c := range d.DependsOn {
				if c == child {
					return d.Scope
				}
			}
		}
		return ""
	}
	if s := scopeOf("pkg:maven/org.apache.tomcat/tomcat-embed-el@9.0.68"); s != "provided" {
		t.Errorf("tomcat-embed-el edge scope = %q, want provided", s)
	}
	if s := scopeOf(snakeyaml); s != "compile" {
		t.Errorf("snakeyaml edge scope = %q, want compile", s)
	}

	// ReachableScopes: the provided transitive is NOT production-reachable; the compile transitive IS.
	prod := sbom.ProductionReachable(deps)
	if prod["pkg:maven/org.apache.tomcat/tomcat-embed-el@9.0.68"] {
		t.Errorf("provided transitive tomcat-embed-el must not be production-reachable")
	}
	if !prod[snakeyaml] {
		t.Errorf("compile transitive snakeyaml must be production-reachable")
	}
}

func TestParseDependencyTreeIntroducers(t *testing.T) {
	// A diamond: two direct deps both pull in the same transitive commons-lang3.
	fixture := `[INFO] com.example:app:jar:1.0
[INFO] +- com.example:mod-a:jar:1.0:compile
[INFO] |  \- org.apache.commons:commons-lang3:jar:3.12.0:compile
[INFO] \- com.example:mod-b:jar:1.0:compile
[INFO]    \- org.apache.commons:commons-lang3:jar:3.12.0:compile
`
	_, deps := parseDependencyTree([]byte(fixture))
	got := sbom.IntroducedBy(deps, "pkg:maven/org.apache.commons/commons-lang3@3.12.0")
	want := []string{"pkg:maven/com.example/mod-a@1.0", "pkg:maven/com.example/mod-b@1.0"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("IntroducedBy = %v, want both direct introducers %v", got, want)
	}
}

func TestParseDependencyTreeChildlessDirectStillInGraph(t *testing.T) {
	// A direct dep with no transitive children must still be reported direct (in-graph, no dependent).
	fixture := `[INFO] com.example:app:jar:1.0
[INFO] \- com.google.guava:guava:jar:31.1-jre:compile
`
	comps, deps := parseDependencyTree([]byte(fixture))
	ids := map[string]bool{}
	for _, c := range comps {
		ids[c.PURL] = true
	}
	guava := "pkg:maven/com.google.guava/guava@31.1-jre"
	if !sbom.IsDirect(deps, ids, guava) {
		t.Errorf("a childless direct dep must be reported direct; deps=%v", deps)
	}
}

func TestParseDependencyTreePrefixlessIndentation(t *testing.T) {
	// No [INFO] prefix (mvn -q or captured differently): space-only indentation must still nest correctly.
	fixture := `com.example:app:jar:1.0
\- com.example:mod-b:jar:1.0:compile
   \- org.apache.commons:commons-lang3:jar:3.12.0:compile
`
	_, deps := parseDependencyTree([]byte(fixture))
	modB := "pkg:maven/com.example/mod-b@1.0"
	lang3 := "pkg:maven/org.apache.commons/commons-lang3@3.12.0"
	if path := sbom.PathToRoot(deps, lang3); !reflect.DeepEqual(path, []string{modB, lang3}) {
		t.Errorf("prefixless: commons-lang3 must nest under mod-b, got path %v", path)
	}
}

func TestParseDependencyTreeSkippedTestDoesNotStealChildren(t *testing.T) {
	// A deeper compile node appearing after a skipped test sibling must NOT attach to the prior prod slot.
	// (Defensive: real mvn narrows a test subtree to scope=test, but the parser must not create a false path.)
	fixture := `[INFO] com.example:app:jar:1.0
[INFO] +- com.example:prod:jar:1:compile
[INFO] \- com.example:testkit:jar:1:test
[INFO]    \- com.example:helper:jar:1:compile
`
	comps, deps := parseDependencyTree([]byte(fixture))
	prod := "pkg:maven/com.example/prod@1"
	helper := "pkg:maven/com.example/helper@1"
	// helper must NOT be a child of prod (its real parent testkit was dropped).
	for _, d := range deps {
		if d.Ref == prod {
			for _, c := range d.DependsOn {
				if c == helper {
					t.Errorf("helper wrongly attached to prod after a skipped test sibling")
				}
			}
		}
	}
	// helper stays a component but with no false production path.
	if path := sbom.PathToRoot(deps, helper); len(path) > 1 && path[0] == prod {
		t.Errorf("helper must not have a production path through prod, got %v", path)
	}
	_ = comps
}
