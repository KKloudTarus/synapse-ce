package ownsbom

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// writePOM installs a .pom into a fake local Maven repository at the standard layout path.
func writePOM(t *testing.T, root, group, artifact, version, body string) {
	t.Helper()
	dir := filepath.Join(append([]string{root}, append(strings.Split(group, "."), artifact, version)...)...)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, artifact+"-"+version+".pom")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func parseMaven(t *testing.T, repoRoot, projectDir, pom string) ([]string, []string) {
	t.Helper()
	t.Setenv("MAVEN_REPO_LOCAL", repoRoot)
	path := filepath.Join(projectDir, "pom.xml")
	if err := os.WriteFile(path, []byte(pom), 0o644); err != nil {
		t.Fatal(err)
	}
	comps, deps, err := Maven{}.Parse(context.Background(), ParseInput{Dir: projectDir, Path: path, Content: []byte(pom)})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var names []string
	for _, c := range comps {
		names = append(names, c.Name+"@"+c.Version)
	}
	sort.Strings(names)
	var edges []string
	for _, d := range deps {
		for _, to := range d.DependsOn {
			edges = append(edges, d.Ref+" -> "+to)
		}
	}
	sort.Strings(edges)
	return names, edges
}

// A Spring-Boot-style project declares a starter with NO version and gets it from the parent BOM. A
// direct-literal parse of such a pom.xml yields nothing, which is why a real Java service reported zero
// components while depending on hundreds of artifacts.
func TestMavenResolvesManagedVersionAndTransitiveTree(t *testing.T) {
	repo := t.TempDir()
	writePOM(t, repo, "com.example", "platform", "1.0.0", `<project>
  <groupId>com.example</groupId><artifactId>platform</artifactId><version>1.0.0</version>
  <properties><jackson.version>2.15.2</jackson.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.example</groupId><artifactId>starter-web</artifactId><version>3.1.0</version></dependency>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>${jackson.version}</version></dependency>
  </dependencies></dependencyManagement>
</project>`)
	writePOM(t, repo, "com.example", "starter-web", "3.1.0", `<project>
  <groupId>com.example</groupId><artifactId>starter-web</artifactId><version>3.1.0</version>
  <dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId></dependency>
    <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.7</version></dependency>
  </dependencies>
</project>`)
	writePOM(t, repo, "com.fasterxml.jackson.core", "jackson-databind", "2.15.2", `<project>
  <groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.15.2</version>
  <dependencies><dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-core</artifactId><version>2.15.2</version></dependency></dependencies>
</project>`)
	writePOM(t, repo, "com.fasterxml.jackson.core", "jackson-core", "2.15.2", `<project>
  <groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-core</artifactId><version>2.15.2</version></project>`)
	writePOM(t, repo, "org.slf4j", "slf4j-api", "2.0.7", `<project>
  <groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.7</version></project>`)

	names, edges := parseMaven(t, repo, t.TempDir(), `<project>
  <parent><groupId>com.example</groupId><artifactId>platform</artifactId><version>1.0.0</version><relativePath/></parent>
  <groupId>com.example</groupId><artifactId>service</artifactId><version>0.1.0</version>
  <dependencies><dependency><groupId>com.example</groupId><artifactId>starter-web</artifactId></dependency></dependencies>
</project>`)

	want := []string{
		"com.example:starter-web@3.1.0",
		"com.fasterxml.jackson.core:jackson-core@2.15.2",
		"com.fasterxml.jackson.core:jackson-databind@2.15.2",
		"org.slf4j:slf4j-api@2.0.7",
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("components =\n  %v\nwant\n  %v", names, want)
	}
	if len(edges) == 0 {
		t.Error("the resolved tree must carry dependency edges; completeness reads them as the resolution signal")
	}
}

// Nearest wins: a version declared at depth 1 beats the same artifact reached at depth 2.
func TestMavenNearestVersionWins(t *testing.T) {
	repo := t.TempDir()
	writePOM(t, repo, "g", "direct", "1.0.0", `<project><groupId>g</groupId><artifactId>direct</artifactId><version>1.0.0</version>
  <dependencies><dependency><groupId>g</groupId><artifactId>shared</artifactId><version>9.9.9</version></dependency></dependencies></project>`)
	writePOM(t, repo, "g", "shared", "1.1.1", `<project><groupId>g</groupId><artifactId>shared</artifactId><version>1.1.1</version></project>`)
	writePOM(t, repo, "g", "shared", "9.9.9", `<project><groupId>g</groupId><artifactId>shared</artifactId><version>9.9.9</version></project>`)

	names, _ := parseMaven(t, repo, t.TempDir(), `<project>
  <groupId>g</groupId><artifactId>app</artifactId><version>0.1</version>
  <dependencies>
    <dependency><groupId>g</groupId><artifactId>shared</artifactId><version>1.1.1</version></dependency>
    <dependency><groupId>g</groupId><artifactId>direct</artifactId><version>1.0.0</version></dependency>
  </dependencies></project>`)
	for _, n := range names {
		if n == "g:shared@9.9.9" {
			t.Errorf("the depth-2 version must lose to the depth-1 declaration, got %v", names)
		}
	}
	if !contains(names, "g:shared@1.1.1") {
		t.Errorf("expected the nearest version, got %v", names)
	}
}

// test and provided scopes are not transitive, and an optional dependency is not inherited: a consumer must
// not be told it depends on another project's test fixtures.
func TestMavenScopeAndOptionalAreNotTransitive(t *testing.T) {
	repo := t.TempDir()
	writePOM(t, repo, "g", "lib", "1.0", `<project><groupId>g</groupId><artifactId>lib</artifactId><version>1.0</version>
  <dependencies>
    <dependency><groupId>g</groupId><artifactId>junit-thing</artifactId><version>1.0</version><scope>test</scope></dependency>
    <dependency><groupId>g</groupId><artifactId>servlet-api</artifactId><version>1.0</version><scope>provided</scope></dependency>
    <dependency><groupId>g</groupId><artifactId>opt</artifactId><version>1.0</version><optional>true</optional></dependency>
    <dependency><groupId>g</groupId><artifactId>real</artifactId><version>1.0</version></dependency>
  </dependencies></project>`)
	for _, a := range []string{"junit-thing", "servlet-api", "opt", "real"} {
		writePOM(t, repo, "g", a, "1.0", `<project><groupId>g</groupId><artifactId>`+a+`</artifactId><version>1.0</version></project>`)
	}
	names, _ := parseMaven(t, repo, t.TempDir(), `<project><groupId>g</groupId><artifactId>app</artifactId><version>0.1</version>
  <dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId><version>1.0</version></dependency></dependencies></project>`)
	for _, bad := range []string{"g:junit-thing@1.0", "g:servlet-api@1.0", "g:opt@1.0"} {
		if contains(names, bad) {
			t.Errorf("%s must not be inherited transitively, got %v", bad, names)
		}
	}
	if !contains(names, "g:real@1.0") {
		t.Errorf("a compile-scope transitive dependency must be resolved, got %v", names)
	}
}

// An <exclusions> block must cut the excluded subtree, or the inventory claims a dependency the build removed.
func TestMavenExclusionsCutTheSubtree(t *testing.T) {
	repo := t.TempDir()
	writePOM(t, repo, "g", "lib", "1.0", `<project><groupId>g</groupId><artifactId>lib</artifactId><version>1.0</version>
  <dependencies><dependency><groupId>g</groupId><artifactId>unwanted</artifactId><version>1.0</version></dependency></dependencies></project>`)
	writePOM(t, repo, "g", "unwanted", "1.0", `<project><groupId>g</groupId><artifactId>unwanted</artifactId><version>1.0</version>
  <dependencies><dependency><groupId>g</groupId><artifactId>deeper</artifactId><version>1.0</version></dependency></dependencies></project>`)
	writePOM(t, repo, "g", "deeper", "1.0", `<project><groupId>g</groupId><artifactId>deeper</artifactId><version>1.0</version></project>`)

	names, _ := parseMaven(t, repo, t.TempDir(), `<project><groupId>g</groupId><artifactId>app</artifactId><version>0.1</version>
  <dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId><version>1.0</version>
    <exclusions><exclusion><groupId>g</groupId><artifactId>unwanted</artifactId></exclusion></exclusions>
  </dependency></dependencies></project>`)
	for _, bad := range []string{"g:unwanted@1.0", "g:deeper@1.0"} {
		if contains(names, bad) {
			t.Errorf("%s was excluded and must not appear (nor its subtree), got %v", bad, names)
		}
	}
}

// An imported BOM contributes its managed versions, which is how a Spring Cloud project pins its tree.
func TestMavenImportedBOMSuppliesVersions(t *testing.T) {
	repo := t.TempDir()
	writePOM(t, repo, "g", "bom", "2.0", `<project><groupId>g</groupId><artifactId>bom</artifactId><version>2.0</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>g</groupId><artifactId>managed</artifactId><version>4.5.6</version></dependency>
  </dependencies></dependencyManagement></project>`)
	writePOM(t, repo, "g", "managed", "4.5.6", `<project><groupId>g</groupId><artifactId>managed</artifactId><version>4.5.6</version></project>`)

	names, _ := parseMaven(t, repo, t.TempDir(), `<project><groupId>g</groupId><artifactId>app</artifactId><version>0.1</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>g</groupId><artifactId>bom</artifactId><version>2.0</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
  <dependencies><dependency><groupId>g</groupId><artifactId>managed</artifactId></dependency></dependencies></project>`)
	if !contains(names, "g:managed@4.5.6") {
		t.Errorf("an imported BOM must supply the managed version, got %v", names)
	}
}

// With no local repository the parser must keep its previous behaviour exactly: the direct literal versions.
// Trading a known result for a smaller one would be a regression dressed as a feature.
func TestMavenFallsBackToLiteralParseWithoutLocalRepository(t *testing.T) {
	names, edges := parseMaven(t, filepath.Join(t.TempDir(), "absent"), t.TempDir(), `<project>
  <groupId>g</groupId><artifactId>app</artifactId><version>0.1</version>
  <dependencies>
    <dependency><groupId>g</groupId><artifactId>pinned</artifactId><version>1.2.3</version></dependency>
    <dependency><groupId>g</groupId><artifactId>managed-elsewhere</artifactId></dependency>
    <dependency><groupId>g</groupId><artifactId>via-property</artifactId><version>${some.version}</version></dependency>
  </dependencies></project>`)
	if strings.Join(names, ",") != "g:pinned@1.2.3" {
		t.Errorf("without a local repository only the literal version is emitted, got %v", names)
	}
	if len(edges) != 0 {
		t.Errorf("a literal parse must emit no edges; edges are the resolution signal: %v", edges)
	}
}

// A dependency whose version never resolves is skipped, never emitted unversioned: no advisory can match an
// unversioned row, so emitting one reports coverage the scan does not have.
func TestMavenSkipsUnresolvableVersion(t *testing.T) {
	repo := t.TempDir()
	writePOM(t, repo, "g", "known", "1.0", `<project><groupId>g</groupId><artifactId>known</artifactId><version>1.0</version>
  <dependencies><dependency><groupId>g</groupId><artifactId>mystery</artifactId><version>${never.defined}</version></dependency></dependencies></project>`)
	names, _ := parseMaven(t, repo, t.TempDir(), `<project><groupId>g</groupId><artifactId>app</artifactId><version>0.1</version>
  <dependencies><dependency><groupId>g</groupId><artifactId>known</artifactId><version>1.0</version></dependency></dependencies></project>`)
	for _, n := range names {
		if strings.Contains(n, "mystery") {
			t.Errorf("an unresolvable version must be skipped, got %v", names)
		}
	}
}

// A multi-module project's parent often is not installed in the local repository, so the reactor parent has
// to be followed on disk or every module resolves nothing.
func TestMavenFollowsParentByRelativePath(t *testing.T) {
	repo := t.TempDir()
	writePOM(t, repo, "g", "dep", "3.3.3", `<project><groupId>g</groupId><artifactId>dep</artifactId><version>3.3.3</version></project>`)
	rootDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootDir, "pom.xml"), []byte(`<project>
  <groupId>g</groupId><artifactId>reactor</artifactId><version>1.0</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>g</groupId><artifactId>dep</artifactId><version>3.3.3</version></dependency>
  </dependencies></dependencyManagement></project>`), 0o644); err != nil {
		t.Fatal(err)
	}
	moduleDir := filepath.Join(rootDir, "service")
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	names, _ := parseMaven(t, repo, moduleDir, `<project>
  <parent><groupId>g</groupId><artifactId>reactor</artifactId><version>1.0</version></parent>
  <artifactId>service</artifactId>
  <dependencies><dependency><groupId>g</groupId><artifactId>dep</artifactId></dependency></dependencies></project>`)
	if !contains(names, "g:dep@3.3.3") {
		t.Errorf("the reactor parent must be followed on disk for its managed versions, got %v", names)
	}
}

// A BOM pins its own modules with ${project.version}, and its managed entries are inherited by every project
// that imports it. Interpolating such an entry with the INHERITING project's properties substituted that
// project's own version: on a live service a dependency came out at the scanned project's 0.0.1-SNAPSHOT
// instead of 3.2.5. The declaring POM's properties are what a managed entry must be read with.
func TestMavenManagedVersionUsesTheDeclaringPomProperties(t *testing.T) {
	repo := t.TempDir()
	writePOM(t, repo, "com.vendor", "vendor-bom", "3.2.5", `<project>
  <groupId>com.vendor</groupId><artifactId>vendor-bom</artifactId><version>3.2.5</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.vendor</groupId><artifactId>vendor-core</artifactId><version>${project.version}</version></dependency>
  </dependencies></dependencyManagement></project>`)
	writePOM(t, repo, "com.vendor", "vendor-core", "3.2.5", `<project>
  <groupId>com.vendor</groupId><artifactId>vendor-core</artifactId><version>3.2.5</version></project>`)

	names, _ := parseMaven(t, repo, t.TempDir(), `<project>
  <groupId>io.example</groupId><artifactId>service</artifactId><version>0.0.1-SNAPSHOT</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.vendor</groupId><artifactId>vendor-bom</artifactId><version>3.2.5</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
  <dependencies><dependency><groupId>com.vendor</groupId><artifactId>vendor-core</artifactId></dependency></dependencies></project>`)
	if !contains(names, "com.vendor:vendor-core@3.2.5") {
		t.Errorf("the BOM's ${project.version} must resolve to the BOM's version, got %v", names)
	}
	for _, n := range names {
		if strings.Contains(n, "0.0.1-SNAPSHOT") {
			t.Errorf("the scanned project's own version must not leak into a dependency: %v", names)
		}
	}
}

// The ROOT project's managed version must beat a transitive declaration, which is the whole point of a Spring
// Boot BOM. When the managed entry failed to interpolate it was discarded and the transitive version won, so a
// project resolved jackson 2.12.3 where its own BOM pins 2.13.3: an inventory naming versions the build never
// uses, which then matches the wrong advisories.
func TestMavenRootManagedVersionBeatsTransitiveDeclaration(t *testing.T) {
	repo := t.TempDir()
	writePOM(t, repo, "com.vendor", "platform-bom", "1.0", `<project>
  <groupId>com.vendor</groupId><artifactId>platform-bom</artifactId><version>1.0</version>
  <properties><jackson.version>2.13.3</jackson.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.fasterxml</groupId><artifactId>jackson-core</artifactId><version>${jackson.version}</version></dependency>
  </dependencies></dependencyManagement></project>`)
	writePOM(t, repo, "com.vendor", "lib", "1.0", `<project>
  <groupId>com.vendor</groupId><artifactId>lib</artifactId><version>1.0</version>
  <dependencies><dependency><groupId>com.fasterxml</groupId><artifactId>jackson-core</artifactId><version>2.12.3</version></dependency></dependencies></project>`)
	for _, v := range []string{"2.12.3", "2.13.3"} {
		writePOM(t, repo, "com.fasterxml", "jackson-core", v, `<project>
  <groupId>com.fasterxml</groupId><artifactId>jackson-core</artifactId><version>`+v+`</version></project>`)
	}

	names, _ := parseMaven(t, repo, t.TempDir(), `<project>
  <groupId>io.example</groupId><artifactId>service</artifactId><version>0.1</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.vendor</groupId><artifactId>platform-bom</artifactId><version>1.0</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
  <dependencies><dependency><groupId>com.vendor</groupId><artifactId>lib</artifactId><version>1.0</version></dependency></dependencies></project>`)
	if !contains(names, "com.fasterxml:jackson-core@2.13.3") {
		t.Errorf("the root's managed version must win over the transitive declaration, got %v", names)
	}
	if contains(names, "com.fasterxml:jackson-core@2.12.3") {
		t.Errorf("the transitive version must not survive alongside the managed one, got %v", names)
	}
}

// A BOM's properties must not leak into the importing project's namespace, or a project's own ${…} silently
// resolves to a vendor's value.
func TestMavenImportedBOMPropertiesDoNotLeak(t *testing.T) {
	repo := t.TempDir()
	writePOM(t, repo, "com.vendor", "bom", "1.0", `<project>
  <groupId>com.vendor</groupId><artifactId>bom</artifactId><version>1.0</version>
  <properties><shared.version>9.9.9</shared.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>g</groupId><artifactId>managed</artifactId><version>${shared.version}</version></dependency>
  </dependencies></dependencyManagement></project>`)
	writePOM(t, repo, "g", "managed", "9.9.9", `<project><groupId>g</groupId><artifactId>managed</artifactId><version>9.9.9</version></project>`)
	writePOM(t, repo, "g", "own", "1.2.3", `<project><groupId>g</groupId><artifactId>own</artifactId><version>1.2.3</version></project>`)

	names, _ := parseMaven(t, repo, t.TempDir(), `<project>
  <groupId>io.example</groupId><artifactId>service</artifactId><version>0.1</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.vendor</groupId><artifactId>bom</artifactId><version>1.0</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>g</groupId><artifactId>managed</artifactId></dependency>
    <dependency><groupId>g</groupId><artifactId>own</artifactId><version>${shared.version}</version></dependency>
  </dependencies></project>`)
	if !contains(names, "g:managed@9.9.9") {
		t.Errorf("the BOM's managed entry must still resolve, got %v", names)
	}
	for _, n := range names {
		if n == "g:own@9.9.9" {
			t.Errorf("the importing project's ${shared.version} must not pick up the BOM's value, got %v", names)
		}
	}
}

// The scope a consumer sees depends on the scope of the dependency that PULLED a transitive artifact in, not
// only on how that artifact declares itself. A compile-scope child of a TEST dependency is test scope in the
// consumer. Losing that counted another project's test fixtures as production risk: on one live service 29
// artifacts reached only through test dependencies were scoped production.
func TestMavenTransitiveScopeIsInheritedFromTheRequiringDependency(t *testing.T) {
	repo := t.TempDir()
	writePOM(t, repo, "g", "testkit", "1.0", `<project><groupId>g</groupId><artifactId>testkit</artifactId><version>1.0</version>
  <dependencies><dependency><groupId>g</groupId><artifactId>testkit-core</artifactId><version>1.0</version></dependency></dependencies></project>`)
	writePOM(t, repo, "g", "testkit-core", "1.0", `<project><groupId>g</groupId><artifactId>testkit-core</artifactId><version>1.0</version>
  <dependencies><dependency><groupId>g</groupId><artifactId>testkit-deep</artifactId><version>1.0</version></dependency></dependencies></project>`)
	writePOM(t, repo, "g", "testkit-deep", "1.0", `<project><groupId>g</groupId><artifactId>testkit-deep</artifactId><version>1.0</version></project>`)
	writePOM(t, repo, "g", "runtime-lib", "1.0", `<project><groupId>g</groupId><artifactId>runtime-lib</artifactId><version>1.0</version>
  <dependencies><dependency><groupId>g</groupId><artifactId>runtime-child</artifactId><version>1.0</version></dependency></dependencies></project>`)
	writePOM(t, repo, "g", "runtime-child", "1.0", `<project><groupId>g</groupId><artifactId>runtime-child</artifactId><version>1.0</version></project>`)

	t.Setenv("MAVEN_REPO_LOCAL", repo)
	dir := t.TempDir()
	pom := `<project><groupId>io.example</groupId><artifactId>service</artifactId><version>0.1</version>
  <dependencies>
    <dependency><groupId>g</groupId><artifactId>testkit</artifactId><version>1.0</version><scope>test</scope></dependency>
    <dependency><groupId>g</groupId><artifactId>runtime-lib</artifactId><version>1.0</version></dependency>
  </dependencies></project>`
	path := filepath.Join(dir, "pom.xml")
	if err := os.WriteFile(path, []byte(pom), 0o644); err != nil {
		t.Fatal(err)
	}
	comps, _, err := (Maven{}).Parse(context.Background(), ParseInput{Dir: dir, Path: path, Content: []byte(pom)})
	if err != nil {
		t.Fatal(err)
	}
	scopeOf := map[string]string{}
	for _, c := range comps {
		scopeOf[c.Name] = c.Scope
	}
	for _, name := range []string{"g:testkit", "g:testkit-core", "g:testkit-deep"} {
		if scopeOf[name] != "test" {
			t.Errorf("%s is reachable only through a test dependency, so it must be test scope, got %q", name, scopeOf[name])
		}
	}
	// A compile-scope branch is unaffected: it must stay production, or the fix would hide real risk.
	for _, name := range []string{"g:runtime-lib", "g:runtime-child"} {
		if scopeOf[name] == "test" {
			t.Errorf("%s is a compile-scope dependency and must not be demoted to test", name)
		}
	}
}

// Among several imported BOMs the FIRST declaration decides an artifact, which is Maven's rule. Letting a
// later import overwrite an earlier one resolved spring-retry to the version an older transitively imported
// Boot BOM pins rather than the one the project's own BOM pins.
func TestMavenFirstImportedBOMWins(t *testing.T) {
	repo := t.TempDir()
	writePOM(t, repo, "com.vendor", "bom-new", "2.0", `<project>
  <groupId>com.vendor</groupId><artifactId>bom-new</artifactId><version>2.0</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>g</groupId><artifactId>shared</artifactId><version>1.3.3</version></dependency>
  </dependencies></dependencyManagement></project>`)
	writePOM(t, repo, "com.vendor", "bom-old", "1.0", `<project>
  <groupId>com.vendor</groupId><artifactId>bom-old</artifactId><version>1.0</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>g</groupId><artifactId>shared</artifactId><version>1.3.1</version></dependency>
  </dependencies></dependencyManagement></project>`)
	for _, v := range []string{"1.3.1", "1.3.3"} {
		writePOM(t, repo, "g", "shared", v, `<project><groupId>g</groupId><artifactId>shared</artifactId><version>`+v+`</version></project>`)
	}
	names, _ := parseMaven(t, repo, t.TempDir(), `<project>
  <groupId>io.example</groupId><artifactId>service</artifactId><version>0.1</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.vendor</groupId><artifactId>bom-new</artifactId><version>2.0</version><type>pom</type><scope>import</scope></dependency>
    <dependency><groupId>com.vendor</groupId><artifactId>bom-old</artifactId><version>1.0</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
  <dependencies><dependency><groupId>g</groupId><artifactId>shared</artifactId></dependency></dependencies></project>`)
	if !contains(names, "g:shared@1.3.3") {
		t.Errorf("the first imported BOM must decide the version, got %v", names)
	}
}

// A POM's OWN explicit entry still beats every import, which is the escape hatch a project uses to pin a
// version its BOMs disagree about.
func TestMavenOwnManagedEntryBeatsAnImport(t *testing.T) {
	repo := t.TempDir()
	writePOM(t, repo, "com.vendor", "bom", "1.0", `<project>
  <groupId>com.vendor</groupId><artifactId>bom</artifactId><version>1.0</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>g</groupId><artifactId>shared</artifactId><version>1.0.0</version></dependency>
  </dependencies></dependencyManagement></project>`)
	for _, v := range []string{"1.0.0", "2.0.0"} {
		writePOM(t, repo, "g", "shared", v, `<project><groupId>g</groupId><artifactId>shared</artifactId><version>`+v+`</version></project>`)
	}
	names, _ := parseMaven(t, repo, t.TempDir(), `<project>
  <groupId>io.example</groupId><artifactId>service</artifactId><version>0.1</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.vendor</groupId><artifactId>bom</artifactId><version>1.0</version><type>pom</type><scope>import</scope></dependency>
    <dependency><groupId>g</groupId><artifactId>shared</artifactId><version>2.0.0</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies><dependency><groupId>g</groupId><artifactId>shared</artifactId></dependency></dependencies></project>`)
	if !contains(names, "g:shared@2.0.0") {
		t.Errorf("the project's own managed entry must beat an imported one, got %v", names)
	}
}

// ${project.parent.version} is how a multi-module release pins its own siblings, and it differs from
// ${project.version} when a module carries its own version. swagger-core declares swagger-models and
// swagger-annotations that way, so without it those two artifacts went unresolved on 8 of 10 live services.
func TestMavenResolvesProjectParentVersionProperty(t *testing.T) {
	repo := t.TempDir()
	writePOM(t, repo, "io.swagger.core.v3", "swagger-project", "2.1.7", `<project>
  <groupId>io.swagger.core.v3</groupId><artifactId>swagger-project</artifactId><version>2.1.7</version></project>`)
	writePOM(t, repo, "io.swagger.core.v3", "swagger-core", "2.1.7", `<project>
  <parent><groupId>io.swagger.core.v3</groupId><artifactId>swagger-project</artifactId><version>2.1.7</version></parent>
  <artifactId>swagger-core</artifactId>
  <dependencies>
    <dependency><groupId>io.swagger.core.v3</groupId><artifactId>swagger-models</artifactId><version>${project.parent.version}</version></dependency>
    <dependency><groupId>io.swagger.core.v3</groupId><artifactId>swagger-annotations</artifactId><version>${project.parent.version}</version></dependency>
  </dependencies></project>`)
	for _, a := range []string{"swagger-models", "swagger-annotations"} {
		writePOM(t, repo, "io.swagger.core.v3", a, "2.1.7", `<project>
  <groupId>io.swagger.core.v3</groupId><artifactId>`+a+`</artifactId><version>2.1.7</version></project>`)
	}
	names, _ := parseMaven(t, repo, t.TempDir(), `<project>
  <groupId>io.example</groupId><artifactId>service</artifactId><version>0.1</version>
  <dependencies><dependency><groupId>io.swagger.core.v3</groupId><artifactId>swagger-core</artifactId><version>2.1.7</version></dependency></dependencies></project>`)
	for _, want := range []string{"io.swagger.core.v3:swagger-models@2.1.7", "io.swagger.core.v3:swagger-annotations@2.1.7"} {
		if !contains(names, want) {
			t.Errorf("expected %s, got %v", want, names)
		}
	}
}

// A module with its OWN version must not have ${project.parent.version} collapse onto it, or a sibling pinned
// to the parent release resolves to the module's version instead.
func TestMavenParentVersionDiffersFromProjectVersion(t *testing.T) {
	repo := t.TempDir()
	writePOM(t, repo, "g", "reactor", "5.0.0", `<project><groupId>g</groupId><artifactId>reactor</artifactId><version>5.0.0</version></project>`)
	writePOM(t, repo, "g", "module", "1.2.3", `<project>
  <parent><groupId>g</groupId><artifactId>reactor</artifactId><version>5.0.0</version></parent>
  <artifactId>module</artifactId><version>1.2.3</version>
  <dependencies><dependency><groupId>g</groupId><artifactId>sibling</artifactId><version>${project.parent.version}</version></dependency></dependencies></project>`)
	for _, v := range []string{"1.2.3", "5.0.0"} {
		writePOM(t, repo, "g", "sibling", v, `<project><groupId>g</groupId><artifactId>sibling</artifactId><version>`+v+`</version></project>`)
	}
	names, _ := parseMaven(t, repo, t.TempDir(), `<project>
  <groupId>io.example</groupId><artifactId>service</artifactId><version>0.1</version>
  <dependencies><dependency><groupId>g</groupId><artifactId>module</artifactId><version>1.2.3</version></dependency></dependencies></project>`)
	if !contains(names, "g:sibling@5.0.0") {
		t.Errorf("${project.parent.version} must be the parent's version, got %v", names)
	}
	if contains(names, "g:sibling@1.2.3") {
		t.Errorf("the module's own version must not be substituted, got %v", names)
	}
}
