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
