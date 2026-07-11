package mavenresolve

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func nameForPURL(comps []sbom.Component, purl string) string {
	for _, c := range comps {
		if c.PURL == purl {
			return c.Name
		}
	}
	return ""
}

func TestParseDependencyList(t *testing.T) {
	// Real `mvn dependency:list` output shape: an [INFO] banner, the resolved coordinates (5- and
	// 6-field forms), a test-scope entry (must be dropped), a duplicate (must collapse), and noise.
	out := []byte(`[INFO] --- maven-dependency-plugin:3.6.1:list ---
[INFO]
[INFO] The following files have been resolved:
[INFO]    org.springframework:spring-core:jar:5.3.15:compile -- module spring.core [auto]
[INFO]    org.yaml:snakeyaml:jar:1.29:runtime
[INFO]    org.apache.tomcat.embed:tomcat-embed-core:jar:9.0.56:compile
[INFO]    com.example:native-lib:jar:linux-x86_64:1.2.3:compile
[INFO]    junit:junit:jar:4.13.2:test
[INFO]    org.springframework:spring-core:jar:5.3.15:compile
[INFO]    something not a coordinate
[INFO] BUILD SUCCESS
`)
	comps := parseDependencyList(out)

	byPURL := map[string]string{} // purl -> version
	for _, c := range comps {
		byPURL[c.PURL] = c.Version
	}
	// compile + runtime resolved; the classifier (6-field) form parses to its version; dedup applied.
	want := map[string]string{
		"pkg:maven/org.springframework/spring-core@5.3.15":           "5.3.15",
		"pkg:maven/org.yaml/snakeyaml@1.29":                          "1.29",
		"pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.56": "9.0.56",
		"pkg:maven/com.example/native-lib@1.2.3":                     "1.2.3", // classifier form: version is the 5th field
	}
	if len(comps) != len(want) {
		t.Fatalf("got %d components, want %d: %+v", len(comps), len(want), comps)
	}
	for purl, ver := range want {
		if byPURL[purl] != ver {
			t.Errorf("missing/with wrong version: %s -> %q (want %q)", purl, byPURL[purl], ver)
		}
	}
	// test-scope junit must be excluded (not shipped)
	if _, ok := byPURL["pkg:maven/junit/junit@4.13.2"]; ok {
		t.Error("test-scope dependency must be dropped")
	}
	// Name must be "group:artifact" (consistent with the other Maven adapters + the owned-advisory key).
	for _, c := range comps {
		if c.Scope == "" || !strings.Contains(c.Name, ":") {
			t.Errorf("component name must be group:artifact + have a scope: %+v", c)
		}
	}
	if byName := nameForPURL(comps, "pkg:maven/org.yaml/snakeyaml@1.29"); byName != "org.yaml:snakeyaml" {
		t.Errorf("Name = %q, want org.yaml:snakeyaml", byName)
	}
}

func TestParseDependencyListEmpty(t *testing.T) {
	if c := parseDependencyList([]byte("[INFO] no deps here\n[INFO] BUILD SUCCESS")); len(c) != 0 {
		t.Errorf("want 0 components from coordinate-free output, got %+v", c)
	}
}

func TestArgsLocalRepo(t *testing.T) {
	base := New("mvn")
	if hasArg(base.args("/x"), "-Dmaven.repo.local") {
		t.Error("no localRepo configured ⇒ no -Dmaven.repo.local flag")
	}
	localRepo, err := filepath.Abs(filepath.FromSlash("/cache/.m2"))
	if err != nil {
		t.Fatal(err)
	}
	withRepo := New("mvn").WithLocalRepo(localRepo)
	if !contains(withRepo.args(filepath.FromSlash("/x")), "-Dmaven.repo.local="+localRepo) {
		t.Errorf("localRepo set ⇒ flag expected, got %v", withRepo.args(filepath.FromSlash("/x")))
	}
	// goal + pom flag always present
	a := base.args("/proj")
	if !contains(a, "dependency:list") || !contains(a, "-f") {
		t.Errorf("args missing goal/pom: %v", a)
	}
}

func TestAllowedHosts(t *testing.T) {
	r := New("mvn").WithRepoHosts([]string{"nexus.corp.local", "", "  repo.spring.io  "})
	hosts := r.allowedHosts()
	want := []string{"repo1.maven.org", "repo.maven.apache.org", "nexus.corp.local", "repo.spring.io"}
	if len(hosts) != len(want) {
		t.Fatalf("allowedHosts = %v, want %v", hosts, want)
	}
	for i, h := range want {
		if hosts[i] != h {
			t.Errorf("host[%d] = %q, want %q", i, hosts[i], h)
		}
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func hasArg(ss []string, prefix string) bool {
	for _, x := range ss {
		if strings.HasPrefix(x, prefix) {
			return true
		}
	}
	return false
}

func TestPomDeclaresModules(t *testing.T) {
	multi := []byte(`<project><modules><module>mod-lib</module><module>mod-app</module></modules></project>`)
	single := []byte(`<project><dependencies><dependency><groupId>g</groupId></dependency></dependencies></project>`)
	if !pomDeclaresModules(multi) {
		t.Error("aggregator POM with <module> must be detected as multi-module")
	}
	if pomDeclaresModules(single) {
		t.Error("single-module POM must NOT be flagged multi-module")
	}
	if pomDeclaresModules(nil) {
		t.Error("nil/unreadable POM must be treated as single-module")
	}
}

func TestArgsMultiModuleOrdering(t *testing.T) {
	// Single-module (no pom on disk → readBounded nil → single): no `install`, just dependency:list.
	single := New("mvn").args("/nonexistent-proj")
	if hasArg(single, "install") {
		t.Errorf("single-module must NOT run install: %v", single)
	}
	if !contains(single, "dependency:list") {
		t.Errorf("single-module must run dependency:list: %v", single)
	}
	// Multi-module: write a real aggregator pom so readBounded sees <module>, then assert install
	// precedes dependency:list (the load-bearing goal order).
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte("<project><modules><module>a</module></modules></project>"), 0o644); err != nil {
		t.Fatal(err)
	}
	multi := New("mvn").args(dir)
	ii, di := indexOf(multi, "install"), indexOf(multi, "dependency:list")
	if ii < 0 || di < 0 || ii >= di {
		t.Errorf("multi-module must run install BEFORE dependency:list: %v", multi)
	}
	if contains(multi, "-DskipTests") || !contains(multi, "-Dmaven.test.skip=true") {
		t.Errorf("multi-module should use maven.test.skip (no test compile), not -DskipTests: %v", multi)
	}
}

func indexOf(ss []string, s string) int {
	for i, x := range ss {
		if x == s {
			return i
		}
	}
	return -1
}

// writePom writes a minimal.pom into a fake Maven local repo at the standard g/a/v layout.
func writePom(t *testing.T, repo, group, artifact, version, body string) {
	t.Helper()
	dir := filepath.Join(repo, filepath.Join(strings.Split(group, ".")...), artifact, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	pom := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<project xmlns="http://maven.apache.org/POM/4.0.0">` + body + `</project>`
	if err := os.WriteFile(filepath.Join(dir, artifact+"-"+version+".pom"), []byte(pom), 0o644); err != nil {
		t.Fatal(err)
	}
}

func licBlock(names ...string) string {
	b := "<licenses>"
	for _, n := range names {
		b += "<license><name>" + n + "</name></license>"
	}
	return b + "</licenses>"
}

// The P1 payoff: the resolver reads the DECLARED license from the resolved.pom, so the component the
// SCA pipeline substitutes for syft's spray carries the single authoritative license.
func TestFillDeclaredLicensesFromPom(t *testing.T) {
	repo := t.TempDir()
	writePom(t, repo, "mysql", "mysql-connector-java", "8.0.21",
		licBlock("The GNU General Public License, v2 with FOSS exception"))
	comps := []sbom.Component{{Name: "mysql:mysql-connector-java", Version: "8.0.21", PURL: "pkg:maven/mysql/mysql-connector-java@8.0.21"}}

	New("mvn").WithLocalRepo(repo).fillDeclaredLicenses(context.Background(), comps)

	if got := comps[0].Licenses; len(got) != 1 || got[0].Name != "The GNU General Public License, v2 with FOSS exception" {
		t.Fatalf("licenses = %+v, want the single declared pom license", got)
	}
	if comps[0].LicenseSource != sbom.LicenseSourceManifest || comps[0].LicenseConfidence != "declared" {
		t.Errorf("provenance = %q/%q, want manifest/declared", comps[0].LicenseSource, comps[0].LicenseConfidence)
	}
}

// A dependency that inherits <licenses> from its parent POM must resolve via the parent chain.
func TestFillDeclaredLicensesInheritedFromParent(t *testing.T) {
	repo := t.TempDir()
	// child pom: no <licenses>, only a <parent>
	writePom(t, repo, "com.acme", "child", "1.0",
		`<parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>2.0</version></parent>`)
	writePom(t, repo, "com.acme", "parent", "2.0", licBlock("Apache License, Version 2.0"))
	comps := []sbom.Component{{Name: "com.acme:child", Version: "1.0"}}

	New("mvn").WithLocalRepo(repo).fillDeclaredLicenses(context.Background(), comps)

	if got := comps[0].Licenses; len(got) != 1 || got[0].Name != "Apache License, Version 2.0" {
		t.Fatalf("licenses = %+v, want the parent-inherited declared license", got)
	}
}

// A coordinate that could escape the repo root must be refused (coords come from untrusted POMs).
func TestPomFilePathTraversalGuard(t *testing.T) {
	repo := "/repo"
	for _, tc := range []struct{ g, a, v string }{
		{"..", "x", "1.0"}, {"com.x", "..", "1.0"}, {"com.x", "x", ".."}, {"", "x", "1.0"},
	} {
		if p := pomFilePath(repo, tc.g, tc.a, tc.v); p != "" {
			t.Errorf("pomFilePath(%q,%q,%q) = %q, want \"\" (unsafe coord refused)", tc.g, tc.a, tc.v, p)
		}
	}
	if p := pomFilePath(repo, "com.google.code.gson", "gson", "2.8.9"); p == "" {
		t.Error("a normal coord must produce a path")
	}
}

// Real-data parity check: if the local ~/.m2 has the mysql pom (populated by a prior resolve), the
// declared license must match what Trivy reports. Skips when the repo/pom isn't present (CI portability).
func TestFillDeclaredLicensesRealM2(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	repo := filepath.Join(home, ".m2", "repository")
	if _, err := os.Stat(filepath.Join(repo, "mysql", "mysql-connector-java", "8.0.21", "mysql-connector-java-8.0.21.pom")); err != nil {
		t.Skip("mysql pom not in local ~/.m2 – skipping real-data check")
	}
	comps := []sbom.Component{{Name: "mysql:mysql-connector-java", Version: "8.0.21"}}
	New("mvn").WithLocalRepo(repo).fillDeclaredLicenses(context.Background(), comps)
	if len(comps[0].Licenses) != 1 || !strings.Contains(comps[0].Licenses[0].Name, "GNU General Public License") {
		t.Fatalf("real ~/.m2 mysql license = %+v, want the single declared GPL license", comps[0].Licenses)
	}
}

func mkpom(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte("<project/>"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestProjectRootsSingleProject(t *testing.T) {
	dir := t.TempDir()
	mkpom(t, dir)
	roots := projectRoots(dir)
	if len(roots) != 1 || roots[0] != dir {
		t.Fatalf("single project: roots = %v, want [%s]", roots, dir)
	}
}

// The P3 fix: a monorepo parent with NO root pom.xml but per-service sub-poms must yield each service
// root (previously the resolver saw no root pom and skipped → severe under-count).
func TestProjectRootsMonorepo(t *testing.T) {
	dir := t.TempDir()
	mkpom(t, filepath.Join(dir, "svcA"))
	mkpom(t, filepath.Join(dir, "svcB"))
	mkpom(t, filepath.Join(dir, "group", "svcC")) // nested one level
	roots := projectRoots(dir)
	if len(roots) != 3 {
		t.Fatalf("monorepo: got %d roots, want 3: %v", len(roots), roots)
	}
}

// A found project's own sub-module is NOT a separate root (mvn on the root handles it), and build-output
// dirs are skipped.
func TestProjectRootsSkipsSubmodulesAndBuildDirs(t *testing.T) {
	dir := t.TempDir()
	mkpom(t, dir)                                    // root project
	mkpom(t, filepath.Join(dir, "module-a"))         // a sub-module – must NOT be a separate root
	mkpom(t, filepath.Join(dir, "target", "shaded")) // build output – must be skipped
	roots := projectRoots(dir)
	if len(roots) != 1 || roots[0] != dir {
		t.Fatalf("roots = %v, want just the top-level project [%s]", roots, dir)
	}
}

func TestProjectRootsNone(t *testing.T) {
	if roots := projectRoots(t.TempDir()); len(roots) != 0 {
		t.Fatalf("no pom anywhere: roots = %v, want none", roots)
	}
}

// fakeRunner returns canned results per root, keyed by a substring expected in the mvn args (-f <root>/pom.xml).
type fakeRunner struct{ byArgSubstr map[string]ports.ToolResult }

func (f fakeRunner) Run(ctx context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	joined := strings.Join(spec.Args, " ")
	for sub, res := range f.byArgSubstr {
		if strings.Contains(joined, sub) {
			return res, nil
		}
	}
	return ports.ToolResult{ExitCode: 1, Stderr: []byte("no canned result")}, nil
}

// Partial failure: in a monorepo where one sub-project resolves and another fails, Resolve must return
// the resolved project's components AND a non-nil error (so the caller keeps the tree yet surfaces the gap).
func TestResolvePartialFailureKeepsResolvedPlusError(t *testing.T) {
	dir := t.TempDir()
	mkpom(t, filepath.Join(dir, "svcA"))
	mkpom(t, filepath.Join(dir, "svcB"))
	depList := "[INFO]    org.apache.commons:commons-lang3:jar:3.10:compile\n[INFO] BUILD SUCCESS\n"
	r := New("mvn").WithRunner(fakeRunner{byArgSubstr: map[string]ports.ToolResult{
		filepath.Join("svcA", "pom.xml"): {Stdout: []byte(depList)},             // svcA resolves
		filepath.Join("svcB", "pom.xml"): {ExitCode: 1, Stderr: []byte("boom")}, // svcB fails
	}})

	comps, err := r.Resolve(context.Background(), dir)
	if err == nil {
		t.Fatal("partial failure must return a non-nil error so the caller can surface it")
	}
	if len(comps) != 1 || comps[0].Name != "org.apache.commons:commons-lang3" {
		t.Fatalf("partial failure must still return the resolved project's components, got %+v", comps)
	}
}
