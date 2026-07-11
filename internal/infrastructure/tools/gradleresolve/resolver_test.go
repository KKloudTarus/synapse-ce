package gradleresolve

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestParseGradleDeps(t *testing.T) {
	// Authentic `gradle dependencies --configuration runtimeClasspath` tree output: tree-drawing
	// prefixes, the "g:a:declared -> resolved" conflict form, "g:a -> resolved" (no declared), a plain
	// "g:a:ver", "(*)" seen-elsewhere + "(c)" constraint + "(n)" not-resolved markers, a `project:x`
	// local module, and a BOM/platform line with no version.
	out := []byte(`
runtimeClasspath - Runtime classpath of source set 'main'.
+--- org.springframework.boot:spring-boot-starter-web:2.7.5
|    +--- org.springframework.boot:spring-boot-starter:2.7.5
|    |    \--- org.springframework:spring-core:5.3.23
|    +--- org.springframework.boot:spring-boot-starter-json:2.7.5 (*)
|    \--- com.fasterxml.jackson.core:jackson-databind:2.13.4 -> 2.13.4.2
+--- org.yaml:snakeyaml:1.30
+--- org.apache.logging.log4j:log4j-api -> 2.17.2
+--- com.example:internal-bom:1.0.0 (c)
+--- project :shared-lib
\--- some.broken:thing (n)
`)
	comps := parseGradleDeps(out)

	got := map[string]string{} // name -> version
	for _, c := range comps {
		got[c.Name] = c.Version
		if !strings.HasPrefix(c.PURL, "pkg:maven/") || c.Scope != sbom.ScopeProduction {
			t.Errorf("bad component: %+v", c)
		}
	}
	want := map[string]string{
		"org.springframework.boot:spring-boot-starter-web":  "2.7.5",
		"org.springframework.boot:spring-boot-starter":      "2.7.5",
		"org.springframework:spring-core":                   "5.3.23",
		"org.springframework.boot:spring-boot-starter-json": "2.7.5",
		"com.fasterxml.jackson.core:jackson-databind":       "2.13.4.2", // resolved (post ->) wins over declared
		"org.yaml:snakeyaml":                                "1.30",
		"org.apache.logging.log4j:log4j-api":                "2.17.2", // "g:a -> resolved", no declared version
	}
	if len(got) != len(want) {
		t.Fatalf("got %d components, want %d: %+v", len(got), len(want), got)
	}
	for name, ver := range want {
		if got[name] != ver {
			t.Errorf("%s = %q, want %q", name, got[name], ver)
		}
	}
	// `(c)` constraint (BOM/platform – not a runtime artifact), `project:shared-lib` (local module),
	// and the `(n)` unresolved entry must ALL be dropped (no phantom components / BOM false positives).
	for name := range got {
		if strings.Contains(name, "internal-bom") || strings.Contains(name, "shared-lib") || strings.Contains(name, "broken") {
			t.Errorf("constraint/non-external/unresolved entry leaked: %q", name)
		}
	}
}

func TestParseGradleDepsEmpty(t *testing.T) {
	if c := parseGradleDeps([]byte("runtimeClasspath\nNo dependencies\n")); len(c) != 0 {
		t.Errorf("want 0 components, got %+v", c)
	}
}

func TestGradleArgsAndHosts(t *testing.T) {
	a := New("gradle").args("/proj")
	for _, want := range []string{"dependencies", "runtimeClasspath", "--no-daemon", "-p"} {
		if !contains(a, want) {
			t.Errorf("args missing %q: %v", want, a)
		}
	}
	hosts := New("gradle").WithRepoHosts([]string{"nexus.corp.local", ""}).allowedHosts()
	if !contains(hosts, "repo1.maven.org") || !contains(hosts, "plugins.gradle.org") || !contains(hosts, "nexus.corp.local") {
		t.Errorf("allowedHosts missing defaults or configured host: %v", hosts)
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

func mkfile(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("// gradle"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBuildRootsSingle(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "build.gradle")
	if roots := buildRoots(dir); len(roots) != 1 || roots[0] != dir {
		t.Fatalf("single build: roots = %v, want [%s]", roots, dir)
	}
}

// A monorepo parent with no root build file but per-build sub-folders must yield each build root.
func TestBuildRootsMonorepo(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, filepath.Join(dir, "svcA"), "build.gradle")
	mkfile(t, filepath.Join(dir, "svcB"), "settings.gradle") // a build root can be marked by settings.gradle
	mkfile(t, filepath.Join(dir, "group", "svcC"), "build.gradle.kts")
	if roots := buildRoots(dir); len(roots) != 3 {
		t.Fatalf("monorepo: got %d roots, want 3: %v", len(roots), roots)
	}
}

// A multi-project build's included sub-project (build.gradle under a settings.gradle root) is NOT a
// separate root – gradle on the root handles it – and Gradle output/build-logic dirs are skipped.
func TestBuildRootsSkipsIncludedAndOutputDirs(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "settings.gradle")                           // the build root
	mkfile(t, dir, "build.gradle")                              // root build script (same dir)
	mkfile(t, filepath.Join(dir, "app"), "build.gradle")        // an included sub-project – must NOT be separate
	mkfile(t, filepath.Join(dir, "build", "x"), "build.gradle") // output dir – must be skipped
	mkfile(t, filepath.Join(dir, "buildSrc"), "build.gradle")   // build logic – must be skipped
	if roots := buildRoots(dir); len(roots) != 1 || roots[0] != dir {
		t.Fatalf("roots = %v, want just the build root [%s]", roots, dir)
	}
}

func TestBuildRootsNone(t *testing.T) {
	if roots := buildRoots(t.TempDir()); len(roots) != 0 {
		t.Fatalf("no build file: roots = %v, want none", roots)
	}
}

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

// Partial failure across independent builds: one resolves, one fails → return the resolved build's
// components AND a non-nil error (caller keeps the tree yet surfaces the gap).
func TestResolvePartialFailureKeepsResolvedPlusError(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, filepath.Join(dir, "svcA"), "build.gradle")
	mkfile(t, filepath.Join(dir, "svcB"), "build.gradle")
	tree := "+--- org.apache.commons:commons-lang3:3.10\n"
	r := New("gradle").WithRunner(fakeRunner{byArgSubstr: map[string]ports.ToolResult{
		filepath.Join(dir, "svcA"): {Stdout: []byte(tree)},                // svcA resolves (matched by -p <root>)
		filepath.Join(dir, "svcB"): {ExitCode: 1, Stderr: []byte("boom")}, // svcB fails
	}})
	comps, err := r.Resolve(context.Background(), dir)
	if err == nil {
		t.Fatal("partial failure must return a non-nil error")
	}
	if len(comps) != 1 || comps[0].Name != "org.apache.commons:commons-lang3" {
		t.Fatalf("partial failure must still return the resolved build's components, got %+v", comps)
	}
}
