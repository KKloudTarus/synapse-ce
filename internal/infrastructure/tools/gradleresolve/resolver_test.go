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
	// The init script emits one `SYNAPSE_DEP group:module:version` line per resolved Maven module (across
	// ALL projects). Gradle also prints help/banner text that must be ignored. Duplicate coords dedup; a
	// 2-part coord, an empty group, and an empty/absent version are dropped.
	out := []byte(`
> Task :help
Welcome to Gradle 9.6.0.
SYNAPSE_DEP org.springframework.boot:spring-boot-starter-web:3.2.5
SYNAPSE_DEP org.springframework:spring-core:6.1.6
SYNAPSE_DEP com.fasterxml.jackson.core:jackson-databind:2.17.0
SYNAPSE_DEP org.springframework.boot:spring-boot-starter-web:3.2.5
SYNAPSE_DEP badcoord-no-colons
SYNAPSE_DEP :missing-group:1.0
SYNAPSE_DEP org.example:lib:
random gradle output org.foo:bar:1.0
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
		"org.springframework.boot:spring-boot-starter-web": "3.2.5",
		"org.springframework:spring-core":                  "6.1.6",
		"com.fasterxml.jackson.core:jackson-databind":      "2.17.0",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d components, want %d: %+v", len(got), len(want), got)
	}
	for name, ver := range want {
		if got[name] != ver {
			t.Errorf("%s = %q, want %q", name, got[name], ver)
		}
	}
	// Malformed coords and non-SYNAPSE_DEP (help/banner) lines must never become components.
	for name := range got {
		if strings.Contains(name, "foo") || strings.Contains(name, "missing-group") || strings.Contains(name, "badcoord") {
			t.Errorf("malformed / non-marker entry leaked: %q", name)
		}
	}
}

func TestParseGradleDepsEmpty(t *testing.T) {
	if c := parseGradleDeps([]byte("> Task :help\nWelcome to Gradle.\nNo dependencies\n")); len(c) != 0 {
		t.Errorf("want 0 components, got %+v", c)
	}
}

func TestGradleArgsAndHosts(t *testing.T) {
	a := New("gradle").args("/proj", "/tmp/x.init.gradle")
	for _, want := range []string{"--init-script", "/tmp/x.init.gradle", "help", "--no-daemon", "-p", "/proj"} {
		if !contains(a, want) {
			t.Errorf("args missing %q: %v", want, a)
		}
	}
	hasTimeout := false
	for _, x := range a {
		if strings.Contains(x, "org.gradle.internal.http.connectionTimeout=") {
			hasTimeout = true
		}
	}
	if !hasTimeout {
		t.Errorf("args missing a short HTTP connection timeout (fail-fast on unreachable repo): %v", a)
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

func TestBuildRootsComposite(t *testing.T) {
	// A composite build (like a service monorepo): the root settings.gradle uses includeBuild for each
	// service, and each service is its OWN build with its own settings.gradle. Every independent build must
	// be discovered; a plain subproject (build.gradle only, under a settings root) must NOT be a root.
	dir := t.TempDir()
	mkfile(t, dir, "settings.gradle")
	mkfile(t, dir, "build.gradle")
	mkfile(t, filepath.Join(dir, "services", "kyc"), "settings.gradle")
	mkfile(t, filepath.Join(dir, "services", "kyc"), "build.gradle")
	mkfile(t, filepath.Join(dir, "services", "acct"), "settings.gradle")
	mkfile(t, filepath.Join(dir, "services", "acct"), "build.gradle")
	mkfile(t, filepath.Join(dir, "shared", "common"), "settings.gradle")
	mkfile(t, filepath.Join(dir, "shared", "common"), "build.gradle")
	mkfile(t, filepath.Join(dir, "shared", "common", "sub"), "build.gradle") // subproject – NOT a root
	if roots := buildRoots(dir); len(roots) != 4 {
		t.Fatalf("composite: got %d roots, want 4 (root + kyc + acct + shared/common): %v", len(roots), roots)
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
	deps := "SYNAPSE_DEP org.apache.commons:commons-lang3:3.10\n" // init-script output form
	r := New("gradle").WithRunner(fakeRunner{byArgSubstr: map[string]ports.ToolResult{
		filepath.Join(dir, "svcA"): {Stdout: []byte(deps)},                // svcA resolves (matched by -p <root>)
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
