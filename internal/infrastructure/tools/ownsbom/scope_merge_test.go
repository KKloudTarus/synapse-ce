package ownsbom

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// walkRecorder wraps a parser and records the order the registry hands it manifests, so a test can show that
// the walk order it relies on really happened.
type walkRecorder struct {
	EcosystemParser
	root string
	seen *[]string
}

func (w walkRecorder) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	rel, err := filepath.Rel(w.root, in.Path)
	if err != nil {
		return nil, nil, err
	}
	*w.seen = append(*w.seen, filepath.ToSlash(rel))
	return w.EcosystemParser.Parse(ctx, in)
}

func junitPOM(artifact, scope string) string {
	return "<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>" + artifact +
		"</artifactId><version>1.0.0</version><dependencies><dependency><groupId>junit</groupId>" +
		"<artifactId>junit</artifactId><version>4.12</version><scope>" + scope + "</scope></dependency>" +
		"</dependencies></project>\n"
}

// One component declared by two manifests is one component, and its scope does not depend on which manifest
// the walk reached first (#1692). Directory names fix the walk order (WalkDir is lexical), and every case is
// run in both orders; the recorder proves the order. Location names the manifest whose scope won.
func TestGenerateMergedScopeDoesNotFollowWalkOrder(t *testing.T) {
	t.Setenv("MAVEN_REPO_LOCAL", filepath.Join(t.TempDir(), "absent")) // the literal pom.xml parse, no local repository
	const (
		gradleTest = "dependencies {\n    testImplementation 'junit:junit:4.12'\n}\n"
		gradleProd = "dependencies {\n    implementation 'junit:junit:4.12'\n}\n"
	)
	cases := []struct {
		name          string
		first, second string // manifests in walk order
		files         map[string]string
		scope, from   string
	}{
		{"gradle: test-only module walked first", "a/build.gradle", "b/build.gradle",
			map[string]string{"a/build.gradle": gradleTest, "b/build.gradle": gradleProd}, sbom.ScopeProduction, "b/build.gradle"},
		{"gradle: production module walked first", "a/build.gradle", "b/build.gradle",
			map[string]string{"a/build.gradle": gradleProd, "b/build.gradle": gradleTest}, sbom.ScopeProduction, "a/build.gradle"},
		{"maven: test-scope module walked first", "a/pom.xml", "b/pom.xml",
			map[string]string{"a/pom.xml": junitPOM("a", "test"), "b/pom.xml": junitPOM("b", "compile")}, sbom.ScopeProduction, "b/pom.xml"},
		{"maven: compile-scope module walked first", "a/pom.xml", "b/pom.xml",
			map[string]string{"a/pom.xml": junitPOM("a", "compile"), "b/pom.xml": junitPOM("b", "test")}, sbom.ScopeProduction, "a/pom.xml"},
		// A background scope survives when every copy is background. A Gradle test configuration is test scope,
		// as a Maven test-scope dependency is, so the two agree; with an example module (example scope) the copies
		// are all background and the first one's label stands.
		{"gradle test configuration and maven test scope agree", "a/build.gradle", "b/pom.xml",
			map[string]string{"a/build.gradle": gradleTest, "b/pom.xml": junitPOM("b", "test")}, sbom.ScopeTest, "a/build.gradle"},
		{"example module walked first, then a test configuration", "demo/pom.xml", "service/build.gradle",
			map[string]string{"demo/pom.xml": junitPOM("demo", "compile"), "service/build.gradle": gradleTest}, sbom.ScopeExample, "demo/pom.xml"},
		{"test configuration walked first, then an example module", "app/build.gradle", "examples/pom.xml",
			map[string]string{"app/build.gradle": gradleTest, "examples/pom.xml": junitPOM("examples", "compile")}, sbom.ScopeTest, "app/build.gradle"},
		{"two background copies stay background", "demo/pom.xml", "examples/pom.xml",
			map[string]string{"demo/pom.xml": junitPOM("demo", "compile"), "examples/pom.xml": junitPOM("examples", "test")}, sbom.ScopeExample, "demo/pom.xml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range tc.files {
				path := filepath.Join(dir, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				mustWrite(t, path, content)
			}
			var walked []string
			reg, err := New(walkRecorder{BuildGradle{}, dir, &walked}, walkRecorder{Maven{}, dir, &walked})
			if err != nil {
				t.Fatal(err)
			}
			doc, err := reg.Generate(context.Background(), dir)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			if want := []string{tc.first, tc.second}; !reflect.DeepEqual(walked, want) {
				t.Fatalf("walk order = %v, want %v", walked, want)
			}
			if len(doc.Components) != 1 {
				t.Fatalf("want one merged component, got %+v", doc.Components)
			}
			c := doc.Components[0]
			if c.Scope != tc.scope {
				t.Errorf("scope = %q, want %q", c.Scope, tc.scope)
			}
			if got := filepath.ToSlash(c.Location); !strings.HasSuffix(got, "/"+tc.from) {
				t.Errorf("location = %q, want the manifest whose scope won (%s)", got, tc.from)
			}
		})
	}
}

// One manifest can name a package twice: npm installs one version at several paths, and a pom.xml can declare a
// coordinate twice. The shared component set keeps one component and lets the merge rule pick its scope, so the
// order of the entries does not decide it.
func TestComponentSetDuplicateMergesScope(t *testing.T) {
	testCopy := sbom.Component{Name: "a", Version: "1", PURL: "pkg:x/a@1", Scope: sbom.ScopeTest}
	prodCopy := sbom.Component{Name: "a", Version: "1", PURL: "pkg:x/a@1", Scope: sbom.ScopeProduction}
	for name, order := range map[string][]sbom.Component{
		"test entry first":       {testCopy, prodCopy},
		"production entry first": {prodCopy, testCopy},
	} {
		s := newComponentSet()
		for _, c := range order {
			s.add(c)
		}
		got := s.components()
		if len(got) != 1 || got[0].Scope != sbom.ScopeProduction {
			t.Errorf("%s: want one production component, got %+v", name, got)
		}
	}
}

// Through a parser: a pom.xml that declares junit twice, test scope first and compile scope second (Maven warns
// about the duplicate and still builds), ships junit.
func TestMavenDuplicateDeclarationShips(t *testing.T) {
	t.Setenv("MAVEN_REPO_LOCAL", filepath.Join(t.TempDir(), "absent"))
	pom := "<project><dependencies>" +
		"<dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version><scope>test</scope></dependency>" +
		"<dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version><scope>compile</scope></dependency>" +
		"</dependencies></project>"
	comps, _, err := (Maven{}).Parse(context.Background(), ParseInput{Path: "pom.xml", Content: []byte(pom)})
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 1 || comps[0].Scope != sbom.ScopeProduction {
		t.Fatalf("want junit once, production, got %+v", comps)
	}
}
