package manifest

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestEnrichAttachesLockfileChecksums(t *testing.T) {
	// Syft omits per-package integrity for lockfile ecosystems; the enricher backfills it from the lockfile.
	dir := t.TempDir()
	lock := `{"name":"app","lockfileVersion":3,"packages":{
        "":{"name":"app"},
        "node_modules/lodash":{"version":"4.17.21","integrity":"sha512-lodashHASH"}
    }}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},          // Syft-produced, no checksum
		{Name: "hasown", Version: "1.0.0", PURL: "pkg:npm/hasown@1.0.0", SHA1: "abc"}, // already has integrity
	}}
	res := (Enricher{}).Enrich(context.Background(), dir, doc)

	if res.ChecksumsAttached != 1 {
		t.Fatalf("want 1 checksum attached, got %d", res.ChecksumsAttached)
	}
	if ck := doc.Components[0].Checksums; len(ck) != 1 || ck[0].Algorithm != "SHA512" || ck[0].Value != "lodashHASH" {
		t.Errorf("lodash should get the lockfile SHA512, got %+v", ck)
	}
	if len(doc.Components[1].Checksums) != 0 {
		t.Error("a component that already had integrity (SHA1) must not be overwritten")
	}
	found := false
	for _, s := range res.Sources {
		if s == "checksums" {
			found = true
		}
	}
	if !found {
		t.Errorf("Sources should record \"checksums\", got %v", res.Sources)
	}
}

func TestParseGemfileLockEdges(t *testing.T) {
	lock := []byte("GEM\n  remote: https://rubygems.org/\n  specs:\n    actioncable (7.0.4)\n      actionpack (= 7.0.4)\n      nio4r (~> 2.0)\n    actionpack (7.0.4)\n      rack (~> 2.0)\n    nio4r (2.5.8)\n    rack (2.2.4)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (~> 7.0)\n")
	edges := parseGemfileLockEdges(lock)
	byRef := map[string][]string{}
	for _, e := range edges {
		byRef[e.Ref] = e.DependsOn
	}
	ac := byRef["pkg:gem/actioncable@7.0.4"]
	if len(ac) != 2 {
		t.Fatalf("actioncable edges = %v, want 2 (actionpack, nio4r)", ac)
	}
	want := map[string]bool{"pkg:gem/actionpack@7.0.4": true, "pkg:gem/nio4r@2.5.8": true}
	for _, d := range ac {
		if !want[d] {
			t.Errorf("unexpected edge target %q", d)
		}
	}
	if len(byRef["pkg:gem/actionpack@7.0.4"]) != 1 {
		t.Errorf("actionpack should depend on rack")
	}
}

func TestParsePomComponents(t *testing.T) {
	pom := []byte(`<project><properties><junit.version>5.9.0</junit.version></properties>
<dependencies>
<dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>32.1.1-jre</version></dependency>
<dependency><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter</artifactId><version>${junit.version}</version><scope>test</scope></dependency>
</dependencies></project>`)
	comps := parsePomComponents(pom)
	if len(comps) != 2 {
		t.Fatalf("want 2 maven comps, got %d", len(comps))
	}
	var guava, junit *sbom.Component
	for i := range comps {
		switch comps[i].Name {
		case "com.google.guava:guava":
			guava = &comps[i]
		case "org.junit.jupiter:junit-jupiter":
			junit = &comps[i]
		}
	}
	if guava == nil || guava.Version != "32.1.1-jre" || guava.PURL != "pkg:maven/com.google.guava/guava@32.1.1-jre" {
		t.Errorf("guava parsed wrong: %+v", guava)
	}
	if junit == nil || junit.Version != "5.9.0" { // resolved from properties
		t.Errorf("junit version not resolved from properties: %+v", junit)
	}
	if junit == nil || junit.Scope != sbom.ScopeTest {
		t.Errorf("junit scope = %v, want test", junit.Scope)
	}
}

// A pom.xml that declares one coordinate twice ships it if either declaration does, whatever their order; a
// dependencyManagement entry only pins a version, so it does not make a test-scope dependency production.
func TestParsePomComponentsDuplicateDeclarationShips(t *testing.T) {
	dep := func(scope string) string {
		return "<dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version><scope>" + scope + "</scope></dependency>"
	}
	for name, deps := range map[string]string{
		"test declaration first":    dep("test") + dep("compile"),
		"compile declaration first": dep("compile") + dep("test"),
	} {
		comps := parsePomComponents([]byte("<project><dependencies>" + deps + "</dependencies></project>"))
		if len(comps) != 1 || comps[0].Scope != sbom.ScopeProduction {
			t.Errorf("%s: want junit once, production, got %+v", name, comps)
		}
	}
	managed := parsePomComponents([]byte("<project><dependencies>" + dep("test") + "</dependencies>" +
		"<dependencyManagement><dependencies><dependency><groupId>junit</groupId><artifactId>junit</artifactId>" +
		"<version>4.12</version></dependency></dependencies></dependencyManagement></project>"))
	if len(managed) != 1 || managed[0].Scope != sbom.ScopeTest {
		t.Errorf("a managed version must not change a declared test scope, got %+v", managed)
	}
}

// The enricher reads every build script and pom.xml in the tree; a coordinate two modules declare is added once,
// and the walk order of the modules must not decide its scope (#1692).
func TestEnrichMergedScopeDoesNotFollowWalkOrder(t *testing.T) {
	const (
		gradleTest = "dependencies {\n    testImplementation 'junit:junit:4.12'\n}\n"
		gradleProd = "dependencies {\n    implementation 'junit:junit:4.12'\n}\n"
	)
	pom := func(scope string) string {
		return "<project><dependencies><dependency><groupId>junit</groupId><artifactId>junit</artifactId>" +
			"<version>4.12</version><scope>" + scope + "</scope></dependency></dependencies></project>"
	}
	for name, files := range map[string]map[string]string{
		"gradle: test module walked first":       {"a/build.gradle": gradleTest, "b/build.gradle": gradleProd},
		"gradle: production module walked first": {"a/build.gradle": gradleProd, "b/build.gradle": gradleTest},
		"maven: test module walked first":        {"a/pom.xml": pom("test"), "b/pom.xml": pom("compile")},
		"maven: compile module walked first":     {"a/pom.xml": pom("compile"), "b/pom.xml": pom("test")},
	} {
		dir := t.TempDir()
		for rel, content := range files {
			path := filepath.Join(dir, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		doc := &sbom.SBOM{}
		res := (Enricher{}).Enrich(context.Background(), dir, doc)
		if res.ComponentsAdded != 1 || len(doc.Components) != 1 {
			t.Fatalf("%s: want junit added once, got %d: %+v", name, res.ComponentsAdded, doc.Components)
		}
		if doc.Components[0].Scope != sbom.ScopeProduction {
			t.Errorf("%s: scope = %q, want production", name, doc.Components[0].Scope)
		}
	}
}

// (TestParseGradleCatalog moved to ownsbom/gradle_test.go – the catalog parser now lives in ownsbom and is
// shared with this enricher via ownsbom.ParseGradleCatalog.)

func TestParsePnpmScopes(t *testing.T) {
	lock := []byte("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      react:\n        specifier: ^18\n        version: 18.2.0\n    devDependencies:\n      typescript:\n        specifier: ^5\n        version: 5.3.3\n  examples/demo:\n    dependencies:\n      lodash:\n        specifier: ^3\n        version: 3.10.1(patch)\n")
	scopes := parsePnpmScopes(lock)
	if scopes["react@18.2.0"] != sbom.ScopeProduction {
		t.Errorf("react should be production, got %q", scopes["react@18.2.0"])
	}
	if scopes["typescript@5.3.3"] != sbom.ScopeDevelopment {
		t.Errorf("root devDependency typescript should be development, got %q", scopes["typescript@5.3.3"])
	}
	if scopes["lodash@3.10.1"] != sbom.ScopeExample {
		t.Errorf("examples/ lodash should be example (peer suffix stripped), got %q", scopes["lodash@3.10.1"])
	}
}
