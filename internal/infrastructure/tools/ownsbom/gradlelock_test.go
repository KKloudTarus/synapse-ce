package ownsbom

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

const gradleLockfileHeader = "# This is a Gradle generated file for dependency locking.\n" +
	"# Manual edits can break the build and are not advised.\n" +
	"# This file is expected to be part of source control.\n"

func parseGradleLockfile(t *testing.T, content string) ([]sbom.Component, error) {
	t.Helper()
	comps, deps, err := (GradleLockfile{}).Parse(context.Background(), ParseInput{Path: "app/gradle.lockfile", Content: []byte(content)})
	if len(deps) != 0 {
		t.Errorf("a lockfile records no edges, got %+v", deps)
	}
	return comps, err
}

func TestGradleLockfileMarkersAndEcosystem(t *testing.T) {
	p := GradleLockfile{}
	if p.Ecosystem() != "maven" {
		t.Errorf("Gradle deps are maven coordinates; Ecosystem() = %q", p.Ecosystem())
	}
	if m := p.Markers(); len(m) != 1 || m[0] != "gradle.lockfile" {
		t.Errorf("must claim exactly gradle.lockfile, got %v", m)
	}
	reg, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry must build without a marker collision: %v", err)
	}
	if got := reg.MarkerEcosystems()["gradle.lockfile"]; got != "maven" {
		t.Errorf("the default registry must claim gradle.lockfile as maven, got %q", got)
	}
}

func TestGradleLockfileParse(t *testing.T) {
	type want struct{ purl, scope string }
	tests := []struct {
		name    string
		content string
		want    []want
	}{
		{
			name: "modules with their configurations, comments and the empty line",
			content: gradleLockfileHeader +
				"com.google.guava:guava:31.0-jre=compileClasspath,runtimeClasspath\n" +
				"org.slf4j:slf4j-api:1.7.30=compileClasspath,runtimeClasspath,testCompileClasspath,testRuntimeClasspath\n" +
				"empty=annotationProcessor,testAnnotationProcessor\n",
			want: []want{
				{"pkg:maven/com.google.guava/guava@31.0-jre", sbom.ScopeProduction},
				{"pkg:maven/org.slf4j/slf4j-api@1.7.30", sbom.ScopeProduction},
			},
		},
		{
			name: "test only when every configuration is a test classpath",
			content: "org.junit.jupiter:junit-jupiter:5.8.2=testCompileClasspath,testRuntimeClasspath\n" +
				"org.mockito:mockito-core:4.0.0=testRuntimeClasspath,testAnnotationProcessor\n" +
				"commons-io:commons-io:2.8.0=compileClasspath,testCompileClasspath\n" +
				"org.hamcrest:hamcrest:2.2=runtimeClasspath\n",
			want: []want{
				{"pkg:maven/org.junit.jupiter/junit-jupiter@5.8.2", sbom.ScopeTest},
				{"pkg:maven/org.mockito/mockito-core@4.0.0", sbom.ScopeTest},
				{"pkg:maven/commons-io/commons-io@2.8.0", sbom.ScopeProduction},
				{"pkg:maven/org.hamcrest/hamcrest@2.2", sbom.ScopeProduction},
			},
		},
		{
			name: "android variants",
			content: "androidx.test:runner:1.5.2=debugAndroidTestCompileClasspath,debugAndroidTestRuntimeClasspath\n" +
				"junit:junit:4.13.2=debugUnitTestCompileClasspath,debugUnitTestRuntimeClasspath,releaseUnitTestRuntimeClasspath\n" +
				"androidx.core:core:1.9.0=debugCompileClasspath,debugRuntimeClasspath,debugUnitTestRuntimeClasspath\n",
			want: []want{
				{"pkg:maven/androidx.test/runner@1.5.2", sbom.ScopeTest},
				{"pkg:maven/junit/junit@4.13.2", sbom.ScopeTest},
				{"pkg:maven/androidx.core/core@1.9.0", sbom.ScopeProduction},
			},
		},
		{
			// "latest" contains the letters "test"; its classpaths are production.
			name:    "a configuration that only contains the letters test is production",
			content: "g:a:1.0=latestRuntimeClasspath,testRuntimeClasspath\n",
			want:    []want{{"pkg:maven/g/a@1.0", sbom.ScopeProduction}},
		},
		{
			name:    "a module with no configuration listed is not shown to be test only",
			content: "g:a:1.0=\n",
			want:    []want{{"pkg:maven/g/a@1.0", sbom.ScopeProduction}},
		},
		{
			name:    "the same module on two lines is test only only if every line is",
			content: "g:a:1.0=testCompileClasspath\ng:a:1.0=runtimeClasspath\ng:b:2.0=testCompileClasspath\ng:b:2.0=testRuntimeClasspath\n",
			want: []want{
				{"pkg:maven/g/a@1.0", sbom.ScopeProduction},
				{"pkg:maven/g/b@2.0", sbom.ScopeTest},
			},
		},
		{
			name:    "windows line endings and indentation",
			content: "# header\r\n  g:a:1.0=compileClasspath  \r\n\r\nempty=\r\n",
			want:    []want{{"pkg:maven/g/a@1.0", sbom.ScopeProduction}},
		},
		{
			name:    "only the empty line is a valid lockfile with no components",
			content: gradleLockfileHeader + "empty=annotationProcessor,compileClasspath,runtimeClasspath\n",
			want:    nil,
		},
		{
			name:    "an empty line with no configurations is still a valid lockfile",
			content: gradleLockfileHeader + "empty=\n",
			want:    nil,
		},
		{
			// A damaged or hand-edited line costs that module only. Merge-conflict markers are the realistic
			// case: both sides' modules survive and the markers do not become components.
			name: "malformed lines are skipped and the valid ones kept",
			content: "<<<<<<< HEAD\n" +
				"g:ours:1.0=compileClasspath\n" +
				"=======\n" +
				"g:theirs:2.0=compileClasspath\n" +
				">>>>>>> feature\n" +
				"no equals sign here\n" +
				"g:two-parts=compileClasspath\n" +
				"g:a:b:c=compileClasspath\n" +
				":a:1.0=compileClasspath\n" +
				"g::1.0=compileClasspath\n" +
				"g:a:=compileClasspath\n" +
				"g:a:1 .0=compileClasspath\n" +
				"g/x:a:1.0=compileClasspath\n" +
				"g:a@evil:1.0=compileClasspath\n" +
				"g:a:1.0?qualifier=x=compileClasspath\n",
			want: []want{
				{"pkg:maven/g/ours@1.0", sbom.ScopeProduction},
				{"pkg:maven/g/theirs@2.0", sbom.ScopeProduction},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comps, err := parseGradleLockfile(t, tt.content)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(comps) != len(tt.want) {
				t.Fatalf("got %d components, want %d: %+v", len(comps), len(tt.want), comps)
			}
			for i, w := range tt.want {
				c := comps[i]
				if c.PURL != w.purl || c.Scope != w.scope {
					t.Errorf("component %d = %s [%s], want %s [%s]", i, c.PURL, c.Scope, w.purl, w.scope)
				}
				if c.Location != "app/gradle.lockfile" {
					t.Errorf("%s: Location = %q, want the lockfile path", c.PURL, c.Location)
				}
				name := strings.TrimPrefix(c.PURL, "pkg:maven/")
				name = strings.ReplaceAll(name[:strings.LastIndex(name, "@")], "/", ":")
				if c.Name != name || !strings.HasSuffix(c.PURL, "@"+c.Version) {
					t.Errorf("%s: Name/Version = %q/%q do not match the purl", c.PURL, c.Name, c.Version)
				}
			}
		})
	}
}

// A file with no recognisable line was present and nothing was read from it. Returning no components would
// be indistinguishable from a project that really locks nothing, which is reported as a complete scan, so it
// is an error and the registry fails the inventory.
func TestGradleLockfileWithNothingReadableIsAnError(t *testing.T) {
	tests := map[string]string{
		"zero bytes":              "",
		"header only":             gradleLockfileHeader,
		"prose":                   "this is not a gradle lockfile\n",
		"binary noise":            "\x00\x01\x02\xff\xfe binary\n",
		"only malformed lines":    "g:a=compileClasspath\n=======\n<<<<<<< HEAD\n",
		"a json document instead": "{\"dependencies\": {\"g:a\": \"1.0\"}}\n",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			comps, err := parseGradleLockfile(t, content)
			if err == nil {
				t.Fatalf("a lockfile with nothing readable must be an error, got components %+v", comps)
			}
			if !strings.Contains(err.Error(), "gradle.lockfile") {
				t.Errorf("the error must name the file kind, got %v", err)
			}
		})
	}
}

// Reads are bounded like the neighbouring line parsers: a single line beyond the scanner cap is an error, not
// an unbounded allocation, and the registry refuses a file beyond maxManifestBytes before the parser runs.
func TestGradleLockfileLineCap(t *testing.T) {
	long := "g:a:1.0=" + strings.Repeat("c", 5<<20) + "\n"
	if _, err := parseGradleLockfile(t, long); err == nil {
		t.Fatal("a line beyond the scanner cap must be an error")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := (GradleLockfile{}).Parse(cancelled, ParseInput{Content: []byte("g:a:1.0=compileClasspath\n")}); err == nil {
		t.Error("a cancelled context must stop the parse")
	}
}

// The word rule, not a substring rule, decides what a test classpath is.
func TestGradleTestConfiguration(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		// Java and Kotlin
		{"testCompileClasspath", true},
		{"testRuntimeClasspath", true},
		{"testAnnotationProcessor", true},
		{"testFixturesCompileClasspath", false},
		{"testFixturesRuntimeClasspath", false},
		{"integrationTestCompileClasspath", true},
		{"integrationTestsRuntimeClasspath", true},
		{"functionalTestRuntimeClasspath", true},
		{"e2eTestRuntimeClasspath", true},
		{"jvmTestCompileClasspath", true},
		{"test2RuntimeClasspath", true},
		// Android variants and flavours
		{"debugUnitTestCompileClasspath", true},
		{"debugUnitTestRuntimeClasspath", true},
		{"releaseUnitTestRuntimeClasspath", true},
		{"debugAndroidTestCompileClasspath", true},
		{"debugAndroidTestRuntimeClasspath", true},
		{"freeDebugUnitTestRuntimeClasspath", true},
		{"debugUITestRuntimeClasspath", true},
		{"debugUnitTestAnnotationProcessorClasspath", true},
		// production
		{"compileClasspath", false},
		{"runtimeClasspath", false},
		{"annotationProcessor", false},
		{"debugCompileClasspath", false},
		{"debugRuntimeClasspath", false},
		{"releaseRuntimeClasspath", false},
		{"debugAnnotationProcessorClasspath", false},
		{"kotlinCompilerClasspath", false},
		// the letters t-e-s-t inside an unrelated word
		{"latestRuntimeClasspath", false},
		{"contestCompileClasspath", false},
		{"attestRuntimeClasspath", false},
		{"protestClasspath", false},
		{"testimonialsRuntimeClasspath", false},
		{"detestableCompileClasspath", false},
		{"testingRuntimeClasspath", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := gradleTestConfiguration(tt.name); got != tt.want {
			t.Errorf("gradleTestConfiguration(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestCamelCaseWords(t *testing.T) {
	tests := map[string]string{
		"debugUnitTestRuntimeClasspath": "debug unit test runtime classpath",
		"debugUITestRuntimeClasspath":   "debug ui test runtime classpath",
		"test2RuntimeClasspath":         "test 2 runtime classpath",
		"kebab-case_and.dots":           "kebab case and dots",
		"ALLCAPS":                       "allcaps",
		"":                              "",
	}
	for in, want := range tests {
		if got := strings.Join(camelCaseWords(in), " "); got != want {
			t.Errorf("camelCaseWords(%q) = %q, want %q", in, got, want)
		}
	}
}

func generateGradle(t *testing.T, files map[string]string) *sbom.SBOM {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, path, content)
	}
	reg, err := DefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := reg.Generate(context.Background(), dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return doc
}

// The build script's own warning tells a user to generate a lockfile. With both files present the locked
// tree must appear, and a module both name must be one component rather than two.
func TestGradleLockfileMergesWithBuildScript(t *testing.T) {
	doc := generateGradle(t, map[string]string{
		"build.gradle": "dependencies {\n" +
			"    implementation 'com.google.guava:guava:31.0-jre'\n" +
			"    implementation 'org.slf4j:slf4j-api:1.7.30'\n" +
			"}\n",
		"gradle.lockfile": gradleLockfileHeader +
			"com.google.guava:failureaccess:1.0.1=compileClasspath,runtimeClasspath\n" +
			"com.google.guava:guava:31.0-jre=compileClasspath,runtimeClasspath\n" +
			"org.slf4j:slf4j-api:1.7.30=compileClasspath,runtimeClasspath\n" +
			"empty=annotationProcessor\n",
	})
	seen := map[string]int{}
	for _, c := range doc.Components {
		seen[c.PURL]++
	}
	for _, purl := range []string{
		"pkg:maven/com.google.guava/failureaccess@1.0.1", // transitive, only the lockfile names it
		"pkg:maven/com.google.guava/guava@31.0-jre",
		"pkg:maven/org.slf4j/slf4j-api@1.7.30",
	} {
		if seen[purl] != 1 {
			t.Errorf("%s appears %d times, want exactly once: %+v", purl, seen[purl], doc.Components)
		}
	}
	if len(doc.Components) != 3 {
		t.Errorf("want 3 components, got %d: %+v", len(doc.Components), doc.Components)
	}
}

// A multi-module build locks each project separately, so the same module is named by several lockfiles.
func TestGradleLockfileSameModuleInTwoProjectsIsOneComponent(t *testing.T) {
	lock := gradleLockfileHeader + "g:a:1.0=compileClasspath,runtimeClasspath\nempty=\n"
	doc := generateGradle(t, map[string]string{"app/gradle.lockfile": lock, "lib/gradle.lockfile": lock})
	if len(doc.Components) != 1 {
		t.Fatalf("want one component for the shared module, got %d: %+v", len(doc.Components), doc.Components)
	}
}

// Through the registry a lockfile that cannot be read fails the inventory loudly, with its path, as every
// other unparseable manifest does, instead of contributing nothing.
func TestGradleLockfileUnreadableFailsGenerate(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "gradle.lockfile"), "not a lockfile\n")
	reg, err := DefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	_, err = reg.Generate(context.Background(), dir)
	if err == nil || !strings.Contains(err.Error(), "gradle.lockfile") {
		t.Fatalf("Generate must fail naming the lockfile, got %v", err)
	}
}

// A lockfile whose only content is the empty line is read, and holds nothing: the registry succeeds.
func TestGradleLockfileEmptyOnlyGenerates(t *testing.T) {
	doc := generateGradle(t, map[string]string{"gradle.lockfile": gradleLockfileHeader + "empty=compileClasspath,runtimeClasspath\n"})
	if len(doc.Components) != 0 {
		t.Errorf("want no components, got %+v", doc.Components)
	}
}
