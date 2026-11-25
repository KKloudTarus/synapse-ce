package ownsbom

import (
	"reflect"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestParseBuildGradleDeps(t *testing.T) {
	src := `
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.4.3'
}
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'   // BOM-managed, no version -> skip
    implementation 'io.github.openfeign.form:feign-form:3.8.0'          // concrete -> keep
    implementation "com.amazonaws:aws-java-sdk-s3:1.12.371"             // double-quoted -> keep
    testImplementation 'org.junit.jupiter:junit-jupiter:5.8.2'          // keep
    implementation "org.example:lib:${someVersion}"                     // interpolated -> skip
    implementation('io.grpc:grpc-core:1.60.0') { exclude group: 'x' }   // keep, brace on the same line
}
repositories {
    maven { url 'https://repo.example.com/foo' }
}
`
	comps := ParseBuildGradleDeps([]byte(src))
	got := map[string]string{}
	for _, c := range comps {
		got[c.Name] = c.Version
		// testImplementation is a test-only declaration, so the junit-jupiter coordinate is development scope; the
		// rest sit under implementation and stay production.
		wantScope := sbom.ScopeProduction
		if c.Name == "org.junit.jupiter:junit-jupiter" {
			wantScope = sbom.ScopeDevelopment
		}
		if c.PURL == "" || c.Scope != wantScope {
			t.Errorf("component missing PURL or wrong scope (want %s): %+v", wantScope, c)
		}
	}
	want := map[string]string{
		"io.github.openfeign.form:feign-form": "3.8.0",
		"com.amazonaws:aws-java-sdk-s3":       "1.12.371",
		"org.junit.jupiter:junit-jupiter":     "5.8.2",
		"io.grpc:grpc-core":                   "1.60.0",
	}
	if len(comps) != len(want) {
		t.Fatalf("want %d comps, got %d: %+v", len(want), len(comps), comps)
	}
	for name, ver := range want {
		if got[name] != ver {
			t.Errorf("%s: want version %s, got %q", name, ver, got[name])
		}
	}
	for _, bad := range []string{"org.springframework.boot:spring-boot-starter-web", "org.example:lib"} {
		if _, ok := got[bad]; ok {
			t.Errorf("%s must not be extracted (version-less/interpolated)", bad)
		}
	}
	// A grpc-core PURL must be well-formed maven.
	if got := purlOf(comps, "io.grpc:grpc-core"); got != "pkg:maven/io.grpc/grpc-core@1.60.0" {
		t.Errorf("grpc-core PURL wrong: %q", got)
	}
}

func TestParseBuildGradleDepsExcludesBuildscriptAndComments(t *testing.T) {
	src := `
buildscript {
    dependencies {
        classpath 'com.android.tools.build:gradle:8.1.0'          // build-time plugin -> must NOT be emitted
    }
}
dependencies {
    implementation 'real:lib:1.2.3'   // was 'com.fasterxml.jackson.core:jackson-databind:2.9.9' -> comment ignored
    implementation 'dyn:sel:1.+'      // dynamic selector -> must NOT be emitted (phantom-major FP)
    /* implementation 'blocked:out:9.9.9' */
    implementation 'ok:concrete:2.0.0'
}
`
	comps := ParseBuildGradleDeps([]byte(src))
	got := map[string]bool{}
	for _, c := range comps {
		got[c.Name] = true
	}
	for _, want := range []string{"real:lib", "ok:concrete"} {
		if !got[want] {
			t.Errorf("expected %s to be emitted; got %v", want, got)
		}
	}
	for _, bad := range []string{
		"com.android.tools.build:gradle",              // buildscript classpath
		"com.fasterxml.jackson.core:jackson-databind", // trailing-comment coord
		"blocked:out", // block-comment coord
		"dyn:sel",     // dynamic version 1.+
	} {
		if got[bad] {
			t.Errorf("%s must NOT be emitted", bad)
		}
	}
	if len(comps) != 2 {
		t.Errorf("want exactly 2 components (real:lib, ok:concrete), got %d: %+v", len(comps), comps)
	}
}

// scopesOf indexes components by group:artifact@version so a case can compare the whole scope assignment.
func scopesOf(comps []sbom.Component) map[string]string {
	out := make(map[string]string, len(comps))
	for _, c := range comps {
		out[c.Name+"@"+c.Version] = c.Scope
	}
	return out
}

func TestParseBuildGradleDepsScope(t *testing.T) {
	const (
		prod = sbom.ScopeProduction
		test = sbom.ScopeDevelopment
	)
	cases := []struct {
		name string
		src  string
		want map[string]string // group:artifact@version -> scope
	}{
		{
			name: "groovy command syntax",
			src: `dependencies {
    implementation 'com.google.guava:guava:31.0-jre'
    testImplementation 'junit:junit:4.12'
}`,
			want: map[string]string{"com.google.guava:guava@31.0-jre": prod, "junit:junit@4.12": test},
		},
		{
			name: "groovy with parentheses and double quotes",
			src: `dependencies {
    implementation('a:prod:1.0')
    testImplementation('a:test:1.0')
    testImplementation("a:testdq:1.0")
}`,
			want: map[string]string{"a:prod@1.0": prod, "a:test@1.0": test, "a:testdq@1.0": test},
		},
		{
			name: "kotlin dsl",
			src: `dependencies {
    implementation("a:prod:1.0")
    testImplementation("a:test:1.0")
    testRuntimeOnly("a:rt:1.0")
}`,
			want: map[string]string{"a:prod@1.0": prod, "a:test@1.0": test, "a:rt@1.0": test},
		},
		{
			// Where a configuration has no generated accessor the Kotlin DSL names it by string. The name
			// belongs to the statement it opens, so it must not carry over to the next declaration.
			name: "kotlin dsl string-named configuration",
			src: `subprojects {
    dependencies {
        "implementation"("a:prod:1.0")
        "testImplementation"("a:test:1.0")
        "implementation"("a:prod2:1.0")
    }
}`,
			want: map[string]string{"a:prod@1.0": prod, "a:test@1.0": test, "a:prod2@1.0": prod},
		},
		{
			name: "platform wrapper keeps the declaring configuration",
			src: `dependencies {
    testImplementation platform('a:bom1:1.0')
    testImplementation(platform("a:bom2:1.0"))
    implementation(platform("a:bom3:1.0"))
    implementation enforcedPlatform('a:bom4:1.0')
}`,
			want: map[string]string{"a:bom1@1.0": test, "a:bom2@1.0": test, "a:bom3@1.0": prod, "a:bom4@1.0": prod},
		},
		{
			name: "argument list spread over several lines",
			src: `dependencies {
    testImplementation(
        'a:one:1.0',
        'a:two:1.0'
    )
    implementation 'a:prod:1.0'
}`,
			want: map[string]string{"a:one@1.0": test, "a:two@1.0": test, "a:prod@1.0": prod},
		},
		{
			name: "groovy list continued after a trailing comma",
			src: `dependencies {
    testImplementation 'a:one:1.0',
                       'a:two:1.0'
    implementation 'a:prod:1.0'
}`,
			want: map[string]string{"a:one@1.0": test, "a:two@1.0": test, "a:prod@1.0": prod},
		},
		{
			name: "configuration closure does not leak into the next declaration",
			src: `dependencies {
    testImplementation('a:test:1.0') {
        exclude group: 'x', module: 'y'
    }
    implementation 'a:prod:1.0'
}`,
			want: map[string]string{"a:test@1.0": test, "a:prod@1.0": prod},
		},
		{
			name: "comments between the configuration and the coordinate",
			src: `dependencies {
    testImplementation 'a:test:1.0' // only for tests
    implementation /* main */ 'a:prod:1.0'
    testImplementation /* again */ 'a:test2:1.0'
}`,
			want: map[string]string{"a:test@1.0": test, "a:prod@1.0": prod, "a:test2@1.0": test},
		},
		{
			name: "statements separated by a semicolon",
			src:  `dependencies { testImplementation 'a:test:1.0'; implementation 'a:prod:1.0' }`,
			want: map[string]string{"a:test@1.0": test, "a:prod@1.0": prod},
		},
		{
			name: "dependencies nested in subprojects and allprojects",
			src: `subprojects {
    apply plugin: 'java'
    dependencies {
        testImplementation 'a:test:1.0'
        implementation 'a:prod:1.0'
    }
}
allprojects { dependencies { testImplementation 'a:test2:1.0' } }`,
			want: map[string]string{"a:test@1.0": test, "a:prod@1.0": prod, "a:test2@1.0": test},
		},
		{
			name: "block nested inside dependencies",
			src: `dependencies {
    constraints {
        implementation('a:constrained:1.0')
    }
    testImplementation 'a:test:1.0'
}`,
			want: map[string]string{"a:constrained@1.0": prod, "a:test@1.0": test},
		},
		{
			name: "buildscript classpath stays excluded",
			src: `buildscript {
    dependencies {
        classpath 'a:plugin:1.0'
        testImplementation 'a:nope:1.0'
    }
}
dependencies { testImplementation 'a:test:1.0' }`,
			want: map[string]string{"a:test@1.0": test},
		},
		{
			name: "statement that does not start with a configuration is production",
			src: `dependencies {
    val extras = listOf("a:extra:1.0")
    testImplementation("a:test:1.0")
}`,
			want: map[string]string{"a:extra@1.0": prod, "a:test@1.0": test},
		},
		{
			name: "test declaration first, production declaration later",
			src: `dependencies {
    testImplementation 'a:both:1.0'
    implementation 'a:both:1.0'
}`,
			want: map[string]string{"a:both@1.0": prod},
		},
		{
			name: "production declaration first, test declaration later",
			src: `dependencies {
    implementation 'a:both:1.0'
    testImplementation 'a:both:1.0'
}`,
			want: map[string]string{"a:both@1.0": prod},
		},
		{
			name: "test then production across separate dependencies blocks",
			src: `dependencies { testImplementation 'a:both:1.0' }
dependencies { api 'a:both:1.0' }`,
			want: map[string]string{"a:both@1.0": prod},
		},
		{
			name: "declared only under test configurations",
			src: `dependencies {
    testImplementation 'a:only:1.0'
    androidTestImplementation 'a:only:1.0'
}`,
			want: map[string]string{"a:only@1.0": test},
		},
		{
			name: "windows line endings",
			src: strings.ReplaceAll(`dependencies {
    testImplementation 'a:test:1.0'
    implementation 'a:prod:1.0'
    testImplementation('a:test2:1.0') // note
    implementation('a:prod2:1.0')
}
`, "\n", "\r\n"),
			want: map[string]string{"a:test@1.0": test, "a:prod@1.0": prod, "a:test2@1.0": test, "a:prod2@1.0": prod},
		},
		{
			name: "same coordinate in both branches of a conditional",
			src: `dependencies {
    if (project.hasProperty('lean')) {
        testImplementation 'a:both:1.0'
    } else {
        implementation 'a:both:1.0'
    }
}`,
			want: map[string]string{"a:both@1.0": prod},
		},
		{
			name: "same artifact at two versions is two components",
			src: `dependencies {
    testImplementation 'a:lib:1.0'
    implementation 'a:lib:2.0'
}`,
			want: map[string]string{"a:lib@1.0": test, "a:lib@2.0": prod},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scopesOf(ParseBuildGradleDeps([]byte(tc.src)))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("scopes mismatch\n got: %v\nwant: %v", got, tc.want)
			}
		})
	}
}

// TestParseBuildGradleDepsConfigurationNames pins which declaration names mean "test only". The rule is the
// lockfile parser's word rule (gradleTestConfiguration): a name is a test configuration when one of its
// camelCase words is "test" or "tests", so an unrelated configuration that merely contains the letters
// (latestImplementation, testing) is not demoted, and the testFixtures family stays production: its
// dependencies are published with the module and reach consumers.
//
// Three rows moved from production to test when the build script adopted that rule (#1692): a custom test suite
// (integrationTestImplementation), the Kotlin Multiplatform jvmTest source set (jvmTestImplementation), and a
// custom configuration named testImplementationExtra. Each has "test" as a word of its name, and the lockfile
// already read the same source sets' classpaths (integrationTestRuntimeClasspath, jvmTestCompileClasspath) as
// test, so the two parsers disagreed on one module.
func TestParseBuildGradleDepsConfigurationNames(t *testing.T) {
	test := []string{
		"testImplementation", "testApi", "testCompileOnly", "testRuntimeOnly", "testAnnotationProcessor",
		"testCompile", "testRuntime", "kaptTest", "kspTest",
		"androidTestImplementation", "androidTestApi", "androidTestCompileOnly", "androidTestRuntimeOnly",
		"androidTestAnnotationProcessor", "androidTestCompile", "androidTestUtil", "kaptAndroidTest",
		"kaptTestDebug", "kspAndroidTest",
		"debugAndroidTestImplementation", "releaseAndroidTestImplementation", "freeDebugAndroidTestImplementation",
		"testDebugImplementation", "testReleaseImplementation", "testFreeDebugImplementation",
		"androidTestDebugImplementation", "debugUnitTestImplementation", "releaseUnitTestImplementation",
		"integrationTestImplementation", "jvmTestImplementation", "testImplementationExtra",
		"functionalTestImplementation",
	}
	prod := []string{
		"implementation", "api", "compile", "runtime", "compileOnly", "runtimeOnly", "annotationProcessor",
		"kapt", "ksp", "debugImplementation", "releaseImplementation", "freeDebugImplementation",
		"latestImplementation", "contestImplementation", "testing", "testingImplementation", "attest",
		"attestImplementation", "protestApi",
		"testFixturesApi", "testFixturesImplementation", "testFixturesCompileOnly", "kaptTestFixtures",
		"classpath",
	}
	check := func(t *testing.T, config, want string) {
		t.Helper()
		for _, decl := range []string{
			config + " 'a:lib:1.0'",         // Groovy command syntax
			config + "('a:lib:1.0')",        // Groovy with parentheses
			config + `("a:lib:1.0")`,        // Kotlin DSL
			`"` + config + `"("a:lib:1.0")`, // Kotlin DSL, configuration named by string
		} {
			src := "dependencies {\n    " + decl + "\n}\n"
			got := scopesOf(ParseBuildGradleDeps([]byte(src)))
			if !reflect.DeepEqual(got, map[string]string{"a:lib@1.0": want}) {
				t.Errorf("%s: got %v, want scope %s", decl, got, want)
			}
		}
	}
	for _, config := range test {
		t.Run(config, func(t *testing.T) { check(t, config, sbom.ScopeDevelopment) })
	}
	for _, config := range prod {
		t.Run(config, func(t *testing.T) { check(t, config, sbom.ScopeProduction) })
	}
}

func TestSplitGradleCoord(t *testing.T) {
	cases := []struct {
		in                       string
		wantOK                   bool
		group, artifact, version string
	}{
		{"g:a:1.2.3", true, "g", "a", "1.2.3"},
		{"g:a:1.0@aar", true, "g", "a", "1.0"},    // @ext stripped
		{"g:a:1.0:jar", true, "g", "a", "1.0"},    // classifier ignored (version is 3rd part)
		{"g:a", false, "", "", ""},                // version-less (BOM)
		{"g:a:${v}", false, "", "", ""},           // interpolated
		{"g:a:1.+", false, "", "", ""},            // dynamic
		{"g:a:latest.release", false, "", "", ""}, // word
	}
	for _, c := range cases {
		g, a, v, ok := splitGradleCoord(c.in)
		if ok != c.wantOK || (ok && (g != c.group || a != c.artifact || v != c.version)) {
			t.Errorf("splitGradleCoord(%q) = (%q,%q,%q,%v), want (%q,%q,%q,%v)", c.in, g, a, v, ok, c.group, c.artifact, c.version, c.wantOK)
		}
	}
}

func purlOf(comps []sbom.Component, name string) string {
	for _, c := range comps {
		if c.Name == name {
			return c.PURL
		}
	}
	return ""
}
