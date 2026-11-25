package ownsbom

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// TestGradleParsersShareTheTestConfigurationRule feeds the same configuration name to both Gradle parsers, as a
// build-script declaration and as a lockfile classpath, and requires the same scope from each. The names cover
// both parsers' tables, so a parser that grows its own rule again fails here.
func TestGradleParsersShareTheTestConfigurationRule(t *testing.T) {
	test := []string{
		// declaration names
		"testImplementation", "testRuntimeOnly", "kaptTest", "kspAndroidTest", "androidTestUtil",
		"debugAndroidTestImplementation", "testFreeDebugImplementation", "debugUnitTestImplementation",
		// custom test suites: the build script now reads them as the lockfile always has
		"integrationTestImplementation", "functionalTestImplementation", "integrationTestsRuntimeOnly",
		// classpath names
		"testCompileClasspath", "debugUnitTestRuntimeClasspath", "integrationTestRuntimeClasspath",
		"debugUITestRuntimeClasspath", "test2RuntimeClasspath",
	}
	prod := []string{
		"implementation", "api", "kapt", "debugImplementation", "latestImplementation", "contestImplementation",
		"attestImplementation", "protestApi", "testing", "testingImplementation",
		"testFixturesApi", "testFixturesImplementation", "kaptTestFixtures", "testFixturesRuntimeClasspath",
		"compileClasspath", "runtimeClasspath", "latestRuntimeClasspath", "testimonialsRuntimeClasspath",
	}
	check := func(t *testing.T, name, want string) {
		t.Helper()
		build := scopesOf(ParseBuildGradleDeps([]byte("dependencies {\n    " + name + " 'g:a:1.0'\n}\n")))["g:a@1.0"]
		locked, err := parseGradleLockfile(t, gradleLockfileHeader+"g:a:1.0="+name+"\n")
		if err != nil || len(locked) != 1 {
			t.Fatalf("lockfile with %s: %v %+v", name, err, locked)
		}
		if build != want || locked[0].Scope != want {
			t.Errorf("%s: build script says %q, lockfile says %q, want %q from both", name, build, locked[0].Scope, want)
		}
	}
	for _, name := range test {
		t.Run(name, func(t *testing.T) { check(t, name, sbom.ScopeTest) })
	}
	for _, name := range prod {
		t.Run(name, func(t *testing.T) { check(t, name, sbom.ScopeProduction) })
	}
}
