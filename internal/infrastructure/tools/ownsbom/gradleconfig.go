package ownsbom

import (
	"strings"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// gradleTestScope is the scope both Gradle parsers give a dependency that only test configurations use: test,
// the scope the Maven parser gives <scope>test</scope> (#1692). A test dependency is not in the shipped artifact
// in either build tool, and giving the two different scopes made the same test-only dependency fail the gate in
// a Gradle build and pass it in a Maven one. Test scope is background, so the gate exempts it unless
// --include-test is set; a dependency any production configuration also names stays production, because
// sbom.MergeScope lets production win over every other scope.
const gradleTestScope = sbom.ScopeTest

// gradleTestConfiguration reports whether a Gradle configuration name is a test configuration. It is the one
// rule both Gradle parsers use: the build-script parser asks it about a declaration name (testImplementation,
// kaptAndroidTest, integrationTestImplementation) and the lockfile parser about a resolved classpath name
// (testRuntimeClasspath, debugUnitTestRuntimeClasspath, integrationTestRuntimeClasspath). Two rules used to
// disagree on custom test suites, so one module's dependency got a different scope from its build script than
// from its lockfile (#1692).
//
// Gradle names are camelCase compositions, so the name is split into its words and counts as a test
// configuration when one of them is exactly "test" or "tests". That covers the unit-test and instrumented source
// sets, their build-type and flavor variants (testDebugImplementation, freeDebugUnitTestRuntimeClasspath),
// kapt/ksp processors named after a test source set (kaptTest, kspAndroidTest), androidTestUtil, and custom test
// suites (integrationTest, functionalTest), whose names say what they are in the same way. Matching the word, not
// the substring, is the point: a source set called "latest" yields latestRuntimeClasspath and
// latestImplementation, which contain the letters "test" and are production, as are testing and protestApi.
//
// The testFixtures configurations are not test configurations: java-test-fixtures publishes those dependencies
// with the module and hands them to every consumer's test classpath, so they are API of the published artifact
// and not private to this module's tests.
func gradleTestConfiguration(name string) bool {
	isTest := false
	for _, w := range camelCaseWords(name) {
		switch w {
		case "fixtures":
			return false
		case "test", "tests":
			isTest = true
		}
	}
	return isTest
}

// camelCaseWords splits an identifier into lower-cased words at lower-to-upper transitions, at the end of an
// acronym (UITest -> UI, Test), at letter/digit transitions, and at any non-alphanumeric character.
func camelCaseWords(s string) []string {
	rs := []rune(s)
	var words []string
	start := -1
	flush := func(end int) {
		if start >= 0 && end > start {
			words = append(words, strings.ToLower(string(rs[start:end])))
		}
		start = -1
	}
	for i, r := range rs {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush(i)
			continue
		}
		if start < 0 {
			start = i
			continue
		}
		prev := rs[i-1]
		boundary := unicode.IsDigit(prev) != unicode.IsDigit(r) ||
			(unicode.IsLower(prev) && unicode.IsUpper(r)) ||
			(unicode.IsUpper(prev) && unicode.IsUpper(r) && i+1 < len(rs) && unicode.IsLower(rs[i+1]))
		if boundary {
			flush(i)
			start = i
		}
	}
	flush(len(rs))
	return words
}
