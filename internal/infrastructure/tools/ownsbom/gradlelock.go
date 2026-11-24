package ownsbom

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// GradleLockfile is the owned parser for Gradle's dependency-locking file, gradle.lockfile, which
// `gradle dependencies --write-locks` produces. Every other owned parser reads the pinned result of a
// resolution; this one is the Gradle equivalent, and it is what makes a Gradle project's TRANSITIVE tree
// visible without running Gradle: a build script names only the direct dependencies.
//
// The format is line oriented:
//
//	# comment
//	group:artifact:version=configurationA,configurationB
//	empty=configurationX,configurationY
//
// Each module line is one locked module and the configurations it was resolved in. The final `empty=` line
// lists the configurations that resolved nothing; it carries no component, but it is what Gradle writes for a
// project that locks nothing, so a file holding only that line is a valid, empty lockfile.
//
// Components use the same pkg:maven/<group>/<artifact>@<version> identity as the build-script and catalog
// parsers, so a module those also name collapses into one component in the registry. The lockfile records no
// edges, so none are emitted.
//
// A line that is not one of those shapes is skipped, like the other line-oriented parsers do, so one damaged
// line costs that module and not the file. A file in which NOT ONE line has a recognised shape is an error
// instead: it was present but nothing was read from it, and returning no components there would be
// indistinguishable from a project that really locks nothing, which is the case that reports a complete scan.
type GradleLockfile struct{}

// Ecosystem identifies this parser's package ecosystem (Gradle deps are Maven coordinates).
func (GradleLockfile) Ecosystem() string { return "maven" }

// Markers are the lockfile basenames this parser claims. The per-configuration files older Gradle versions
// wrote under gradle/dependency-locks/, and the buildscript/settings lockfiles, are different files and are
// deliberately not claimed.
func (GradleLockfile) Markers() []string { return []string{"gradle.lockfile"} }

// Parse extracts the locked modules as maven components, tagged with the lockfile path.
func (GradleLockfile) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	// The registry has already refused a file over maxManifestBytes; the scanner's line cap bounds the rest.
	sc := bufio.NewScanner(bytes.NewReader(in.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)

	type locked struct {
		comp     sbom.Component
		testOnly bool // true while every configuration seen for this module is a test classpath
	}
	var order []string
	byPURL := map[string]*locked{}
	recognised := false

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, configs, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok {
			continue
		}
		if key == "empty" {
			recognised = true // a valid lockfile that locks nothing in these configurations
			continue
		}
		group, artifact, version, ok := splitGradleLockCoord(key)
		if !ok {
			continue
		}
		recognised = true
		purl := "pkg:maven/" + group + "/" + artifact + "@" + version
		testOnly := gradleTestOnly(configs)
		if cur, seen := byPURL[purl]; seen {
			cur.testOnly = cur.testOnly && testOnly // the same module on two lines: test only if every line is
			continue
		}
		order = append(order, purl)
		byPURL[purl] = &locked{
			comp:     sbom.Component{Name: group + ":" + artifact, Version: version, PURL: purl, Location: in.Path},
			testOnly: testOnly,
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan gradle.lockfile: %w", err)
	}
	if !recognised {
		return nil, nil, errors.New("gradle.lockfile holds no lock entry (group:artifact:version=configurations) and no empty= line, so nothing was read from it")
	}

	comps := make([]sbom.Component, 0, len(order))
	for _, purl := range order {
		l := byPURL[purl]
		l.comp.Scope = sbom.ScopeProduction
		if l.testOnly {
			l.comp.Scope = sbom.ScopeDevelopment
		}
		comps = append(comps, l.comp)
	}
	return comps, nil, nil
}

// splitGradleLockCoord splits "group:artifact:version". Gradle writes exactly three parts; anything else is
// not a lock entry. The parts end up inside a package URL, so a character that has a meaning there is refused
// rather than letting one line forge a different identity.
func splitGradleLockCoord(s string) (group, artifact, version string, ok bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return "", "", "", false
	}
	for _, p := range parts {
		if p == "" || strings.ContainsAny(p, "/@?#%=") || strings.IndexFunc(p, unicode.IsSpace) >= 0 || strings.IndexFunc(p, unicode.IsControl) >= 0 {
			return "", "", "", false
		}
	}
	return parts[0], parts[1], parts[2], true
}

// gradleTestOnly reports whether a module is test-only: it was resolved in at least one configuration and
// EVERY configuration it was resolved in is a test classpath. A module also on a production classpath ships,
// so it stays production; a module with no configuration listed cannot be shown to be test-only, so it also
// stays production. Both default to the side that never hides a dependency.
//
// A test classpath is scoped development: the scope an npm devDependency gets and the one the build-script
// parser gives a testImplementation declaration. Development scope is not exempt from the gate, so classifying a
// module here never hides it from --fail-on.
func gradleTestOnly(configs string) bool {
	n := 0
	for _, c := range strings.Split(configs, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !gradleTestConfiguration(c) {
			return false
		}
		n++
	}
	return n > 0
}

// gradleTestConfiguration reports whether a Gradle configuration name is a test classpath. Gradle names are
// camelCase compositions (testCompileClasspath, debugUnitTestRuntimeClasspath, integrationTestRuntimeClasspath),
// so the name is split into its words and counts as a test configuration when one of them is exactly "test" or "tests". Matching the word, not the substring, is the point: a source set
// called "latest" yields latestRuntimeClasspath, which contains the letters "test" and is production.
//
// The testFixtures classpaths are not test configurations: java-test-fixtures publishes those dependencies with
// the module for other modules' tests, so they are not private to this module's tests. The build-script parser
// makes the same call for testFixturesImplementation.
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
