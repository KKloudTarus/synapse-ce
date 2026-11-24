package ownsbom

import (
	"context"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// BuildGradle is the owned parser for a Gradle build script's INLINE dependency declarations
// (build.gradle / build.gradle.kts `dependencies { ... }`). It complements the version-catalog parser
// (ownsbom.Gradle, libs.versions.toml) and the runtime resolver (gradleresolve): those cover the catalog
// and the fully-resolved transitive tree, while this recovers coordinates declared directly in the build
// script with a concrete version, so a pinned vulnerable DIRECT dependency is detectable even when the
// resolver cannot run (no JDK, offline, private repo). Only declarations with a literal version are
// emitted; version-less (BOM/platform-managed) and interpolated (${var}) coordinates are skipped, since
// without a concrete version they cannot be matched against an advisory. Coordinates inside a
// `buildscript { }` (build-plugin classpath) are ignored – those are build-time tooling, not runtime
// artifacts. Gradle uses Maven coordinates, so the components are pkg:maven PURLs; the registry dedups by
// PURL, so overlap with the resolver/catalog is merged rather than double-counted. A coordinate declared
// under a test configuration (testImplementation, androidTestImplementation, kaptTest, ...) is development scope,
// the scope an npm devDependency gets; every other declaration is production.
type BuildGradle struct{}

// Ecosystem identifies this parser's package ecosystem (Gradle deps are Maven coordinates).
func (BuildGradle) Ecosystem() string { return "maven" }

// Markers are the build-script basenames this parser claims (Groovy + Kotlin DSL).
func (BuildGradle) Markers() []string { return []string{"build.gradle", "build.gradle.kts"} }

// Parse extracts the build script's inline dependency coordinates, tagging each with the script path.
func (BuildGradle) Parse(_ context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	comps := ParseBuildGradleDeps(in.Content)
	for i := range comps {
		comps[i].Location = in.Path
	}
	return comps, nil, nil
}

// concreteVersionRE requires a version beginning with a digit and containing no `+` (1.2.3, 20240101-abc,
// 2.2.2). `+` is excluded on purpose so a Gradle dynamic selector (1.+, 2.+, 1.0.+) is NOT treated as
// concrete – it has no single version to match and the Maven comparator would collapse `1.+` to the bare
// major `1`, a phantom match. Interpolation (${var}), ranges ([1.0,2.0)) and words (latest.release) are
// rejected by the digit-lead requirement.
var concreteVersionRE = regexp.MustCompile(`^[0-9][A-Za-z0-9_.-]*$`)

// testConfigurationRE matches, on the WHOLE name, the dependency configurations Gradle and the Android and
// kapt/ksp plugins create for a test source set. A name is matched structurally and not by substring, so a
// custom configuration that merely contains "test" (latestImplementation, testing) is left alone. Forms:
//   - <marker>[Variant]<Kind>: the marker is the unit-test source set ("test"), the instrumented one
//     ("androidTest") or a build-type/flavor prefix on either Android test variant ("debugAndroidTest",
//     "freeReleaseUnitTest"); Variant is the capitalised build-type/flavor words that may follow it
//     (testDebugImplementation); Kind is the declaration kind, including the pre-Gradle-7 compile/runtime.
//   - kapt/ksp name the processor configuration after the source set it serves: kaptTest, kaptAndroidTest,
//     kspTestDebug.
//   - androidTestUtil, the instrumented-test helper APKs.
//
// A custom test suite (integrationTestImplementation) is not matched: nothing in its name proves it is not
// shipped, and a name wrongly read as test-only would hide a production dependency from the gate.
var testConfigurationRE = regexp.MustCompile(`^(?:` +
	`(?:test|androidTest|[a-z][A-Za-z0-9]*(?:Android|Unit)Test)(?:[A-Z][A-Za-z0-9]*)?` +
	`(?:Api|Implementation|CompileOnly|CompileOnlyApi|RuntimeOnly|AnnotationProcessor|Compile|Runtime)` +
	`|(?:kapt|ksp)(?:[A-Z][A-Za-z0-9]*)?(?:Android|Unit)?Test(?:[A-Z][A-Za-z0-9]*)?` +
	`|androidTestUtil` +
	`)$`)

// isTestConfiguration reports whether a dependency declared under this configuration name is test-only.
// The testFixtures family is deliberately NOT test-only: java-test-fixtures publishes those dependencies
// with the module and hands them to every consumer's test classpath, so they are API of the published
// artifact and not private to this module's tests.
func isTestConfiguration(name string) bool {
	if strings.Contains(strings.ToLower(name), "fixtures") {
		return false
	}
	return testConfigurationRE.MatchString(name)
}

// ParseBuildGradleDeps extracts inline Maven coordinates (with a literal version) from a Gradle build
// script's dependencies { } block(s). It is a small comment- and string-aware scanner that tracks a stack
// of enclosing block names, so a coordinate is emitted only when it sits inside a `dependencies { }` that
// is NOT nested under `buildscript { }` (build-plugin classpath). Dedups by group:artifact@version.
//
// Each coordinate is scoped by the configuration it is declared under: the first identifier of its
// statement (`testImplementation` in `testImplementation platform('g:a:1')`, or the quoted name in the Kotlin
// DSL's `"testImplementation"("g:a:1")`). A coordinate declared both ways is production whatever the order,
// because it ships: dropping the production declaration would lose it from the gate.
func ParseBuildGradleDeps(data []byte) []sbom.Component {
	var out []sbom.Component
	at := map[string]int{} // group:artifact@version -> index in out
	collect := func(content string, test bool) {
		group, artifact, ver, ok := splitGradleCoord(content)
		if !ok {
			return
		}
		scope := sbom.ScopeProduction
		if test {
			scope = sbom.ScopeDevelopment
		}
		key := group + ":" + artifact + "@" + ver
		if i, dup := at[key]; dup {
			if scope == sbom.ScopeProduction {
				out[i].Scope = scope
			}
			return
		}
		at[key] = len(out)
		out = append(out, sbom.Component{
			Name:    group + ":" + artifact,
			Version: ver,
			Scope:   scope,
			PURL:    "pkg:maven/" + group + "/" + artifact + "@" + ver,
		})
	}

	src := data
	var stack []string              // enclosing block names, e.g. ["buildscript","dependencies"]
	var ident []byte                // identifier accumulated before a '{'
	lastIdent := ""                 // last complete identifier seen (the token before '{' when separated by space)
	var quote byte                  // active quote char (0 = none)
	qStart := -1                    // index just after the opening quote
	inLine, inBlock := false, false // // and /* */ comments
	head := ""                      // first identifier of the current statement: the configuration its coordinates are declared under
	depth := 0                      // open ( and [ in the current statement; a newline inside them does not end it
	var lastSig byte                // last non-blank byte outside strings and comments; a trailing ',' continues the statement
	flushIdent := func() {
		if s := strings.TrimSpace(string(ident)); s != "" {
			lastIdent = s
			if head == "" {
				head = s
			}
		}
		ident = ident[:0]
	}
	newline := func() {
		if depth == 0 && lastSig != ',' {
			head = ""
		}
	}
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case inLine:
			if c == '\n' {
				inLine = false
				newline()
			}
			continue
		case inBlock:
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				inBlock = false
				i++
			}
			continue
		case quote != 0:
			if c == quote {
				content := string(src[qStart:i])
				if head == "" {
					head = content // a statement opened by a string: the Kotlin DSL's "configuration"(...)
				}
				if inRuntimeDeps(stack) {
					collect(content, isTestConfiguration(head))
				}
				lastSig = c
				quote = 0
			}
			continue
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			flushIdent()
			inLine = true
			i++
			continue
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			flushIdent()
			inBlock = true
			i++
			continue
		case c == '\'' || c == '"':
			flushIdent()
			quote = c
			qStart = i + 1
			lastSig = c
			continue
		case isIdentByte(c):
			ident = append(ident, c)
			lastSig = c
			continue
		case c == '{':
			name := strings.TrimSpace(string(ident))
			if name == "" {
				name = lastIdent
			}
			stack = append(stack, name)
			ident = ident[:0]
			lastIdent = ""
			head = "" // what follows is a new statement inside the block
			lastSig = c
			continue
		case c == '}':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			ident = ident[:0]
			lastIdent = ""
			head, depth = "", 0 // closing a block ends every statement in it, even one left unbalanced
			lastSig = c
			continue
		default:
			flushIdent()
			switch c {
			case '(', '[':
				depth++
			case ')', ']':
				if depth > 0 {
					depth--
				}
			case ';':
				head = ""
			case '\n':
				newline()
			}
			if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
				lastSig = c
			}
		}
	}
	return out
}

// inRuntimeDeps reports whether the current block stack is inside a runtime `dependencies { }` block –
// i.e. it contains a "dependencies" frame and no "buildscript" frame (buildscript deps are build-time
// plugin classpath, not runtime artifacts).
func inRuntimeDeps(stack []string) bool {
	deps := false
	for _, s := range stack {
		switch s {
		case "buildscript":
			return false
		case "dependencies":
			deps = true
		}
	}
	return deps
}

// splitGradleCoord parses "group:artifact:version[:classifier]" (optionally with an "@ext" on the
// version), returning the coordinate when the version is concrete. A 2-part "group:artifact" (version
// supplied by a BOM) or any interpolated/dynamic version yields ok=false.
func splitGradleCoord(s string) (group, artifact, version string, ok bool) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) < 3 {
		return "", "", "", false
	}
	group, artifact, version = parts[0], parts[1], parts[2]
	if at := strings.IndexByte(version, '@'); at >= 0 { // drop @ext (e.g. 1.0@aar)
		version = version[:at]
	}
	if group == "" || artifact == "" || !concreteVersionRE.MatchString(version) {
		return "", "", "", false
	}
	return group, artifact, version, true
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '.' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
