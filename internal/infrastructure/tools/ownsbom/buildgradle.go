package ownsbom

import (
	"bufio"
	"bytes"
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
// without a concrete version they cannot be matched against an advisory. Gradle uses Maven coordinates, so
// the components are pkg:maven PURLs. The registry dedups by PURL, so overlap with the resolver/catalog is
// merged rather than double-counted.
type BuildGradle struct{}

func (BuildGradle) Ecosystem() string { return "maven" }
func (BuildGradle) Markers() []string { return []string{"build.gradle", "build.gradle.kts"} }

func (BuildGradle) Parse(_ context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	comps := ParseBuildGradleDeps(in.Content)
	for i := range comps {
		comps[i].Location = in.Path
	}
	return comps, nil, nil
}

var (
	// reDepBlockOpen matches the start of a `dependencies { ... }` block (Groovy or Kotlin DSL).
	reDepBlockOpen = regexp.MustCompile(`(?i)^dependencies\s*\{`)
	// buildGradleCoordRE matches a "group:artifact:version" coordinate inside a quoted string
	// (Groovy '...' or Kotlin "..."). group/artifact use coordinate characters; the version is captured
	// loosely and validated by concreteVersionRE (interpolated/property versions are rejected).
	buildGradleCoordRE = regexp.MustCompile(`["']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^"':\s]+)["']`)
	// concreteVersionRE requires a version beginning with a digit (1.2.3, 20240101-abc, 2.2.2), rejecting
	// ${var}/$var interpolation, version.ref placeholders, and words like "latest.release".
	concreteVersionRE = regexp.MustCompile(`^[0-9][A-Za-z0-9_.+-]*$`)
)

// ParseBuildGradleDeps extracts inline Maven coordinates (with a literal version) from a Gradle build
// script's dependencies { } block(s). It tracks brace depth so coordinates in other blocks (plugins,
// repositories, buildscript, dependencyManagement) are ignored, and dedups by group:artifact@version.
func ParseBuildGradleDeps(data []byte) []sbom.Component {
	var out []sbom.Component
	seen := map[string]bool{}
	collect := func(line string) {
		for _, m := range buildGradleCoordRE.FindAllStringSubmatch(line, -1) {
			group, artifact, ver := m[1], m[2], m[3]
			if !concreteVersionRE.MatchString(ver) {
				continue
			}
			key := group + ":" + artifact + "@" + ver
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, sbom.Component{
				Name:    group + ":" + artifact,
				Version: ver,
				Scope:   sbom.ScopeProduction,
				PURL:    "pkg:maven/" + group + "/" + artifact + "@" + ver,
			})
		}
	}

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	inDeps := false
	depth := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "/*") {
			continue
		}
		opens := strings.Count(line, "{")
		closes := strings.Count(line, "}")
		if !inDeps {
			if !reDepBlockOpen.MatchString(line) {
				continue
			}
			inDeps = true
			depth = opens - closes // the `dependencies {` brace (and any on the same line)
			collect(line)          // rare one-liner `dependencies { implementation '...' }`
			if depth <= 0 {
				inDeps = false
			}
			continue
		}
		collect(line)
		depth += opens - closes
		if depth <= 0 {
			inDeps = false
		}
	}
	return out
}
