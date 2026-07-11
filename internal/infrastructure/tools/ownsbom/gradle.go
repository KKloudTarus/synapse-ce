package ownsbom

import (
	"bufio"
	"bytes"
	"context"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Gradle is the owned Gradle parser: it reads a Gradle version catalog (gradle/libs.versions.toml)
// into Maven-coordinate components (pkg:maven/<group>/<artifact>@<version>, Name <group>:<artifact>),
// resolving each library's version.ref against the [versions] table. Modern Gradle projects declare deps
// here, which Syft does not resolve from source – so this gives the owned SBOM producer Gradle coverage it
// previously lacked. Its Ecosystem is "maven" (Gradle is a build tool for the Java/Maven package
// ecosystem; the components ARE maven PURLs); its marker is the catalog filename. It shares its parsing
// (ParseGradleCatalog) with the manifest enricher's Syft-enrichment path – ONE Gradle parser, no
// duplication. No third-party TOML library: only the [versions] + [libraries] tables are read.
type Gradle struct{}

// Ecosystem identifies this parser's package ecosystem (Gradle deps are Maven coordinates).
func (Gradle) Ecosystem() string { return "maven" }

// Markers are the manifest basenames Gradle claims.
func (Gradle) Markers() []string { return []string{"libs.versions.toml"} }

// Parse extracts the catalog's declared libraries as maven components, tagging each with the catalog file
// as its Location (the shared ParseGradleCatalog leaves Location unset for the enricher's path).
func (Gradle) Parse(_ context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	comps := ParseGradleCatalog(in.Content)
	for i := range comps {
		comps[i].Location = in.Path
	}
	return comps, nil, nil
}

// ParseGradleCatalog extracts Maven-coordinate dependencies from a Gradle version catalog
// (gradle/libs.versions.toml): the declared [libraries] resolved against the [versions] table, as
// components (Name "group:artifact", pkg:maven PURL when a version resolves). It is the shared, pure parser
// used by BOTH the owned Gradle EcosystemParser (owned generation) AND the manifest enricher
// (Syft-enrichment) – one implementation, two producers. Only the [versions] + [libraries] tables are read;
// a full TOML parse is unnecessary, so no TOML dependency is added.
func ParseGradleCatalog(data []byte) []sbom.Component {
	versions := map[string]string{}
	type lib struct {
		group, artifact, version, versionRef string
	}
	var libs []lib

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	table := ""
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			table = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		key, rhs, ok := gradleSplitKV(line)
		if !ok {
			continue
		}
		switch table {
		case "versions":
			versions[key] = gradleUnquote(rhs)
		case "libraries":
			if l, ok := parseGradleLibraryRHS(rhs); ok {
				libs = append(libs, lib(l))
			}
		}
	}

	seen := map[string]bool{}
	var out []sbom.Component
	for _, l := range libs {
		if l.group == "" || l.artifact == "" {
			continue
		}
		ver := l.version
		if ver == "" && l.versionRef != "" {
			ver = versions[l.versionRef]
		}
		key := l.group + ":" + l.artifact + "@" + ver
		if seen[key] {
			continue
		}
		seen[key] = true
		comp := sbom.Component{Name: l.group + ":" + l.artifact, Version: ver, Scope: sbom.ScopeProduction}
		if ver != "" {
			comp.PURL = "pkg:maven/" + l.group + "/" + l.artifact + "@" + ver
		}
		out = append(out, comp)
	}
	return out
}

type gradleLibCoord struct{ group, artifact, version, versionRef string }

// parseGradleLibraryRHS handles the two common library forms:
//
//	x = "group:artifact:version"
//	x = { module = "group:artifact", version.ref = "k" }
//	x = { group = "g", name = "a", version = "1.2" }
func parseGradleLibraryRHS(rhs string) (gradleLibCoord, bool) {
	rhs = strings.TrimSpace(rhs)
	if strings.HasPrefix(rhs, "\"") {
		parts := strings.Split(gradleUnquote(rhs), ":")
		if len(parts) >= 2 {
			c := gradleLibCoord{group: parts[0], artifact: parts[1]}
			if len(parts) >= 3 {
				c.version = parts[2]
			}
			return c, true
		}
		return gradleLibCoord{}, false
	}
	if strings.HasPrefix(rhs, "{") {
		var c gradleLibCoord
		inner := strings.Trim(rhs, "{}")
		for _, field := range gradleSplitTopLevelCommas(inner) {
			k, v, ok := gradleSplitKV(strings.TrimSpace(field))
			if !ok {
				continue
			}
			switch strings.ToLower(k) {
			case "module":
				if g, a, ok := strings.Cut(gradleUnquote(v), ":"); ok {
					c.group, c.artifact = g, a
				}
			case "group":
				c.group = gradleUnquote(v)
			case "name":
				c.artifact = gradleUnquote(v)
			case "version":
				c.version = gradleUnquote(v)
			case "version.ref":
				c.versionRef = gradleUnquote(v)
			}
		}
		if c.group != "" && c.artifact != "" {
			return c, true
		}
	}
	return gradleLibCoord{}, false
}

func gradleSplitKV(line string) (key, value string, ok bool) {
	i := strings.Index(line, "=")
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

func gradleUnquote(s string) string {
	s = strings.TrimSpace(s)
	return strings.TrimSuffix(strings.TrimPrefix(s, "\""), "\"")
}

// gradleSplitTopLevelCommas splits on commas not inside quotes (inline-table fields).
func gradleSplitTopLevelCommas(s string) []string {
	var out []string
	var b strings.Builder
	inQ := false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
			b.WriteRune(r)
		case r == ',' && !inQ:
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}
