package manifest

import (
	"encoding/xml"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

type pomProject struct {
	Properties struct {
		Entries []pomProp `xml:",any"`
	} `xml:"properties"`
	Dependencies struct {
		Dependency []pomDependency `xml:"dependency"`
	} `xml:"dependencies"`
	DependencyManagement struct {
		Dependencies struct {
			Dependency []pomDependency `xml:"dependency"`
		} `xml:"dependencies"`
	} `xml:"dependencyManagement"`
}

type pomProp struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

// parsePomComponents extracts Maven dependencies (declared + managed) from a
// pom.xml. Syft cannot resolve a Gradle/Maven tree without a lockfile, so these
// DIRECT deps recover real components (which then get vuln + license scanned).
// Property-referenced versions (${x}) are resolved from <properties> when present;
// otherwise the version is left unresolved (still cataloged, flagged unversioned).
func parsePomComponents(data []byte) []sbom.Component {
	var p pomProject
	if err := xml.Unmarshal(data, &p); err != nil {
		return nil
	}
	props := map[string]string{}
	for _, e := range p.Properties.Entries {
		props[e.XMLName.Local] = strings.TrimSpace(e.Value)
	}
	resolve := func(v string) string {
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") {
			if r, ok := props[v[2:len(v)-1]]; ok {
				return r
			}
			return "" // unresolved property reference
		}
		return v
	}
	seen := map[string]int{} // group:artifact@version -> position in out
	var out []sbom.Component
	// declared is true for a <dependencies> entry. Two declarations of one coordinate merge their scopes with
	// sbom.MergeScope, so the order they are written in does not decide whether it ships; a dependencyManagement
	// entry only pins a version, so it never changes the scope of a declared dependency.
	add := func(d pomDependency, scope string, declared bool) {
		g, a := strings.TrimSpace(d.GroupID), strings.TrimSpace(d.ArtifactID)
		if g == "" || a == "" {
			return
		}
		ver := resolve(d.Version)
		key := g + ":" + a + "@" + ver
		if i, dup := seen[key]; dup {
			if declared {
				out[i].Scope = sbom.MergeScope(out[i].Scope, scope)
			}
			return
		}
		seen[key] = len(out)
		comp := sbom.Component{
			Name:    g + ":" + a,
			Version: ver,
			Scope:   scope,
		}
		if ver != "" {
			comp.PURL = "pkg:maven/" + g + "/" + a + "@" + ver
		}
		out = append(out, comp)
	}
	for _, d := range p.Dependencies.Dependency {
		sc := sbom.ScopeProduction
		if strings.EqualFold(d.Scope, "test") {
			sc = sbom.ScopeTest
		} else if strings.EqualFold(d.Scope, "provided") {
			sc = sbom.ScopeDevelopment
		}
		add(d, sc, true)
	}
	for _, d := range p.DependencyManagement.Dependencies.Dependency {
		add(d, sbom.ScopeProduction, false)
	}
	return out
}
