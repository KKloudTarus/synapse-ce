package ownsbom

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Maven is the owned Java parser: it reads a pom.xml's DIRECT <dependencies> into maven
// components (pkg:maven/<group>/<artifact>@<version>, Name <group>:<artifact>). Only a LITERAL <version>
// yields a resolved version – a version via ${property} or inherited from a parent / dependencyManagement
// BOM is not resolved here (full parent-chain + property resolution, which needs the companion/parent
// poms via ParseInput.Dir, is not done yet), so those deps are SKIPPED rather than emitted with an
// unresolved version. <scope>test</scope> maps to background test scope. Uses stdlib encoding/xml – and
// because the schema only binds <project><dependencies>, the <dependencyManagement> BOM (version
// constraints, not real deps) is naturally excluded. No third-party library, vendor-neutral.
type Maven struct{}

// Ecosystem identifies this parser's package ecosystem.
func (Maven) Ecosystem() string { return "maven" }

// Markers are the manifest basenames Maven claims.
func (Maven) Markers() []string { return []string{"pom.xml"} }

// Parse extracts the direct dependencies (with literal versions) from a pom.xml as maven components.
func (Maven) Parse(_ context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	var pom struct {
		Dependencies struct {
			Dependency []struct {
				GroupID    string `xml:"groupId"`
				ArtifactID string `xml:"artifactId"`
				Version    string `xml:"version"`
				Scope      string `xml:"scope"`
			} `xml:"dependency"`
		} `xml:"dependencies"`
	}
	if err := xml.Unmarshal(in.Content, &pom); err != nil {
		return nil, nil, fmt.Errorf("parse pom.xml: %w", err)
	}
	baseScope := sbom.ClassifyScope(in.Path, "")
	set := newComponentSet()
	for _, d := range pom.Dependencies.Dependency {
		group := strings.TrimSpace(d.GroupID)
		artifact := strings.TrimSpace(d.ArtifactID)
		version := strings.TrimSpace(d.Version)
		// Skip a dep with no resolvable version: a ${property} ref, or a version inherited from a parent /
		// dependencyManagement BOM (omitted <version>). IsResolvedVersion rejects ${…} (non-digit start).
		if group == "" || artifact == "" || !sbom.IsResolvedVersion(version) {
			continue
		}
		scope := baseScope
		if strings.EqualFold(strings.TrimSpace(d.Scope), "test") {
			scope = sbom.ScopeTest
		}
		set.add(sbom.Component{
			Name:     group + ":" + artifact,
			Version:  version,
			PURL:     "pkg:maven/" + group + "/" + artifact + "@" + version,
			Location: in.Path,
			Scope:    scope,
		})
	}
	return set.components(), nil, nil
}
