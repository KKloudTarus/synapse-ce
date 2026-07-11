package syft

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// canonicalCDX17 is a representative CycloneDX 1.7 document – the open standard Synapse ingests:
// bomFormat + specVersion 1.7, a 1.5+ `metadata.tools.components` block, library components carrying PURLs
// across ecosystems (golang + npm) with a CDX `scope`, and a dependency graph keyed by bom-ref.
const canonicalCDX17 = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "metadata": {"tools": {"components": [{"type": "application", "name": "syft", "version": "1.18.0"}]}},
  "components": [
    {"bom-ref": "ref-app", "type": "library", "name": "github.com/sirupsen/logrus", "version": "1.9.3", "purl": "pkg:golang/github.com/sirupsen/logrus@1.9.3", "scope": "required"},
    {"bom-ref": "ref-dev", "type": "library", "name": "mocha", "version": "10.2.0", "purl": "pkg:npm/mocha@10.2.0", "scope": "excluded"}
  ],
  "dependencies": [
    {"ref": "ref-app", "dependsOn": ["ref-dev"]}
  ]
}`

// TestCycloneDX17Conformance locks the producer adapter against the CycloneDX 1.7
// standard: a real 1.7 document maps to the normalized domain SBOM with PURLs preserved verbatim across
// ecosystems, the CDX `scope` mapped to the domain scope, the generator version read from the 1.7
// metadata, and the dependency graph resolved by bom-ref into PURL edges. Proves we parse the 1.7
// subset we ingest (not the full schema), against a real document rather than hand-crafted minimal JSON.
func TestCycloneDX17Conformance(t *testing.T) {
	comps, deps, ver, err := parseCycloneDX([]byte(canonicalCDX17))
	if err != nil {
		t.Fatalf("parse CDX 1.7: %v", err)
	}
	if len(comps) != 2 {
		t.Fatalf("want 2 components, got %d: %+v", len(comps), comps)
	}
	byPURL := map[string]sbom.Component{}
	for _, c := range comps {
		byPURL[c.PURL] = c
	}
	// PURLs preserved verbatim across ecosystems (golang + npm)
	if _, ok := byPURL["pkg:golang/github.com/sirupsen/logrus@1.9.3"]; !ok {
		t.Fatalf("golang component PURL not preserved: %+v", comps)
	}
	dev, ok := byPURL["pkg:npm/mocha@10.2.0"]
	if !ok {
		t.Fatalf("npm component PURL not preserved: %+v", comps)
	}
	// CDX scope "excluded" (an npm devDependency) maps to the domain ScopeDevelopment
	if dev.Scope != sbom.ScopeDevelopment {
		t.Errorf("CDX excluded must map to ScopeDevelopment, got %q", dev.Scope)
	}
	// generator version read from the 1.7 metadata.tools.components form
	if ver != "1.18.0" {
		t.Errorf("generator version = %q, want 1.18.0", ver)
	}
	// dependency graph resolved by bom-ref into PURL edges
	if len(deps) != 1 || deps[0].Ref != "pkg:golang/github.com/sirupsen/logrus@1.9.3" ||
		len(deps[0].DependsOn) != 1 || deps[0].DependsOn[0] != "pkg:npm/mocha@10.2.0" {
		t.Errorf("dep edge = %+v, want logrus -> [mocha]", deps)
	}
}
