package ownsbom

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

const npmLockV3 = `{
  "name": "app", "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0", "dependencies": {"lodash": "^4"}},
    "node_modules/lodash": {"version": "4.17.21", "integrity": "sha512-lodashhash"},
    "node_modules/mocha": {"version": "10.2.0", "dev": true, "dependencies": {"ms": "^2"}},
    "node_modules/@angular/core": {"version": "17.0.1", "dependencies": {"tslib": "^2", "ms": "^1"}},
    "node_modules/ms": {"version": "2.1.3"},
    "node_modules/tslib": {"version": "2.6.2"},
    "node_modules/@angular/core/node_modules/ms": {"version": "1.0.0"}
  }
}`

func TestNPMParseV3(t *testing.T) {
	comps, deps, err := NPM{}.Parse(context.Background(), ParseInput{Path: "package-lock.json", Content: []byte(npmLockV3)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(comps) != 6 {
		t.Fatalf("want 6 components (root project skipped; the two ms versions are distinct), got %d: %+v", len(comps), comps)
	}
	byName := map[string]sbom.Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	// resolved version + production scope
	if c := byName["lodash"]; c.Version != "4.17.21" || c.PURL != "pkg:npm/lodash@4.17.21" || c.Scope != sbom.ScopeProduction {
		t.Errorf("lodash = %+v, want 4.17.21 / pkg:npm/lodash@4.17.21 / production", c)
	}
	// npm `integrity` (SRI) is captured as a component Checksum.
	if ck := byName["lodash"].Checksums; len(ck) != 1 || ck[0].Algorithm != "SHA512" || ck[0].Value != "lodashhash" {
		t.Errorf("lodash checksum = %+v, want [{SHA512 lodashhash}]", ck)
	}
	// the lock's dev flag maps to ScopeDevelopment
	if c := byName["mocha"]; c.Scope != sbom.ScopeDevelopment {
		t.Errorf("mocha (dev) must be ScopeDevelopment: %+v", c)
	}
	// scoped package: Name keeps @scope/name, PURL percent-encodes the leading @ as %40 (PURL spec)
	if c := byName["@angular/core"]; c.PURL != "pkg:npm/%40angular/core@17.0.1" {
		t.Errorf("scoped PURL = %q, want pkg:npm/%%40angular/core@17.0.1", c.PURL)
	}

	// Edges, with npm's NEAREST-WINS hoisting: @angular/core depends on ms, and a nested
	// node_modules/@angular/core/node_modules/ms@1.0.0 shadows the hoisted node_modules/ms@2.1.3 — so the
	// edge must point at the NEARER 1.0.0, while mocha (no nested ms) resolves to the hoisted 2.1.3.
	on := map[string][]string{}
	for _, d := range deps {
		on[d.Ref] = d.DependsOn
	}
	ng := on["pkg:npm/%40angular/core@17.0.1"]
	if !contains(ng, "pkg:npm/ms@1.0.0") || !contains(ng, "pkg:npm/tslib@2.6.2") {
		t.Errorf("@angular/core must depend on the NESTED ms@1.0.0 (nearest-wins) + tslib@2.6.2, got %v", ng)
	}
	if contains(ng, "pkg:npm/ms@2.1.3") {
		t.Errorf("@angular/core must NOT link the hoisted ms@2.1.3 (it is shadowed by the nested 1.0.0): %v", ng)
	}
	if ms := on["pkg:npm/mocha@10.2.0"]; !contains(ms, "pkg:npm/ms@2.1.3") {
		t.Errorf("mocha (no nested ms) must resolve ms to the hoisted 2.1.3, got %v", ms)
	}
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

const npmLockV1 = `{
  "name": "app", "lockfileVersion": 1,
  "dependencies": {
    "express": {"version": "4.18.2", "dependencies": {
      "accepts": {"version": "1.3.8"}
    }},
    "jest": {"version": "29.0.0", "dev": true}
  }
}`

func TestNPMParseV1Nested(t *testing.T) {
	comps, _, err := NPM{}.Parse(context.Background(), ParseInput{Path: "package-lock.json", Content: []byte(npmLockV1)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byName := map[string]string{}
	for _, c := range comps {
		byName[c.Name] = c.Version
	}
	// the nested transitive (accepts, under express) is recursed, not just the top level
	if byName["express"] != "4.18.2" || byName["accepts"] != "1.3.8" || byName["jest"] != "29.0.0" {
		t.Fatalf("v1 nested recursion wrong: %+v", byName)
	}
	if len(comps) != 3 {
		t.Fatalf("want 3 components (express, accepts, jest), got %d: %+v", len(comps), comps)
	}
}

// TestRegistryMultiEcosystem proves the Registry dispatches different manifests to their parsers and
// merges across ecosystems — go.mod -> GoMod, package-lock.json -> NPM, in one normalized SBOM.
func TestRegistryMultiEcosystem(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "go.mod"), goModFixture)
	sub := filepath.Join(dir, "frontend")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(sub, "package-lock.json"), npmLockV3)

	reg, err := New(GoMod{}, NPM{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	doc, err := reg.Generate(context.Background(), dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var nGo, nNPM int
	for _, c := range doc.Components {
		switch {
		case len(c.PURL) >= 11 && c.PURL[:11] == "pkg:golang/":
			nGo++
		case len(c.PURL) >= 8 && c.PURL[:8] == "pkg:npm/":
			nNPM++
		}
	}
	if nGo != 3 || nNPM != 6 { // npm fixture (npmLockV3) carries 6 components across two ms versions
		t.Fatalf("want 3 go + 6 npm components, got %d go / %d npm: %+v", nGo, nNPM, doc.Components)
	}
}
