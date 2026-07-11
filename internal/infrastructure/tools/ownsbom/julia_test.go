package ownsbom

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// manifest_format 2.0: packages nest under [[deps.Name]]. Dates (a bundled stdlib) has no version.
const juliaManifestV2Fixture = `# This file is machine-generated - editing it directly is not advised
julia_version = "1.9.3"
manifest_format = "2.0"

[[deps.DataFrames]]
deps = ["Missings", "PrettyTables"]
git-tree-sha1 = "04c738083f29f86e62c8afc341f0967d8717bdb8"
uuid = "a93c6f00-e57d-5684-b7b6-d8193f3e46c0"
version = "1.6.1"

[[deps.JSON]]
deps = ["Dates", "Mmap", "Parsers"]
uuid = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"
version = "0.21.4"

[[deps.Dates]]
deps = ["Printf"]
uuid = "ade2ca70-3891-5945-98fb-dc099432e06a"
`

// manifest_format 1.0: packages are top-level [[Name]] array-of-tables.
const juliaManifestV1Fixture = `[[Example]]
git-tree-sha1 = "abc"
uuid = "7876af07-990d-54b4-ab0e-23690620f79a"
version = "0.5.3"
`

func TestJuliaParseFormat2(t *testing.T) {
	comps, deps, err := Julia{}.Parse(context.Background(), ParseInput{Path: "Manifest.toml", Content: []byte(juliaManifestV2Fixture)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if deps != nil {
		t.Errorf("edges not emitted; want nil deps, got %v", deps)
	}
	byName := map[string]sbom.Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	// DataFrames + JSON = 2; Dates (no version, a bundled stdlib) is dropped.
	if len(comps) != 2 {
		t.Fatalf("want 2 components (Dates has no version), got %d (%+v)", len(comps), comps)
	}
	if c := byName["DataFrames"]; c.PURL != "pkg:julia/DataFrames@1.6.1" {
		t.Errorf("DataFrames PURL wrong: %+v", c)
	}
	if _, ok := byName["Dates"]; ok {
		t.Error("a stdlib package with no version must not be emitted")
	}
}

func TestJuliaParseFormat1(t *testing.T) {
	comps, _, err := Julia{}.Parse(context.Background(), ParseInput{Path: "Manifest.toml", Content: []byte(juliaManifestV1Fixture)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(comps) != 1 || comps[0].PURL != "pkg:julia/Example@0.5.3" {
		t.Fatalf("want Example@0.5.3, got %+v", comps)
	}
}

func TestJuliaParseDeterministic(t *testing.T) {
	c1, _, _ := Julia{}.Parse(context.Background(), ParseInput{Path: "Manifest.toml", Content: []byte(juliaManifestV2Fixture)})
	c2, _, _ := Julia{}.Parse(context.Background(), ParseInput{Path: "Manifest.toml", Content: []byte(juliaManifestV2Fixture)})
	if len(c1) != len(c2) {
		t.Fatalf("length mismatch %d vs %d", len(c1), len(c2))
	}
	for i := range c1 {
		if c1[i].PURL != c2[i].PURL {
			t.Errorf("order not deterministic at %d: %q vs %q", i, c1[i].PURL, c2[i].PURL)
		}
	}
}
