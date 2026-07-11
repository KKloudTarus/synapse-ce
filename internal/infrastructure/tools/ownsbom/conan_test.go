package ownsbom

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Conan 2.x: reference strings under requires / build_requires / python_requires.
const conanLockV2Fixture = `{
  "version": "0.5",
  "requires": [
    "zlib/1.2.13#dd1f9f9e73f5c3d0e9e7f5c8a1234567",
    "openssl/3.1.0@_/_#abcdef"
  ],
  "build_requires": [
    "cmake/3.27.0"
  ],
  "python_requires": []
}`

// Conan 1.x: a graph_lock whose node ref fields carry the same reference strings.
const conanLockV1Fixture = `{
  "version": "0.4",
  "graph_lock": {
    "nodes": {
      "0": {"ref": "app/1.0"},
      "1": {"ref": "boost/1.83.0#rev123"}
    }
  }
}`

func TestConanParseV2(t *testing.T) {
	comps, deps, err := Conan{}.Parse(context.Background(), ParseInput{Path: "conan.lock", Content: []byte(conanLockV2Fixture)})
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
	if len(comps) != 3 {
		t.Fatalf("want 3 components (zlib, openssl, cmake), got %d (%+v)", len(comps), comps)
	}
	if c := byName["zlib"]; c.PURL != "pkg:conan/zlib@1.2.13" {
		t.Errorf("zlib PURL wrong (revision must be stripped): %+v", c)
	}
	if c := byName["openssl"]; c.Version != "3.1.0" {
		t.Errorf("openssl version wrong (user/channel + revision must be stripped): %+v", c)
	}
}

func TestConanParseV1(t *testing.T) {
	comps, _, err := Conan{}.Parse(context.Background(), ParseInput{Path: "conan.lock", Content: []byte(conanLockV1Fixture)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byName := map[string]sbom.Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	if len(comps) != 2 {
		t.Fatalf("want 2 components (app, boost), got %d (%+v)", len(comps), comps)
	}
	if c := byName["boost"]; c.PURL != "pkg:conan/boost@1.83.0" {
		t.Errorf("boost PURL wrong: %+v", c)
	}
}

func TestConanParseDeterministic(t *testing.T) {
	// The 1.x graph_lock nodes map has no inherent order; the parser sorts by PURL for stable output.
	c1, _, _ := Conan{}.Parse(context.Background(), ParseInput{Path: "conan.lock", Content: []byte(conanLockV1Fixture)})
	c2, _, _ := Conan{}.Parse(context.Background(), ParseInput{Path: "conan.lock", Content: []byte(conanLockV1Fixture)})
	if len(c1) != len(c2) {
		t.Fatalf("length mismatch %d vs %d", len(c1), len(c2))
	}
	for i := range c1 {
		if c1[i].PURL != c2[i].PURL {
			t.Errorf("order not deterministic at %d: %q vs %q", i, c1[i].PURL, c2[i].PURL)
		}
	}
}

func TestConanParseMalformed(t *testing.T) {
	if _, _, err := (Conan{}).Parse(context.Background(), ParseInput{Path: "conan.lock", Content: []byte("{bad")}); err == nil {
		t.Error("malformed conan.lock must fail loud")
	}
}
