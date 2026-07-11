package ownsbom

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

const renvLockFixture = `{
  "R": {
    "Version": "4.3.1",
    "Repositories": [
      {"Name": "CRAN", "URL": "https://cloud.r-project.org"}
    ]
  },
  "Packages": {
    "ggplot2": {
      "Package": "ggplot2",
      "Version": "3.4.4",
      "Source": "Repository",
      "Repository": "CRAN"
    },
    "dplyr": {
      "Package": "dplyr",
      "Version": "1.1.3",
      "Source": "Repository"
    },
    "brokenNoVersion": {
      "Package": "brokenNoVersion"
    }
  }
}`

func TestRenvParse(t *testing.T) {
	comps, deps, err := Renv{}.Parse(context.Background(), ParseInput{Path: "renv.lock", Content: []byte(renvLockFixture)})
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
	// ggplot2 + dplyr = 2; the record with no Version is dropped.
	if len(comps) != 2 {
		t.Fatalf("want 2 components (no-version dropped), got %d (%+v)", len(comps), comps)
	}
	if c := byName["ggplot2"]; c.PURL != "pkg:cran/ggplot2@3.4.4" {
		t.Errorf("ggplot2 PURL wrong: %+v", c)
	}
	if _, ok := byName["brokenNoVersion"]; ok {
		t.Error("a package with no Version must not be emitted")
	}
}

func TestRenvParseDeterministic(t *testing.T) {
	// renv.lock's Packages object has no inherent order; the parser sorts by PURL for stable output.
	c1, _, _ := Renv{}.Parse(context.Background(), ParseInput{Path: "renv.lock", Content: []byte(renvLockFixture)})
	c2, _, _ := Renv{}.Parse(context.Background(), ParseInput{Path: "renv.lock", Content: []byte(renvLockFixture)})
	if len(c1) != len(c2) {
		t.Fatalf("length mismatch %d vs %d", len(c1), len(c2))
	}
	for i := range c1 {
		if c1[i].PURL != c2[i].PURL {
			t.Errorf("order not deterministic at %d: %q vs %q", i, c1[i].PURL, c2[i].PURL)
		}
	}
}

func TestRenvParseMalformed(t *testing.T) {
	if _, _, err := (Renv{}).Parse(context.Background(), ParseInput{Path: "renv.lock", Content: []byte("{bad")}); err == nil {
		t.Error("malformed renv.lock must fail loud")
	}
}
