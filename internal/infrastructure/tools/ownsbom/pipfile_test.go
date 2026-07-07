package ownsbom

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

const pipfileLockFixture = `{
  "_meta": {"hash": {"sha256": "abc"}},
  "default": {
    "requests": {"version": "==2.31.0", "hashes": ["sha256:x"]},
    "Django": {"version": "==4.2.0"},
    "somevcs": {"git": "https://example.com/x.git", "ref": "abc"}
  },
  "develop": {
    "pytest": {"version": "==7.4.0"}
  }
}`

func TestPipfileParse(t *testing.T) {
	comps, deps, err := Pipfile{}.Parse(context.Background(), ParseInput{Path: "Pipfile.lock", Content: []byte(pipfileLockFixture)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if deps != nil {
		t.Errorf("components only (no edges); want nil deps, got %v", deps)
	}
	byName := map[string]sbom.Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	// "==" stripped → bare version + pkg:pypi PURL; default → production.
	if c := byName["requests"]; c.Version != "2.31.0" || c.PURL != "pkg:pypi/requests@2.31.0" || c.Scope != sbom.ScopeProduction {
		t.Errorf("requests = %+v, want 2.31.0 / pkg:pypi/requests@2.31.0 / production", c)
	}
	// the "sha256:<hex>" hash is captured as a SHA256 component Checksum; a package with no hashes has none.
	if ck := byName["requests"].Checksums; len(ck) != 1 || ck[0].Algorithm != "SHA256" || ck[0].Value != "x" {
		t.Errorf("requests checksum = %+v, want [{SHA256 x}]", ck)
	}
	if ck := byName["django"].Checksums; len(ck) != 0 {
		t.Errorf("django has no hashes, want no checksum, got %+v", ck)
	}
	// PEP 503 normalization: Django → django.
	if c := byName["django"]; c.Version != "4.2.0" {
		t.Errorf("Django must normalize to django @4.2.0, got %+v", c)
	}
	// develop → development scope.
	if c := byName["pytest"]; c.Version != "7.4.0" || c.Scope != sbom.ScopeDevelopment {
		t.Errorf("pytest = %+v, want 7.4.0 / development", c)
	}
	// a VCS/editable entry (no concrete version) is skipped.
	if _, ok := byName["somevcs"]; ok {
		t.Error("a VCS entry with no concrete version must be skipped")
	}
	if len(comps) != 3 {
		t.Fatalf("want 3 components (requests, django, pytest), got %d: %+v", len(comps), comps)
	}
}

func TestPipfileRejectsBadJSON(t *testing.T) {
	if _, _, err := (Pipfile{}).Parse(context.Background(), ParseInput{Path: "Pipfile.lock", Content: []byte("{not json")}); err == nil {
		t.Error("malformed Pipfile.lock must fail closed")
	}
}
