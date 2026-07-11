package ownsbom

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestConanMarkers(t *testing.T) {
	markers := Conan{}.Markers()
	hasLock := false
	hasTxt := false
	for _, m := range markers {
		if m == "conan.lock" {
			hasLock = true
		}
		if m == "conanfile.txt" {
			hasTxt = true
		}
	}
	if !hasLock || !hasTxt {
		t.Errorf("Conan parser missing markers, got: %v", markers)
	}
}

const conanfileTxtFullFixture = `
# this is a comment
[options]
openssl/*:shared=True

[requires]
zlib/1.3.1
openssl/3.2.1
poco/[>1.0 <2.0]
boost/1.85.0@company/stable
zlib/1.2.13#revision1
zlib/1.3.1 # inline comment
invalid-reference
openssl/
	# indented comment

[tool_requires]
cmake/3.29.0

[test_requires]
gtest/1.14.0

[generators]
CMakeDeps
`

func TestConanTxtParse(t *testing.T) {
	ctx := context.Background()
	in := ParseInput{Path: "conanfile.txt", Content: []byte(conanfileTxtFullFixture)}

	comps, deps, err := Conan{}.Parse(ctx, in)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if deps != nil {
		t.Errorf("expected no deps, got %v", deps)
	}

	byPURL := make(map[string]sbom.Component)
	for _, c := range comps {
		byPURL[c.PURL] = c
	}

	if len(comps) != 6 {
		t.Fatalf("expected 6 components, got %d: %+v", len(comps), comps)
	}

	expecteds := []struct {
		purl    string
		version string
		scope   string
	}{
		{"pkg:conan/zlib@1.3.1", "1.3.1", sbom.ScopeProduction},
		{"pkg:conan/openssl@3.2.1", "3.2.1", sbom.ScopeProduction},
		{"pkg:conan/boost@1.85.0", "1.85.0", sbom.ScopeProduction},
		{"pkg:conan/zlib@1.2.13", "1.2.13", sbom.ScopeProduction}, // Recipe revision is accepted but omitted from the normalized version and PURL.
		{"pkg:conan/cmake@3.29.0", "3.29.0", sbom.ScopeDevelopment},
		{"pkg:conan/gtest@1.14.0", "1.14.0", sbom.ScopeTest},
	}

	for _, e := range expecteds {
		c, ok := byPURL[e.purl]
		if !ok {
			t.Errorf("missing expected component %s", e.purl)
			continue
		}
		if c.Version != e.version {
			t.Errorf("expected version %s, got %s", e.version, c.Version)
		}
		if c.Scope != e.scope {
			t.Errorf("expected scope %s, got %s", e.scope, c.Scope)
		}
	}

	// Verify deterministic sorting
	for i := 1; i < len(comps); i++ {
		if comps[i-1].PURL > comps[i].PURL {
			t.Errorf("components not sorted: %s > %s", comps[i-1].PURL, comps[i].PURL)
		}
	}
}

func TestConanTxtContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := Conan{}.Parse(ctx, ParseInput{Path: "conanfile.txt", Content: []byte("[requires]\nzlib/1.3.1")})
	if err == nil {
		t.Errorf("expected context error, got nil")
	}
}

func TestConanRegistryGenerate(t *testing.T) {
	dir := t.TempDir()
	conanTxt := `[requires]
zlib/1.3.1`

	// Create a conanfile.txt file in temp dir
	if err := os.WriteFile(filepath.Join(dir, "conanfile.txt"), []byte(conanTxt), 0o644); err != nil {
		t.Fatal(err)
	}

	reg, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry: %v", err)
	}

	doc, err := reg.Generate(context.Background(), dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(doc.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(doc.Components))
	}
	if doc.Components[0].PURL != "pkg:conan/zlib@1.3.1" {
		t.Errorf("expected pkg:conan/zlib@1.3.1, got %s", doc.Components[0].PURL)
	}
}

func TestConanTxtLockfilePrecedence(t *testing.T) {
	dir := t.TempDir()
	conanTxt := `[requires]
duplicate/1.0.0
manifest_only/2.0.0`
	conanLock := `{
  "version": "0.5",
  "requires": [
    "lockfile_only/3.0.0"
  ]
}`

	if err := os.WriteFile(filepath.Join(dir, "conanfile.txt"), []byte(conanTxt), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "conan.lock"), []byte(conanLock), 0o644); err != nil {
		t.Fatal(err)
	}

	reg, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry: %v", err)
	}

	doc, err := reg.Generate(context.Background(), dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Should only parse the lockfile. The manifest components should be absent.
	if len(doc.Components) != 1 {
		t.Fatalf("expected exactly 1 component from lockfile, got %d: %+v", len(doc.Components), doc.Components)
	}
	if doc.Components[0].PURL != "pkg:conan/lockfile_only@3.0.0" {
		t.Errorf("expected lockfile component pkg:conan/lockfile_only@3.0.0, got %s", doc.Components[0].PURL)
	}
}
