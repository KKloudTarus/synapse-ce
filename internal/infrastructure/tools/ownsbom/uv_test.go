package ownsbom

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func parseUVTest(t *testing.T, path string, content string) ([]sbom.Component, []sbom.Dependency) {
	t.Helper()

	comps, deps, err := UV{}.Parse(context.Background(), ParseInput{
		Path:    path,
		Content: []byte(content),
	})
	if err != nil {
		t.Fatalf("parse uv.lock: %v", err)
	}

	return comps, deps
}

func TestUVMarkersAndEcosystem(t *testing.T) {
	parser := UV{}
	if parser.Ecosystem() != "pypi" {
		t.Errorf("want ecosystem pypi, got %s", parser.Ecosystem())
	}
	markers := parser.Markers()
	if len(markers) != 1 || markers[0] != "uv.lock" {
		t.Errorf("want exactly one marker uv.lock, got %v", markers)
	}
}

func TestUVParseRegistryComponents(t *testing.T) {
	fixture := `version = 1
revision = 3
requires-python = ">=3.12"

[[package]]
name = "AnyIO"
version = "4.4.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "typing_extensions"
version = "4.12.2"
source = { registry = "https://packages.example.com/simple" }`

	comps, deps := parseUVTest(t, "uv.lock", fixture)

	expectedComps := []sbom.Component{
		{
			Name:     "anyio",
			Version:  "4.4.0",
			PURL:     "pkg:pypi/anyio@4.4.0",
			Location: "uv.lock",
			Scope:    sbom.ScopeProduction,
		},
		{
			Name:     "typing-extensions",
			Version:  "4.12.2",
			PURL:     "pkg:pypi/typing-extensions@4.12.2",
			Location: "uv.lock",
			Scope:    sbom.ScopeProduction,
		},
	}

	if len(comps) != 2 {
		t.Fatalf("want 2 components, got %d", len(comps))
	}

	for i, e := range expectedComps {
		c := comps[i]
		if c.Name != e.Name || c.Version != e.Version || c.PURL != e.PURL || c.Scope != e.Scope || c.Location != e.Location {
			t.Errorf("comp %d: want %+v, got %+v", i, e, c)
		}
	}

	if deps != nil {
		t.Errorf("want nil deps, got %+v", deps)
	}
}

func TestUVParseFieldOrder(t *testing.T) {
	fixture := `[[package]]
source = { registry = "https://pypi.org/simple" }
version = "4.4.0"
name = "AnyIO"

[[package]]
version = "3.10"
source = { registry = "https://pypi.org/simple" }
name = "idna"`

	comps, _ := parseUVTest(t, "uv.lock", fixture)
	if len(comps) != 2 {
		t.Fatalf("want 2 components, got %d", len(comps))
	}
	if comps[0].PURL != "pkg:pypi/anyio@4.4.0" {
		t.Errorf("first component wrong: %s", comps[0].PURL)
	}
	if comps[1].PURL != "pkg:pypi/idna@3.10" {
		t.Errorf("second component wrong: %s", comps[1].PURL)
	}
}

func TestUVParseNameNormalization(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantName string
		wantPURL string
	}{
		{
			name:     "uppercase",
			input:    "AnyIO",
			wantName: "anyio",
			wantPURL: "pkg:pypi/anyio@1.0.0",
		},
		{
			name:     "underscore",
			input:    "typing_extensions",
			wantName: "typing-extensions",
			wantPURL: "pkg:pypi/typing-extensions@1.0.0",
		},
		{
			name:     "dot",
			input:    "zope.interface",
			wantName: "zope-interface",
			wantPURL: "pkg:pypi/zope-interface@1.0.0",
		},
		{
			name:     "separator run",
			input:    "Some__Pkg.Name",
			wantName: "some-pkg-name",
			wantPURL: "pkg:pypi/some-pkg-name@1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := `[[package]]
name = "` + tt.input + `"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }`

			comps, deps := parseUVTest(t, "uv.lock", fixture)

			if len(comps) != 1 {
				t.Fatalf("want 1 component, got %d", len(comps))
			}
			c := comps[0]
			if c.Name != tt.wantName {
				t.Errorf("want name %s, got %s", tt.wantName, c.Name)
			}
			if c.Version != "1.0.0" {
				t.Errorf("want version 1.0.0, got %s", c.Version)
			}
			if c.PURL != tt.wantPURL {
				t.Errorf("want PURL %s, got %s", tt.wantPURL, c.PURL)
			}
			if c.Location != "uv.lock" {
				t.Errorf("want Location uv.lock, got %s", c.Location)
			}
			if c.Scope != sbom.ScopeProduction {
				t.Errorf("want scope %s, got %s", sbom.ScopeProduction, c.Scope)
			}
			if deps != nil {
				t.Errorf("want nil deps, got %v", deps)
			}
		})
	}
}

func TestUVParseRegistryURLDoesNotChangeIdentity(t *testing.T) {
	fixture := `[[package]]
name = "AnyIO"
version = "4.4.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "anyio"
version = "4.4.0"
source = { registry = "https://private.example.com/simple" }`

	comps, _ := parseUVTest(t, "uv.lock", fixture)
	if len(comps) != 1 {
		t.Fatalf("want 1 component, got %d", len(comps))
	}
	if comps[0].PURL != "pkg:pypi/anyio@4.4.0" {
		t.Errorf("want pkg:pypi/anyio@4.4.0, got %s", comps[0].PURL)
	}
}

func TestUVParseRegistryPathSource(t *testing.T) {
	fixture := `[[package]]
name = "internal-wheel"
version = "1.2.3"
source = { registry = "../wheelhouse" }`
	comps, _ := parseUVTest(t, "uv.lock", fixture)
	if len(comps) != 1 {
		t.Fatalf("want 1 component, got %d", len(comps))
	}
	if comps[0].PURL != "pkg:pypi/internal-wheel@1.2.3" {
		t.Errorf("want pkg:pypi/internal-wheel@1.2.3, got %s", comps[0].PURL)
	}
}

func TestUVParseSourcePolicy(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{
			name: "registry",
			line: `source = { registry = "https://pypi.org/simple" }`,
			want: true,
		},
		{
			name: "git",
			line: `source = { git = "https://github.com/org/repo?rev=abc" }`,
			want: false,
		},
		{
			name: "direct URL",
			line: `source = { url = "https://example.com/pkg.whl" }`,
			want: false,
		},
		{
			name: "path",
			line: `source = { path = "../pkg.whl" }`,
			want: false,
		},
		{
			name: "directory",
			line: `source = { directory = "../pkg" }`,
			want: false,
		},
		{
			name: "editable",
			line: `source = { editable = "." }`,
			want: false,
		},
		{
			name: "virtual",
			line: `source = { virtual = "." }`,
			want: false,
		},
		{
			name: "empty registry",
			line: `source = { registry = "" }`,
			want: false,
		},
		{
			name: "unknown key",
			line: `source = { mirror = "https://example.com" }`,
			want: false,
		},
		{
			name: "substring must not match",
			line: `source = { not_registry = "https://example.com" }`,
			want: false,
		},
		{
			name: "non-inline source",
			line: `source = "https://pypi.org/simple"`,
			want: false,
		},
		{
			name: "whitespace-only registry",
			line: `source = { registry = "   " }`,
			want: false,
		},
		{
			name: "extra inline-table field",
			line: `source = { registry = "https://pypi.org/simple", git = "unexpected" }`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := `[[package]]
name = "pkg"
version = "1.0.0"
` + tt.line
			comps, _ := parseUVTest(t, "uv.lock", fixture)
			if tt.want {
				if len(comps) != 1 {
					t.Fatalf("want 1 component, got %d", len(comps))
				}
			} else {
				if len(comps) != 0 {
					t.Fatalf("want 0 components, got %d", len(comps))
				}
			}
		})
	}
}

func TestUVParseSkipsIncompletePackages(t *testing.T) {
	fixture := `[[package]]
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "missing-version"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "missing-source"
version = "1.0.0"

[[package]]
name = "unknown-version"
version = "unknown"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "floating-version"
version = "latest"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "valid"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }`

	comps, _ := parseUVTest(t, "uv.lock", fixture)
	if len(comps) != 1 {
		t.Fatalf("want exactly one component, got %d", len(comps))
	}
	if comps[0].PURL != "pkg:pypi/valid@2.0.0" {
		t.Errorf("want pkg:pypi/valid@2.0.0, got %s", comps[0].PURL)
	}
}

func TestUVParseMalformedBlockDoesNotPoisonNext(t *testing.T) {
	fixture := `[[package]]
name = "broken"
version = "1.0.0"
source = { registry =

[[package]]
name = "valid"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }`
	comps, _ := parseUVTest(t, "uv.lock", fixture)
	if len(comps) != 1 {
		t.Fatalf("want exactly one component, got %d", len(comps))
	}
	if comps[0].PURL != "pkg:pypi/valid@2.0.0" {
		t.Errorf("want pkg:pypi/valid@2.0.0, got %s", comps[0].PURL)
	}
}

func TestUVParseNestedTableEndsDirectPackageFields(t *testing.T) {
	fixture := `[[package]]
name = "first"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[package.metadata]
name = "must-not-rebind"
version = "9.9.9"
source = { registry = "https://evil.example/simple" }

[[package]]
name = "second"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }`
	comps, _ := parseUVTest(t, "uv.lock", fixture)
	if len(comps) != 2 {
		t.Fatalf("want 2 components, got %d", len(comps))
	}
	if comps[0].PURL != "pkg:pypi/first@1.0.0" {
		t.Errorf("want first@1.0.0, got %s", comps[0].PURL)
	}
	if comps[1].PURL != "pkg:pypi/second@2.0.0" {
		t.Errorf("want second@2.0.0, got %s", comps[1].PURL)
	}
}

func TestUVParseDeduplicatesNormalizedPURL(t *testing.T) {
	fixture := `[[package]]
name = "Some_Pkg"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "some.pkg"
version = "1.0.0"
source = { registry = "https://private.example/simple" }

[[package]]
name = "some-pkg"
version = "1.0.0"
source = { registry = "../wheelhouse" }`
	comps, _ := parseUVTest(t, "uv.lock", fixture)
	if len(comps) != 1 {
		t.Fatalf("want one component, got %d", len(comps))
	}
	if comps[0].PURL != "pkg:pypi/some-pkg@1.0.0" {
		t.Errorf("want pkg:pypi/some-pkg@1.0.0, got %s", comps[0].PURL)
	}
}

func TestUVParsePreservesMultipleVersions(t *testing.T) {
	fixture := `[[package]]
name = "platform-package"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "platform_package"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }`
	comps, _ := parseUVTest(t, "uv.lock", fixture)
	if len(comps) != 2 {
		t.Fatalf("want 2 components, got %d", len(comps))
	}
	if comps[0].PURL != "pkg:pypi/platform-package@1.0.0" {
		t.Errorf("want platform-package@1.0.0, got %s", comps[0].PURL)
	}
	if comps[1].PURL != "pkg:pypi/platform-package@2.0.0" {
		t.Errorf("want platform-package@2.0.0, got %s", comps[1].PURL)
	}
}

func TestUVParseScopeFromPath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantScope string
	}{
		{
			name:      "production",
			path:      "uv.lock",
			wantScope: sbom.ScopeProduction,
		},
		{
			name:      "test",
			path:      "tests/uv.lock",
			wantScope: sbom.ScopeTest,
		},
		{
			name:      "fixture",
			path:      "testdata/uv.lock",
			wantScope: sbom.ScopeFixture,
		},
		{
			name:      "example",
			path:      "examples/app/uv.lock",
			wantScope: sbom.ScopeExample,
		},
		{
			name:      "documentation",
			path:      "docs/sample/uv.lock",
			wantScope: sbom.ScopeDocumentation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := `[[package]]
name = "pkg"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }`
			comps, _ := parseUVTest(t, tt.path, fixture)
			if len(comps) != 1 {
				t.Fatalf("want 1 component, got %d", len(comps))
			}
			if comps[0].Scope != tt.wantScope {
				t.Errorf("want scope %s, got %s", tt.wantScope, comps[0].Scope)
			}
		})
	}
}

func TestUVParseDoesNotInferDependencyEdges(t *testing.T) {
	fixture := `[[package]]
name = "anyio"
version = "4.4.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "idna" },
    { name = "typing-extensions", marker = "python_version < '3.13'" },
]`
	comps, deps := parseUVTest(t, "uv.lock", fixture)
	if len(comps) != 1 {
		t.Fatalf("want 1 component, got %d", len(comps))
	}
	if comps[0].PURL != "pkg:pypi/anyio@4.4.0" {
		t.Errorf("want anyio, got %s", comps[0].PURL)
	}
	if deps != nil {
		t.Errorf("want nil deps, got %+v", deps)
	}
}

func TestUVParseDeterministicOrder(t *testing.T) {
	fixture := `[[package]]
name = "zebra"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "AnyIO"
version = "4.4.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "middle_pkg"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }`

	comps, _ := parseUVTest(t, "uv.lock", fixture)
	if len(comps) != 3 {
		t.Fatalf("want 3 components, got %d", len(comps))
	}

	expectedPURLs := []string{
		"pkg:pypi/anyio@4.4.0",
		"pkg:pypi/middle-pkg@2.0.0",
		"pkg:pypi/zebra@1.0.0",
	}

	for i, purl := range expectedPURLs {
		if comps[i].PURL != purl {
			t.Errorf("comp %d: want %s, got %s", i, purl, comps[i].PURL)
		}
	}
}

func TestUVParseContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := UV{}.Parse(ctx, ParseInput{
		Path: "uv.lock",
		Content: []byte(`[[package]]
name = "anyio"
version = "4.4.0"
source = { registry = "https://pypi.org/simple" }`),
	})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestUVParseScannerError(t *testing.T) {
	hugeLine := make([]byte, 5*1024*1024)
	for i := range hugeLine {
		hugeLine[i] = 'a'
	}

	_, _, err := UV{}.Parse(context.Background(), ParseInput{
		Path:    "uv.lock",
		Content: hugeLine,
	})

	if err == nil {
		t.Fatalf("want error for scanner overflow, got nil")
	}
	if !errors.Is(err, bufio.ErrTooLong) {
		t.Errorf("want bufio.ErrTooLong, got %v", err)
	}
	if !strings.Contains(err.Error(), "scan uv.lock") {
		t.Errorf("want wrapped scan uv.lock error, got %v", err)
	}
}

func TestUVRegistryGenerate(t *testing.T) {
	dir := t.TempDir()
	fixture := `[[package]]
name = "anyio"
version = "4.4.0"
source = { registry = "https://pypi.org/simple" }`

	if err := os.WriteFile(filepath.Join(dir, "uv.lock"), []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}

	reg, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry: %v", err)
	}

	doc, err := reg.Generate(context.Background(), dir)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if doc.Source != "ownsbom" || doc.GeneratorVersion != ownsbomVersion {
		t.Errorf("want source ownsbom and generator %s, got %s and %s", ownsbomVersion, doc.Source, doc.GeneratorVersion)
	}

	if len(doc.Components) != 1 {
		t.Fatalf("want 1 component, got %d", len(doc.Components))
	}

	if doc.Components[0].PURL != "pkg:pypi/anyio@4.4.0" {
		t.Errorf("want anyio, got %s", doc.Components[0].PURL)
	}

	if len(doc.Dependencies) != 0 {
		t.Errorf("want 0 dependencies, got %+v", doc.Dependencies)
	}
}
