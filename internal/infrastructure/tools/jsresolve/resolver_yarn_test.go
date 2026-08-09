package jsresolve

import (
	"context"
	"fmt"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestYarnBerryImporterSelectsVersion(t *testing.T) {
	t.Parallel()

	for _, metadataVersion := range []int{8, 10} {
		metadataVersion := metadataVersion
		t.Run(fmt.Sprintf("metadata-v%d", metadataVersion), func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
				"name":           "app",
				"version":        "1.0.0",
				"packageManager": "yarn@4.9.0",
				"dependencies":   map[string]string{"lodash": "^4.17.0"},
			})
			writeFile(t, r2bJoin(root, "yarn.lock"), fmt.Sprintf(`__metadata:
  version: %d

"lodash@npm:^4.17.0":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
`, metadataVersion))

			result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "lodash"), docWith(
				"pkg:npm/lodash@4.17.20",
				"pkg:npm/lodash@4.17.21",
			))
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			got := resolutionsBySpecifier(result.Imports)["lodash"]
			if got.Status != jsresolution.StatusComponent || got.Package.Version != "4.17.21" {
				t.Fatalf("Yarn importer did not select 4.17.21: %+v", got)
			}
			if !result.Complete {
				t.Fatalf("supported Yarn Berry metadata unexpectedly degraded coverage: %+v", result.Coverage)
			}
		})
	}
}

func TestYarnBerryNPMProtocolKeepsDependencyIdentity(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "app",
		"version":        "1.0.0",
		"packageManager": "yarn@4.9.0",
		"dependencies":   map[string]string{"lodash": "npm:4.17.21"},
	})
	writeFile(t, r2bJoin(root, "yarn.lock"), `__metadata:
  version: 8

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
`)

	result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "lodash"), docWith("pkg:npm/lodash@4.17.21"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := resolutionsBySpecifier(result.Imports)["lodash"]
	if got.Status != jsresolution.StatusComponent || got.Package.PURL != "pkg:npm/lodash@4.17.21" || !result.Complete {
		t.Fatalf("Yarn npm: selector changed the dependency identity: import=%+v coverage=%+v", got, result.Coverage)
	}
}

func TestYarnNPMProtocolRequiresYarnPackageManager(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":         "app",
		"version":      "1.0.0",
		"dependencies": map[string]string{"lodash": "npm:4.17.21"},
	})
	writeFile(t, r2bJoin(root, "yarn.lock"), `__metadata:
  version: 8

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
`)

	result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "lodash"), docWith("pkg:npm/lodash@4.17.21"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := resolutionsBySpecifier(result.Imports)["lodash"]
	if got.Status == jsresolution.StatusComponent || result.Complete {
		t.Fatalf("a stray yarn.lock changed no-manager npm alias semantics: import=%+v coverage=%+v", got, result.Coverage)
	}
	if !hasCoverageKind(result.Coverage, jsresolution.CoverageUnsupportedPackageManager) {
		t.Fatalf("stray yarn.lock lacks explicit package-manager coverage: %+v", result.Coverage)
	}
}

func TestYarnBerryLocatorIdentityMismatchFailsClosed(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "app",
		"version":        "1.0.0",
		"packageManager": "yarn@4.9.0",
		"dependencies":   map[string]string{"lodash": "4.17.21"},
	})
	writeFile(t, r2bJoin(root, "yarn.lock"), `__metadata:
  version: 8

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "evil@npm:4.17.21"
`)

	result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "lodash"), docWith("pkg:npm/lodash@4.17.21"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := resolutionsBySpecifier(result.Imports)["lodash"]
	if got.Status == jsresolution.StatusComponent || result.Complete {
		t.Fatalf("mismatched Yarn locator became definitive: import=%+v coverage=%+v", got, result.Coverage)
	}
	if !hasCoverageKind(result.Coverage, jsresolution.CoverageUnsupportedMetadata) {
		t.Fatalf("mismatched Yarn locator lacks unsupported-metadata coverage: %+v", result.Coverage)
	}
}

func TestYarnBerryDuplicateDescriptorFailsClosed(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "app",
		"version":        "1.0.0",
		"packageManager": "yarn@4.9.0",
		"dependencies":   map[string]string{"lodash": "4.17.21"},
	})
	writeFile(t, r2bJoin(root, "yarn.lock"), `__metadata:
  version: 8

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "evil@npm:4.17.21"
`)

	result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "lodash"), docWith("pkg:npm/lodash@4.17.21"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := resolutionsBySpecifier(result.Imports)["lodash"]
	if got.Status == jsresolution.StatusComponent || result.Complete {
		t.Fatalf("duplicate Yarn descriptor became definitive: import=%+v coverage=%+v", got, result.Coverage)
	}
	if !hasCoverageKind(result.Coverage, jsresolution.CoverageUnsupportedMetadata) {
		t.Fatalf("duplicate Yarn descriptor lacks unsupported-metadata coverage: %+v", result.Coverage)
	}
}

func TestYarnBerryUnknownMetadataVersionFailsClosed(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "app",
		"version":        "1.0.0",
		"packageManager": "yarn@99.0.0",
		"dependencies":   map[string]string{"lodash": "4.17.21"},
	})
	writeFile(t, r2bJoin(root, "yarn.lock"), `__metadata:
  version: 99

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
`)

	result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "lodash"), docWith("pkg:npm/lodash@4.17.21"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := resolutionsBySpecifier(result.Imports)["lodash"]
	if got.Status == jsresolution.StatusComponent || result.Complete {
		t.Fatalf("unknown Yarn metadata version became definitive: import=%+v coverage=%+v", got, result.Coverage)
	}
	if !hasCoverageKind(result.Coverage, jsresolution.CoverageUnsupportedMetadata) {
		t.Fatalf("unknown Yarn metadata version lacks unsupported-metadata coverage: %+v", result.Coverage)
	}
}

func TestYarnBerryScopedPackageCorrelates(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "app",
		"version":        "1.0.0",
		"packageManager": "yarn@4.9.0",
		"dependencies":   map[string]string{"@scope/pkg": "1.2.3"},
	})
	writeFile(t, r2bJoin(root, "yarn.lock"), `__metadata:
  version: 8

"@scope/pkg@npm:1.2.3":
  version: 1.2.3
  resolution: "@scope/pkg@npm:1.2.3"
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "@scope/pkg", Version: "1.2.3", PURL: "pkg:npm/%40scope/pkg@1.2.3"}}}

	result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "@scope/pkg/subpath"), doc)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := resolutionsBySpecifier(result.Imports)["@scope/pkg/subpath"]
	if got.Status != jsresolution.StatusComponent || got.Package.PURL != "pkg:npm/%40scope/pkg@1.2.3" || !result.Complete {
		t.Fatalf("scoped Yarn package did not correlate: import=%+v coverage=%+v", got, result.Coverage)
	}
}

func TestYarnBerrySameNameWorkspaceStaysAmbiguous(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"private":        true,
		"packageManager": "yarn@4.9.0",
		"workspaces":     []string{"packages/*"},
		"dependencies":   map[string]string{"shared": "npm:1.0.0"},
	})
	writeJSON(t, r2bJoin(root, "packages", "shared", "package.json"), map[string]any{"name": "shared", "version": "1.0.0"})
	writeFile(t, r2bJoin(root, "yarn.lock"), `__metadata:
  version: 8

"shared@npm:1.0.0":
  version: 1.0.0
  resolution: "shared@npm:1.0.0"
`)

	result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "shared"), docWith("pkg:npm/shared@1.0.0"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := resolutionsBySpecifier(result.Imports)["shared"]
	if got.Status != jsresolution.StatusAmbiguous || result.Complete {
		t.Fatalf("same-name workspace was forced to a registry identity: import=%+v coverage=%+v", got, result.Coverage)
	}
}

func TestYarnBerryUnrelatedBadLocatorPreservesPositiveButIncomplete(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "app",
		"version":        "1.0.0",
		"packageManager": "yarn@4.9.0",
		"dependencies":   map[string]string{"lodash": "4.17.21"},
	})
	writeFile(t, r2bJoin(root, "yarn.lock"), `__metadata:
  version: 8

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"

"evil@npm:1.0.0":
  version: 1.0.0
  resolution: "other@npm:1.0.0"
`)

	result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "lodash"), docWith("pkg:npm/lodash@4.17.21"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := resolutionsBySpecifier(result.Imports)["lodash"]
	if got.Status != jsresolution.StatusComponent || got.Package.PURL != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("unrelated bad Yarn locator destroyed a valid positive: import=%+v coverage=%+v", got, result.Coverage)
	}
	if result.Complete {
		t.Fatalf("unrelated bad Yarn locator was silently ignored: %+v", result.Coverage)
	}
	if !hasCoverageKind(result.Coverage, jsresolution.CoverageUnsupportedMetadata) {
		t.Fatalf("unrelated bad Yarn locator lacks unsupported-metadata coverage: %+v", result.Coverage)
	}
}

func TestYarnBerryIgnoresStaleNPMImporterEvidence(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "app",
		"version":        "1.0.0",
		"packageManager": "yarn@4.9.0",
		"dependencies":   map[string]string{"lodash": "^4.17.0"},
	})
	writeJSON(t, r2bJoin(root, "package-lock.json"), map[string]any{
		"name": "app", "lockfileVersion": 3,
		"packages": map[string]any{
			"":                    map[string]any{"dependencies": map[string]string{"lodash": "^3.10.1"}},
			"node_modules/lodash": map[string]any{"version": "3.10.1"},
		},
	})
	writeFile(t, r2bJoin(root, "yarn.lock"), `__metadata:
  version: 8

"lodash@npm:^4.17.0":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
`)

	result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "lodash"), docWith(
		"pkg:npm/lodash@3.10.1",
		"pkg:npm/lodash@4.17.21",
	))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := resolutionsBySpecifier(result.Imports)["lodash"]
	if got.Status != jsresolution.StatusComponent || got.Package.Version != "4.17.21" {
		t.Fatalf("stale package-lock overrode explicit Yarn selection: import=%+v coverage=%+v", got, result.Coverage)
	}
}
