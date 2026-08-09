package jsresolve

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
)

// graphFrom builds a one-edge graph from an arbitrary importer module.
func graphFrom(from, specifier string) modulegraph.Graph {
	return modulegraph.Graph{
		Modules: []modulegraph.Module{{Path: from, Dialect: modulegraph.DialectTypeScript}},
		Edges:   []modulegraph.Edge{{From: from, Specifier: specifier, Kind: modulegraph.ImportESMStatic}},
	}
}

// TestPnpmImporterSelectsTheVersion is the point of the whole phase: two versions of one package are
// installed, so the SBOM alone is ambiguous, but the lockfile records which one EACH workspace resolves.
func TestPnpmImporterSelectsTheVersion(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "private": true, "workspaces": []string{"packages/*"}})
	writeJSON(t, r2bJoin(root, "packages", "api", "package.json"), map[string]any{"name": "@repo/api", "version": "1.0.0", "dependencies": map[string]string{"lodash": "^4.17.21"}})
	writeJSON(t, r2bJoin(root, "packages", "web", "package.json"), map[string]any{"name": "@repo/web", "version": "1.0.0", "dependencies": map[string]string{"lodash": "^3.10.1"}})
	writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), `
importers:
  packages/api:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21
  packages/web:
    dependencies:
      lodash:
        specifier: ^3.10.1
        version: 3.10.1
`)
	doc := docWith("pkg:npm/lodash@4.17.21", "pkg:npm/lodash@3.10.1")

	tests := []struct {
		importer    string
		wantVersion string
	}{
		{importer: "packages/api/src/index.ts", wantVersion: "4.17.21"},
		{importer: "packages/web/src/index.ts", wantVersion: "3.10.1"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.importer, func(t *testing.T) {
			t.Parallel()
			result, err := NewResolver().Resolve(context.Background(), root, graphFrom(test.importer, "lodash"), doc)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			got := resolutionsBySpecifier(result.Imports)["lodash"]
			if got.Status != jsresolution.StatusComponent {
				t.Fatalf("importer context must select one version, got %q (candidates %+v)", got.Status, got.Candidates)
			}
			if got.Package.Version != test.wantVersion {
				t.Fatalf("version = %q, want %q", got.Package.Version, test.wantVersion)
			}
		})
	}
}

func TestNPMHoistingSelectsTheVersion(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "private": true, "workspaces": []string{"packages/*"}})
	writeJSON(t, r2bJoin(root, "packages", "api", "package.json"), map[string]any{"name": "@repo/api", "version": "1.0.0", "dependencies": map[string]string{"lodash": "^3.10.1"}})
	// packages/api pins its own nested copy; the root hoists a different version.
	writeJSON(t, r2bJoin(root, "package-lock.json"), map[string]any{
		"name": "root", "lockfileVersion": 3,
		"packages": map[string]any{
			"":                                 map[string]any{"dependencies": map[string]string{"lodash": "^4.17.21"}},
			"packages/api":                     map[string]any{"name": "@repo/api", "version": "1.0.0", "dependencies": map[string]string{"lodash": "^3.10.1"}},
			"node_modules/lodash":              map[string]any{"version": "4.17.21"},
			"packages/api/node_modules/lodash": map[string]any{"version": "3.10.1"},
		},
	})
	doc := docWith("pkg:npm/lodash@4.17.21", "pkg:npm/lodash@3.10.1")

	// The nested install wins for the workspace (npm's nearest-wins rule).
	result, err := NewResolver().Resolve(context.Background(), root, graphFrom("packages/api/src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := resolutionsBySpecifier(result.Imports)["lodash"]
	if got.Status != jsresolution.StatusComponent || got.Package.Version != "3.10.1" {
		t.Fatalf("npm hoisting must select the nested version 3.10.1, got %+v", got)
	}
}

func TestImporterDisambiguationNeverGuesses(t *testing.T) {
	t.Parallel()

	doc := docWith("pkg:npm/lodash@4.17.21", "pkg:npm/lodash@3.10.1")

	t.Run("no lockfile leaves ambiguity", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "app", "version": "1.0.0"})
		result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "lodash"), doc)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		got := resolutionsBySpecifier(result.Imports)["lodash"]
		if got.Status != jsresolution.StatusAmbiguous {
			t.Fatalf("without a lockfile the ambiguity must stand, got %q", got.Status)
		}
	})

	t.Run("lockfile version matching no candidate leaves ambiguity", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "app", "version": "1.0.0", "dependencies": map[string]string{"lodash": "^2"}})
		writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), "importers:\n  .:\n    dependencies:\n      lodash:\n        specifier: ^2\n        version: 2.4.2\n")
		result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "lodash"), doc)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		got := resolutionsBySpecifier(result.Imports)["lodash"]
		if got.Status != jsresolution.StatusAmbiguous {
			t.Fatalf("a lockfile version matching no sbom candidate must not select one, got %+v", got)
		}
	})

	t.Run("yarn lockfiles report their limitation", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "app", "version": "1.0.0"})
		writeFile(t, r2bJoin(root, "yarn.lock"), "# yarn lockfile v1\nlodash@^4:\n  version \"4.17.21\"\n")
		result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "lodash"), doc)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if !hasCoverageKind(result.Coverage, jsresolution.CoverageUnsupportedPackageManager) {
			t.Fatalf("a yarn lockfile must report that per-importer selection is unavailable, got %+v", result.Coverage)
		}
	})

	t.Run("a pnpm link is not a registry version", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "app", "version": "1.0.0"})
		writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), "importers:\n  .:\n    dependencies:\n      lodash:\n        specifier: workspace:*\n        version: link:../local\n")
		result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "lodash"), doc)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		got := resolutionsBySpecifier(result.Imports)["lodash"]
		if got.Status == jsresolution.StatusComponent {
			t.Fatalf("a link: resolution must not select a registry component, got %+v", got)
		}
	})
}

func TestPnpmVersionStripsPeerSuffix(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"18.2.0":               "18.2.0",
		"18.2.0(react@18.2.0)": "18.2.0",
		"1.0.0(a@1)(b@2)":      "1.0.0",
		"  4.17.21  ":          "4.17.21",
		"link:../local":        "",
		"file:../tarball.tgz":  "",
	}
	for input, want := range tests {
		input, want := input, want
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			if got := pnpmVersion(input); got != want {
				t.Fatalf("pnpmVersion(%q) = %q, want %q", input, got, want)
			}
		})
	}
}
