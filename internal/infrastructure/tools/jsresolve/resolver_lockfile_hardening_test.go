package jsresolve

import (
	"context"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
)

func TestPNPMV9PeerQualifiedSnapshotSelectsVersion(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name": "app", "version": "1.0.0",
		"dependencies": map[string]string{"react-dom": "19.2.0"},
	})
	writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react-dom:
        specifier: 19.2.0
        version: 19.2.0(react@19.2.0)
packages:
  react-dom@19.2.0: {}
snapshots:
  react-dom@19.2.0(react@19.2.0): {}
`)

	result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "react-dom"), docWith(
		"pkg:npm/react-dom@18.3.1",
		"pkg:npm/react-dom@19.2.0",
	))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := resolutionsBySpecifier(result.Imports)["react-dom"]
	if got.Status != jsresolution.StatusComponent || got.Package.Version != "19.2.0" {
		t.Fatalf("peer-qualified pnpm snapshot did not select 19.2.0: %+v", got)
	}
}

func TestPNPMV9ScopedPeerQualifiedSnapshotSelectsVersion(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name": "app", "version": "1.0.0",
		"dependencies": map[string]string{"@scope/pkg": "1.2.3"},
	})
	writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      '@scope/pkg':
        specifier: 1.2.3
        version: 1.2.3(peer@2.0.0)
packages:
  '@scope/pkg@1.2.3': {}
snapshots:
  '@scope/pkg@1.2.3(peer@2.0.0)': {}
`)

	result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "@scope/pkg/subpath"), docWith(
		"pkg:npm/%40scope/pkg@1.2.2",
		"pkg:npm/%40scope/pkg@1.2.3",
	))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := resolutionsBySpecifier(result.Imports)["@scope/pkg/subpath"]
	if got.Status != jsresolution.StatusComponent || got.Package.Version != "1.2.3" {
		t.Fatalf("scoped peer-qualified pnpm snapshot did not select 1.2.3: %+v", got)
	}
}

func TestPNPMV9RequiresMatchingPackageAndSnapshot(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"missing package identity": `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      lodash:
        specifier: 4.17.21
        version: 4.17.21
packages:
  lodash@4.17.20: {}
snapshots:
  lodash@4.17.21: {}
`,
		"missing snapshot identity": `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      lodash:
        specifier: 4.17.21
        version: 4.17.21
packages:
  lodash@4.17.21: {}
snapshots:
  lodash@4.17.20: {}
`,
	}

	for name, lockfile := range tests {
		name, lockfile := name, lockfile
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
				"name": "app", "version": "1.0.0",
				"dependencies": map[string]string{"lodash": "4.17.21"},
			})
			writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), lockfile)

			result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "lodash"), docWith(
				"pkg:npm/lodash@4.17.20",
				"pkg:npm/lodash@4.17.21",
			))
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			got := resolutionsBySpecifier(result.Imports)["lodash"]
			if got.Status == jsresolution.StatusComponent {
				t.Fatalf("dangling pnpm v9 evidence selected a component: %+v", got)
			}
			if !hasCoverageKind(result.Coverage, jsresolution.CoverageUnsupportedPackageManager) {
				t.Fatalf("dangling pnpm v9 evidence lacks coverage: %+v", result.Coverage)
			}
		})
	}
}

func TestPNPMV9MalformedPeerSuffixFailsClosed(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name": "app", "version": "1.0.0",
		"dependencies": map[string]string{"react-dom": "19.2.0"},
	})
	writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react-dom:
        specifier: 19.2.0
        version: 19.2.0(react@19.2.0
packages:
  react-dom@19.2.0: {}
snapshots:
  react-dom@19.2.0(react@19.2.0): {}
`)

	result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "react-dom"), docWith(
		"pkg:npm/react-dom@18.3.1",
		"pkg:npm/react-dom@19.2.0",
	))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := resolutionsBySpecifier(result.Imports)["react-dom"]
	if got.Status == jsresolution.StatusComponent {
		t.Fatalf("malformed peer suffix selected a component: %+v", got)
	}
	if !hasCoverageKind(result.Coverage, jsresolution.CoverageUnsupportedPackageManager) {
		t.Fatalf("malformed peer suffix lacks coverage: %+v", result.Coverage)
	}
}

func TestNPMShrinkwrapTakesPrecedenceOverPackageLock(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name": "app", "version": "1.0.0",
		"dependencies": map[string]string{"lodash": "^4.17.0"},
	})
	writeJSON(t, r2bJoin(root, "package-lock.json"), map[string]any{
		"name": "app", "lockfileVersion": 3,
		"packages": map[string]any{
			"":                    map[string]any{"dependencies": map[string]string{"lodash": "^3.10.1"}},
			"node_modules/lodash": map[string]any{"version": "3.10.1"},
		},
	})
	writeJSON(t, r2bJoin(root, "npm-shrinkwrap.json"), map[string]any{
		"name": "app", "lockfileVersion": 3,
		"packages": map[string]any{
			"":                    map[string]any{"dependencies": map[string]string{"lodash": "^4.17.0"}},
			"node_modules/lodash": map[string]any{"version": "4.17.21"},
		},
	})

	result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "lodash"), docWith(
		"pkg:npm/lodash@3.10.1",
		"pkg:npm/lodash@4.17.21",
	))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := resolutionsBySpecifier(result.Imports)["lodash"]
	if got.Status != jsresolution.StatusComponent || got.Package.Version != "4.17.21" {
		t.Fatalf("npm shrinkwrap did not take precedence over package-lock: %+v", got)
	}
}

func TestNPMImporterRejectsDuplicateJSONKeys(t *testing.T) {
	t.Parallel()

	raw := []byte(`{
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"lodash": "4.17.21"}},
    "node_modules/lodash": {"version": "4.17.20", "version": "4.17.21"}
  }
}`)
	out := &importerResolutions{byImporter: map[string]map[string]string{}}
	if parseNPMImporters(raw, out) {
		t.Fatalf("duplicate npm lock key was accepted: %+v", out.byImporter)
	}
}

func TestStrictJSONNestingBudget(t *testing.T) {
	t.Parallel()

	depth := maxStrictJSONNestingDepth + 2
	raw := strings.Repeat("{\"x\":", depth) + "0" + strings.Repeat("}", depth)
	if err := validateNoDuplicateJSONKeys([]byte(raw)); err == nil || !strings.Contains(err.Error(), "nesting depth") {
		t.Fatalf("deep JSON was not rejected by the nesting budget: %v", err)
	}
}
