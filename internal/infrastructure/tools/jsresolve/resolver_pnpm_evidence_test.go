package jsresolve

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
)

// twoDepGraph imports both specifiers from one module, so a lockfile can be partly valid.
func twoDepGraph(a, b string) modulegraph.Graph {
	return modulegraph.Graph{
		Modules: []modulegraph.Module{{Path: "src/index.ts", Dialect: modulegraph.DialectTypeScript}},
		Edges: []modulegraph.Edge{
			{From: "src/index.ts", Specifier: a, Kind: modulegraph.ImportESMStatic},
			{From: "src/index.ts", Specifier: b, Kind: modulegraph.ImportESMStatic},
		},
	}
}

// TestPNPMV9InconsistentLockfileDiscardsAllImporterEvidence covers the invalidV9Evidence guard, which
// the single-dependency cases cannot reach: when the identity check rejects the only dependency,
// `selected` ends up empty and the pre-existing len(selected)==0 return already refuses. Deleting the
// guard therefore left the suite green while changing behaviour.
//
// The behaviour under test: a lockfile that contradicts itself is not trusted PIECEWISE. `lodash` has a
// matching package + snapshot and would resolve on its own, but `left-pad` claims a version present in
// neither section — so the file has been proven inconsistent and you cannot tell which half is lying.
// Both dependencies must fall back to ambiguity rather than one of them borrowing credibility.
func TestPNPMV9InconsistentLockfileDiscardsAllImporterEvidence(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name": "app", "version": "1.0.0",
		"dependencies": map[string]string{"lodash": "4.17.21", "left-pad": "1.3.0"},
	})
	writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      lodash:
        specifier: 4.17.21
        version: 4.17.21
      left-pad:
        specifier: 1.3.0
        version: 1.3.0
packages:
  lodash@4.17.21: {}
snapshots:
  lodash@4.17.21: {}
`)

	// Two versions of lodash, so the SBOM alone is AMBIGUOUS and only the lockfile could decide. Without
	// this the SBOM resolves lodash unaided and the test proves nothing about the lockfile path.
	result, err := NewResolver().Resolve(context.Background(), root,
		twoDepGraph("lodash", "left-pad"),
		docWith("pkg:npm/lodash@4.17.20", "pkg:npm/lodash@4.17.21", "pkg:npm/left-pad@1.3.0"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	got := resolutionsBySpecifier(result.Imports)["lodash"]
	if got.Status == jsresolution.StatusComponent {
		t.Fatalf("a proven-inconsistent pnpm v9 lockfile still selected %s@%s for the valid dependency; importer evidence must be discarded as a whole",
			got.Package.Name, got.Package.Version)
	}
	if !hasCoverageKind(result.Coverage, jsresolution.CoverageUnsupportedPackageManager) {
		t.Fatalf("discarding the lockfile must be reported as a coverage issue, not silently: %+v", result.Coverage)
	}
}

// TestPNPMSnapshotCrossCheckIsNotGatedOnAVersionLiteral pins the fix for a fail-open: the cross-check
// used to run only for the exact strings "9"/"9.0", so identical dangling evidence resolved to a
// component under '9.1' or '10.0' — naming a version present in neither `packages` nor `snapshots`.
// A hardening step that disappears on a format bump is worse than a known gap, because nobody looks.
func TestPNPMSnapshotCrossCheckIsNotGatedOnAVersionLiteral(t *testing.T) {
	t.Parallel()

	for _, version := range []string{"'9.0'", "'9.1'", "'10.0'", "'11'"} {
		t.Run(version, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
				"name": "app", "version": "1.0.0",
				"dependencies": map[string]string{"lodash": "4.17.21"},
			})
			writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), "lockfileVersion: "+version+`
importers:
  .:
    dependencies:
      lodash:
        specifier: 4.17.21
        version: 4.17.21
packages:
  lodash@4.17.20: {}
snapshots:
  lodash@4.17.20: {}
`)
			result, err := NewResolver().Resolve(context.Background(), root,
				graphFrom("src/index.ts", "lodash"),
				docWith("pkg:npm/lodash@4.17.20", "pkg:npm/lodash@4.17.21"))
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			got := resolutionsBySpecifier(result.Imports)["lodash"]
			if got.Status == jsresolution.StatusComponent {
				t.Fatalf("lockfileVersion %s: dangling evidence selected %q; the cross-check must not depend on a known version literal",
					version, got.Package.Version)
			}
		})
	}
}

func TestPNPMHasSnapshotGraph(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		snapshots map[string]any
		version   string
		want      bool
	}{
		{name: "snapshots present is enough on its own", snapshots: map[string]any{"a@1": nil}, version: "", want: true},
		{name: "an empty but present snapshots section still cross-checks", snapshots: map[string]any{}, version: "", want: true},
		// A declared v9 lockfile with NO snapshots section is malformed, not a pre-v9 layout: the
		// version fallback keeps it in the strict path so it is refused rather than downgraded.
		{name: "declared v9 with no snapshots section stays strict", snapshots: nil, version: "'9.0'", want: true},
		{name: "a future major stays strict", snapshots: nil, version: "'10.0'", want: true},
		{name: "pre-v9 without snapshots is not cross-checked", snapshots: nil, version: "'6.0'", want: false},
		{name: "v5.4 without snapshots is not cross-checked", snapshots: nil, version: "5.4", want: false},
		{name: "an unparseable version without snapshots is not cross-checked", snapshots: nil, version: "abc", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pnpmHasSnapshotGraph(tc.snapshots, tc.version); got != tc.want {
				t.Fatalf("pnpmHasSnapshotGraph(%v, %q) = %v, want %v", tc.snapshots, tc.version, got, tc.want)
			}
		})
	}
}
