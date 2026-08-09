package jsresolve

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
)

func TestYarnBerryLocatorVersionMismatchFailsClosed(t *testing.T) {
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
  resolution: "lodash@npm:4.17.20"
`)

	result, err := NewResolver().Resolve(context.Background(), root, graphFrom("src/index.ts", "lodash"), docWith("pkg:npm/lodash@4.17.21"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := resolutionsBySpecifier(result.Imports)["lodash"]
	if got.Status == jsresolution.StatusComponent || result.Complete {
		t.Fatalf("version-mismatched Yarn locator became definitive: import=%+v coverage=%+v", got, result.Coverage)
	}
	if !hasCoverageKind(result.Coverage, jsresolution.CoverageUnsupportedMetadata) {
		t.Fatalf("version-mismatched Yarn locator lacks unsupported-metadata coverage: %+v", result.Coverage)
	}
}
