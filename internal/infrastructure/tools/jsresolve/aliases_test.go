package jsresolve

import (
	"context"
	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAliasInventoryBuilderParsesPackageImportsAndJSONCPaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{
  "name": "root",
  "imports": {
    "#shared/*": "./packages/shared/src/*",
    "#dep": "lodash/fp"
  }
}`)
	writeFile(t, filepath.Join(root, "tsconfig.json"), `{
  // JSONC comments and trailing commas are accepted.
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@shared/*": ["packages/shared/src/*",],
    },
  },
}`)

	got, err := newAliasInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.coverage) != 0 {
		t.Fatalf("unexpected coverage: %#v", got.coverage)
	}
	if len(got.mappings) != 3 {
		t.Fatalf("mapping count = %d, want 3: %#v", len(got.mappings), got.mappings)
	}
}

func TestAliasInventoryBuilderUnsupportedConditionalImportIsExplicit(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{
  "name": "root",
  "imports": {"#internal": {"node": "./node.js", "default": "./default.js"}}
}`)

	got, err := newAliasInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.mappings) != 0 || !hasCoverageKind(got.coverage, jsresolution.CoverageUnsupportedAlias) {
		t.Fatalf("conditional imports were not explicit unsupported coverage: %#v", got)
	}
}

func TestAliasInventoryBuilderTSConfigExtendsKeepsCoverageIncomplete(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "tsconfig.json"), `{
  "extends": "./base.json",
  "compilerOptions": {"paths": {"@app/*": ["src/*"]}}
}`)

	got, err := newAliasInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.mappings) != 1 || !hasCoverageKind(got.coverage, jsresolution.CoverageUnsupportedAlias) {
		t.Fatalf("extends coverage = %#v mappings=%#v", got.coverage, got.mappings)
	}
}

func TestAliasInventoryBuilderRejectsEscapingBaseURL(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "tsconfig.json"), `{
  "compilerOptions": {"baseUrl": "../outside", "paths": {"@app/*": ["src/*"]}}
}`)
	got, err := newAliasInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.mappings) != 0 || !hasCoverageKind(got.coverage, jsresolution.CoverageWorkspaceRootEscape) {
		t.Fatalf("escaping baseUrl was not rejected: %#v", got)
	}
}

func TestAliasInventoryBuilderBudgetsAreInjectable(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "tsconfig.json"), `{
  "compilerOptions": {"paths": {"a": ["src/a"], "b": ["src/b"]}}
}`)
	limits := defaultAliasLimits()
	limits.maxMappings = 1
	got, err := newAliasInventoryBuilderWithLimits(limits).Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !hasCoverageKind(got.coverage, jsresolution.CoverageMetadataBudgetExceeded) {
		t.Fatalf("mapping budget did not produce coverage: %#v", got.coverage)
	}
}

func TestAliasInventoryBuilderMalformedJSONCIsIncomplete(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "tsconfig.json"), `{"compilerOptions":{"paths":{"a":["src/a"]}} /* never closes`)
	got, err := newAliasInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !hasCoverageKind(got.coverage, jsresolution.CoverageMalformedMetadata) {
		t.Fatalf("malformed JSONC did not produce coverage: %#v", got.coverage)
	}
}

func TestAliasInventoryBuilderRefusesSymlinkedAliasMetadata(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not reliably available on Windows CI")
	}
	t.Parallel()
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "tsconfig.json")
	writeFile(t, outside, `{"compilerOptions":{"paths":{"@x/*":["src/*"]}}}`)
	if err := os.Symlink(outside, filepath.Join(root, "tsconfig.json")); err != nil {
		t.Fatal(err)
	}
	got, err := newAliasInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.mappings) != 0 || !hasCoverageKind(got.coverage, jsresolution.CoverageUnreadableMetadata) {
		t.Fatalf("symlinked alias metadata was not refused: %#v", got)
	}
}

func hasCoverageKind(issues []jsresolution.CoverageIssue, kind jsresolution.CoverageIssueKind) bool {
	for _, issue := range issues {
		if issue.Kind == kind {
			return true
		}
	}
	return false
}
