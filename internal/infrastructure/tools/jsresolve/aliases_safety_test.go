package jsresolve

import (
	"context"
	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"path/filepath"
	"testing"
)

func TestAliasInventoryBuilderTracksBaseURLWithoutPaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "tsconfig.json"), `{"compilerOptions":{"baseUrl":"src"}}`)
	got, err := newAliasInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.configs) != 1 || !got.configs[0].hasBaseURL {
		t.Fatalf("baseUrl context not retained: %#v", got.configs)
	}
}

func TestAliasInventoryBuilderExtendsWithoutLocalPathsIsStillIncomplete(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "tsconfig.json"), `{"extends":"./base.json"}`)
	got, err := newAliasInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !hasCoverageKind(got.coverage, jsresolution.CoverageUnsupportedAlias) {
		t.Fatalf("extends without local paths silently looked complete: %#v", got.coverage)
	}
}

func TestAliasInventoryBuilderRejectsNullAliasObjects(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"root","imports":null}`)
	writeFile(t, filepath.Join(root, "tsconfig.json"), `{"compilerOptions":{"paths":null}}`)
	got, err := newAliasInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !hasCoverageKind(got.coverage, jsresolution.CoverageUnsupportedAlias) || !hasCoverageKind(got.coverage, jsresolution.CoverageMalformedMetadata) {
		t.Fatalf("null alias metadata was not explicit coverage: %#v", got.coverage)
	}
}

func TestAliasInventoryBuilderRejectsEscapingAndNodeModulesTargets(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"root","imports":{"#escape":"./../outside","#nm":"./node_modules/x"}}`)
	got, err := newAliasInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !hasCoverageKind(got.coverage, jsresolution.CoverageWorkspaceRootEscape) || !hasCoverageKind(got.coverage, jsresolution.CoverageUnsupportedAlias) {
		t.Fatalf("unsafe package imports targets were not rejected: %#v", got.coverage)
	}
}

func TestAliasInventoryBuilderTSPathsRejectsNodeModulesTarget(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "tsconfig.json"), `{"compilerOptions":{"paths":{"lodash":["node_modules/lodash"]}}}`)
	got, err := newAliasInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.mappings) != 0 || !hasCoverageKind(got.coverage, jsresolution.CoverageUnsupportedAlias) {
		t.Fatalf("node_modules path target was treated as first-party: %#v", got)
	}
}

func TestAliasInventoryBuilderMarksProjectSelectionAliasContextUncertain(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "tsconfig.json"), `{"include":["src/**"],"compilerOptions":{"paths":{"@x/*":["src/*"]}}}`)
	got, err := newAliasInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.configs) != 1 || !got.configs[0].uncertain || !hasCoverageKind(got.coverage, jsresolution.CoverageUnsupportedAlias) {
		t.Fatalf("project-selection alias context was treated as certain: %#v", got)
	}
}
