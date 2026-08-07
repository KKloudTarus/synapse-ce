package jsresolve

import (
	"context"
	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"os"
	"path/filepath"
	"testing"
)

func TestAliasInventoryBuilderPatternByteBudget(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"root","imports":{"#abcdef":"./src/a"}}`)
	limits := defaultAliasLimits()
	limits.maxPatternBytes = 4
	got, err := newAliasInventoryBuilderWithLimits(limits).Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !hasCoverageKind(got.coverage, jsresolution.CoverageUnsupportedAlias) {
		t.Fatalf("oversized alias pattern did not produce coverage: %#v", got.coverage)
	}
}

func TestAliasInventoryBuilderAcceptsUTF8BOMJSONC(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	content := append([]byte{0xef, 0xbb, 0xbf}, []byte(`{"compilerOptions":{"paths":{"@x/*":["src/*"]}}}`)...)
	if err := os.WriteFile(filepath.Join(root, "tsconfig.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := newAliasInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.mappings) != 1 || len(got.coverage) != 0 {
		t.Fatalf("BOM JSONC parse = %#v", got)
	}
}

func TestAliasInventoryBuilderTracksMalformedNestedPackageBoundary(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"root","imports":{"#x":"lodash"}}`)
	writeFile(t, filepath.Join(root, "packages", "app", "package.json"), `{not-json`)

	got, err := newAliasInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	var nested aliasPackageContext
	found := false
	for _, scope := range got.packageScopes {
		if scope.scopeDir == "packages/app" {
			nested, found = scope, true
			break
		}
	}
	if !found || !nested.uncertain {
		t.Fatalf("malformed nested package boundary was not retained as uncertain: %#v", got.packageScopes)
	}
}

func TestAliasInventoryBuilderUnsupportedImportsMakesWholeScopeUncertain(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{
  "name":"root",
  "imports":{
    "#x":{"default":"lodash"},
    "#*":"left-pad"
  }
}`)

	got, err := newAliasInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.packageScopes) != 1 || !got.packageScopes[0].importsPresent || !got.packageScopes[0].uncertain {
		t.Fatalf("partially unsupported imports scope was not marked uncertain: %#v", got.packageScopes)
	}
}

func TestAliasInventoryBuilderPartialTSPathsMakesContextUncertain(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "tsconfig.json"), `{
  "compilerOptions":{"paths":{"@ok/*":["src/*"],"@bad/*":["node_modules/pkg/*"]}}
}`)

	got, err := newAliasInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.configs) != 1 || !got.configs[0].uncertain {
		t.Fatalf("partially unsupported paths config was not marked uncertain: %#v", got.configs)
	}
}

func TestAliasInventoryBuilderMappingBudgetNeverStoresPartialSource(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"root","imports":{"#a":"a","#b":"b"}}`)
	limits := defaultAliasLimits()
	limits.maxMappings = 1

	got, err := newAliasInventoryBuilderWithLimits(limits).Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.mappings) != 0 || len(got.packageScopes) != 1 || !got.packageScopes[0].uncertain {
		t.Fatalf("mapping budget retained a semantically partial source: mappings=%#v scopes=%#v", got.mappings, got.packageScopes)
	}
	if !hasCoverageKind(got.coverage, jsresolution.CoverageMetadataBudgetExceeded) {
		t.Fatalf("mapping budget missing explicit coverage: %#v", got.coverage)
	}
}
