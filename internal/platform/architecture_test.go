package platform_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlatformDoesNotImportInfrastructure(t *testing.T) {
	assertNoInfrastructureImport(t, ".")
}

// TestUsecaseDoesNotImportInfrastructure enforces the inward dependency rule for the usecase layer:
// production usecase code depends on domain + usecase/ports only, never a concrete infrastructure
// package. Test files are exempt (they legitimately wire the in-memory adapter twins).
func TestUsecaseDoesNotImportInfrastructure(t *testing.T) {
	assertNoInfrastructureImport(t, filepath.Join("..", "usecase"))
}

func assertNoInfrastructureImport(t *testing.T, root string) {
	t.Helper()
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			if strings.Contains(spec.Path.Value, "/internal/infrastructure/") {
				t.Errorf("%s imports infrastructure package %s", path, spec.Path.Value)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
