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
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
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
