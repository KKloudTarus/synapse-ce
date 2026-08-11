package cloudposture

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDomainHasNoProviderSDKImports(t *testing.T) {
	err := filepath.WalkDir("..", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range file.Imports {
			importPath, _ := strconv.Unquote(imp.Path.Value)
			for _, forbidden := range []string{"github.com/aws/", "github.com/Azure/", "cloud.google.com/go", "google.golang.org/api"} {
				if strings.HasPrefix(importPath, forbidden) {
					t.Fatalf("domain file %s imports provider SDK %q", path, importPath)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
