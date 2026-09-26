package docs_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestProductionGoDoesNotImportTestSupport(t *testing.T) {
	root := repoRoot(t)
	for _, tree := range []string{"api", "cmd", "deploy", "internal", "migrations", "scripts"} {
		err := filepath.WalkDir(filepath.Join(root, tree), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				if entry.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imported := range file.Imports {
				name, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					return err
				}
				if strings.Contains(name, "/internal/testutil/") {
					t.Errorf("production file %s imports test support %s", path, name)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("inspect production Go imports in %s: %v", tree, err)
		}
	}
}
