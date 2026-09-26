package msgtemplate

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// allowedImports keeps the engine pure: stdlib only, no I/O, no reflection-based escape hatches, and
// no dependency on the notification or ticketing packages that use it.
var allowedImports = map[string]bool{
	"errors":              true,
	"fmt":                 true,
	"sort":                true,
	"strconv":             true,
	"strings":             true,
	"text/template":       true,
	"text/template/parse": true,
	"unicode/utf8":        true,
}

func TestPackageImportsOnlyAllowedStdlib(t *testing.T) {
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && path != "." {
			return fs.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range file.Imports {
			importPath, _ := strconv.Unquote(imp.Path.Value)
			if !allowedImports[importPath] {
				t.Errorf("%s imports %q, which msgtemplate does not allow", path, importPath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
