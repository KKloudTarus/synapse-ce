package msgmarkdown

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// allowedImports keeps the parser pure: the standard library only, no I/O.
var allowedImports = map[string]bool{
	"strings":      true,
	"unicode":      true,
	"unicode/utf8": true,
}

// allowedTestImports adds what the tests need; msgtemplate is used to check the escaping contract.
var allowedTestImports = map[string]bool{
	"go/parser":     true,
	"go/token":      true,
	"os":            true,
	"path/filepath": true,
	"strconv":       true,
	"testing":       true,
	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate": true,
}

func TestPackageImportsOnlyTheStandardLibrary(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		test := strings.HasSuffix(name, "_test.go")
		for _, spec := range file.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			if !allowedImports[path] && !(test && allowedTestImports[path]) {
				t.Errorf("%s imports %s", name, path)
			}
		}
	}
	if _, err := os.Stat("doc.go"); err != nil {
		t.Fatal("package documentation is missing")
	}
}
