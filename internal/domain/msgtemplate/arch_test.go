package msgtemplate

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// allowedImports keeps the engine pure: stdlib only apart from the shared textsafety rune classes,
// no I/O, no reflection-based escape hatches, and no dependency on the notification or ticketing
// packages that use it.
var allowedImports = map[string]bool{
	"errors":              true,
	"fmt":                 true,
	"sort":                true,
	"strconv":             true,
	"strings":             true,
	"text/template":       true,
	"text/template/parse": true,
	"unicode/utf8":        true,
	"github.com/KKloudTarus/synapse-ce/internal/domain/textsafety": true,
}

// allowedTestImports adds what the tests themselves need. Tests are held to a list too, so a test
// cannot quietly pull in the network or a third-party package.
var allowedTestImports = map[string]bool{
	"go/parser":     true,
	"go/token":      true,
	"os":            true,
	"path/filepath": true,
	"testing":       true,
	"text/template": true,
	"time":          true,
	"sync":          true,
}

func TestPackageImportsOnlyAllowedPackages(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".go" {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		isTest := strings.HasSuffix(name, "_test.go")
		for _, imp := range file.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if !allowedImports[path] && !(isTest && allowedTestImports[path]) {
				t.Errorf("%s imports %q, which msgtemplate does not allow", name, path)
			}
		}
	}
}
