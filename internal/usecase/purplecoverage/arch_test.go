package purplecoverage

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDomainDoesNotImportPortsOrPersistence asserts the dependency rule for the purple-coverage domain:
// the pure domain (internal/domain/purplecoverage) must not reach outward to usecase ports or any
// persistence package. The join/verdict logic stays pure; the I/O lives here in the usecase.
func TestDomainDoesNotImportPortsOrPersistence(t *testing.T) {
	root := filepath.Join("..", "..", "..", "internal", "domain", "purplecoverage")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read domain dir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(root, e.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if strings.Contains(p, "usecase/ports") || strings.Contains(p, "persistence") || strings.Contains(p, "usecase/") {
				t.Errorf("%s imports %q — the purple-coverage domain must stay pure", e.Name(), p)
			}
		}
	}
}
