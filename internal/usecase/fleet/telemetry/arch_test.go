package telemetry

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTelemetryStoreNeverLeaksIntoDomain is the #424 architecture acceptance: the columnar telemetry
// store appears in NO domain type. The store is reached only through ports.TelemetryStore (a usecase
// port), and the dependency rule already forbids a domain package from importing usecase/ports — so a
// telemetry type could only reach the domain by someone breaking that rule. This test walks every
// internal/domain package and fails if any file imports usecase/ports (which is where TelemetryStore and
// its row/query types live) or a persistence package, catching such a leak explicitly rather than
// relying on review.
func TestTelemetryStoreNeverLeaksIntoDomain(t *testing.T) {
	// Locate the repo's internal/domain from this test's working directory
	// (internal/usecase/fleet/telemetry -> ../../../domain).
	domainRoot, err := filepath.Abs(filepath.Join("..", "..", "..", "domain"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(domainRoot); err != nil {
		t.Fatalf("cannot find internal/domain at %s: %v", domainRoot, err)
	}

	forbidden := []string{
		"internal/usecase/ports",              // where TelemetryStore + telemetry types live
		"internal/infrastructure/persistence", // any concrete store, including the columnar tier
	}
	fset := token.NewFileSet()
	walkErr := filepath.Walk(domainRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if strings.Contains(p, bad) {
					t.Errorf("domain file %s imports %q — the telemetry store (and any persistence) must never reach a domain type", path, p)
				}
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walking domain: %v", walkErr)
	}
}
