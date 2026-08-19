package telemetry

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

// TestArchNoDetectionObservationType enforces the A1 boundary (#622): the raw-telemetry domain owns its
// OWN observation schema (TelemetryEvent + the per-class *Observation types) and must never reuse
// detection.Event — the thin, single-timestamp shape built for rule matching — as the canonical
// observation type. Reusing detection.Class (the four-value class enum) is allowed and intentional; the
// forbidden thing is the detection OBSERVATION types.
//
// The check parses each source file and inspects real selector expressions (detection.X in CODE), so a
// doc comment that merely MENTIONS "detection.Event" to explain the boundary does not trip it.
func TestArchNoDetectionObservationType(t *testing.T) {
	forbidden := map[string]bool{
		"Event":          true,
		"ProcessEvent":   true,
		"NetworkEvent":   true,
		"FileEvent":      true,
		"PrivilegeEvent": true,
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		// Exclude test files from the boundary scan: the boundary is a property of the shipped package,
		// and tests legitimately reference detection.ClassProcess etc.
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("arch test parsed no packages; the boundary is not actually being checked")
	}

	scannedFiles := 0
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			scannedFiles++
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if !ok || ident.Name != "detection" {
					return true
				}
				if forbidden[sel.Sel.Name] {
					t.Errorf("%s uses detection.%s in code — raw telemetry must not reuse the detection observation type (A1/D4 boundary)", name, sel.Sel.Name)
				}
				return true
			})
		}
	}
	if scannedFiles == 0 {
		t.Fatal("arch test scanned no source files; the boundary is not actually being checked")
	}
}
