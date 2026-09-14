//go:build cgo

package astwalk

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
)

// resolveJSSource writes one app.js under a fresh dir, extracts real facts, and resolves the call graph.
func resolveJSSource(t *testing.T, source string) jsprogram.Resolution {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := JsFactsFor(context.Background(), dir)
	if err != nil {
		t.Fatalf("extract js facts: %v", err)
	}
	res, err := jsprogram.Resolve(doc)
	if err != nil {
		t.Fatalf("resolve js facts: %v", err)
	}
	return res
}

// TestJSExternalNodeReachabilityEndToEnd is the whole vertical on the REAL tree-sitter extractor: a
// first-party call into a third-party package must produce a reachable external node, and an
// imported-but-uncalled package must not. This is what the production interprocedural JS Tier-2 analyzer
// (internal/usecase/jsreach) queries; the analyzer's matching logic is unit-tested separately.
func TestJSExternalNodeReachabilityEndToEnd(t *testing.T) {
	node := jsprogram.ExternalSymbolID("lodash", "template")

	// A named import called through a first-party wrapper reached from module top level: reachable.
	reached := resolveJSSource(t, "import { template } from 'lodash';\nfunction render(x) { return template(x); }\nrender('hi');\n")
	if !reached.Graph.Reaches(node) {
		t.Errorf("a lodash.template call reached through a first-party wrapper must reach %s", node)
	}

	// Imported but never called: the external node is not reachable (import is not reach).
	uncalled := resolveJSSource(t, "import { template } from 'lodash';\nfunction render(x) { return x; }\nrender('hi');\n")
	if uncalled.Graph.Reaches(node) {
		t.Errorf("an imported-but-uncalled lodash.template must not be reachable (import != reach)")
	}

	// A direct top-level call is reachable too.
	direct := resolveJSSource(t, "import { template } from 'lodash';\ntemplate('hi');\n")
	if !direct.Graph.Reaches(node) {
		t.Errorf("a top-level lodash.template call must reach %s", node)
	}
}
