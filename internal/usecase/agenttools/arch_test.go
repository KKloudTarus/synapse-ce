package agenttools

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestCatalogCannotReachAScoreSetter pins the read-only-consumer invariant: the agent tool
// catalog must have NO path to move a finding's EvidenceScore or to
// confirm an exploitation finding. It therefore must not import the exploitation use case,
// the findings write service, or any concrete persistence (where SetEvidenceScore lives – it
// is deliberately off the ports.FindingRepository interface). The catalog reaches findings
// only through its own read-only findingReader interface. This is the structural twin of the
// report package's no-LLM tripwire: a same-package AST import scan that fails loudly if a
// future edit wires a score-setter into the LLM-facing tool surface.
func TestCatalogCannotReachAScoreSetter(t *testing.T) {
	const mod = "github.com/KKloudTarus/synapse-ce"
	forbidden := []string{
		mod + "/internal/usecase/exploitation",
		mod + "/internal/usecase/findings",
		mod + "/internal/usecase/analysis",       // judgment Verify (the score/state mover) – the agent must not reach it
		mod + "/internal/usecase/writeupdraftuc", // draft Edit/Accept/Reject (the human sign-off) – agent reaches Propose only, via the narrow writeupdraftProposer
		mod + "/internal/infrastructure",         // concrete repos hold SetEvidenceScore / SetScoreState (and the writeupdraft store)
	}
	// NOTE: domain/judgment is intentionally NOT forbidden – the catalog imports it for the
	// ReachabilityTier consts and will for ReachabilityClaim. Its in-memory
	// ApplyVerdict/Accept are value-receiver transitions with NO persistence reach; the actual
	// score/state move lives in the forbidden usecase/analysis + infrastructure setters above.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		file, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range file.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if p == bad || strings.HasPrefix(p, bad+"/") {
					t.Errorf("%s imports forbidden package %q – the agent tool catalog must not reach a finding score-setter", name, p)
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no catalog source files – test wiring is wrong")
	}
}
