package riskstoryuc

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestRiskStoryAssemblyHasNoLLM is the #427 architecture assertion: the risk story is assembled
// DETERMINISTICALLY from stored records, with no LLM anywhere in the assembly path (prose narration
// stays in the human-gated writeupdraft path, outside the report). It fails if any non-test source file
// in this package imports an agent/LLM package or references an LLM port type, so nobody can quietly
// wire a model into the deterministic assembler.
func TestRiskStoryAssemblyHasNoLLM(t *testing.T) {
	const mod = "github.com/KKloudTarus/synapse-ce"
	forbiddenImport := []string{
		mod + "/internal/domain/agent",
		mod + "/internal/usecase/agent",
		mod + "/internal/usecase/agenttools",
		mod + "/internal/usecase/safety",
		mod + "/internal/usecase/approval",
		mod + "/internal/usecase/exploitation",
		mod + "/internal/usecase/analysis",
		mod + "/internal/infrastructure/llm",
	}
	// ports.LLM / ChatRequest / ChatResponse are LLM types living in the (otherwise allowed) ports
	// package; flag them by selector so importing ports for a read store is fine.
	forbiddenSelector := map[string]bool{"LLM": true, "ChatRequest": true, "ChatResponse": true}

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
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range file.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbiddenImport {
				if p == bad || strings.HasPrefix(p, bad+"/") {
					t.Errorf("%s imports forbidden package %q – no LLM/agent in the risk-story assembly path", name, p)
				}
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "ports" && forbiddenSelector[sel.Sel.Name] {
				t.Errorf("%s references ports.%s – the risk-story assembly path must not touch an LLM type", name, sel.Sel.Name)
			}
			return true
		})
	}
	if scanned == 0 {
		t.Fatal("scanned no risk-story source files – test wiring is wrong")
	}
}

// TestRiskStoryAssemblyHasNoLLMTransitive is defense-in-depth over the direct-import scan: it asserts
// the package's FULL transitive import graph reaches no LLM implementation or agent-orchestration
// package, catching a model wired in two hops away. Best-effort: skips if the go toolchain is
// unavailable, so the always-on direct scan remains the floor.
func TestRiskStoryAssemblyHasNoLLMTransitive(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", ".").CombinedOutput()
	if err != nil {
		t.Skipf("go toolchain unavailable for the transitive check (%v); the direct-import scan still applies", err)
	}
	const mod = "github.com/KKloudTarus/synapse-ce"
	forbidden := []string{
		mod + "/internal/infrastructure/llm",
		mod + "/internal/usecase/agent",
		mod + "/internal/usecase/agenttools",
		mod + "/internal/usecase/safety",
		mod + "/internal/usecase/approval",
		mod + "/internal/usecase/exploitation",
		mod + "/internal/usecase/analysis",
	}
	for _, line := range strings.Split(string(out), "\n") {
		dep := strings.TrimSpace(line)
		for _, bad := range forbidden {
			if dep == bad || strings.HasPrefix(dep, bad+"/") {
				t.Errorf("risk-story assembly transitively imports forbidden package %q – no LLM/agent in the assembly path", dep)
			}
		}
	}
}
