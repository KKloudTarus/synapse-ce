package export

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestExportPathHasNoLLM is the golden-rule-5 tripwire for the export path (SARIF / OpenVEX): the
// customer-facing artifacts are templated from STORED data, with no LLM anywhere. It fails if any
// non-test source file in this package imports an agent/LLM package or references an LLM port type.
// Export now reads AI judgments for the OpenVEX justification-by-tier – it reads only TYPED
// data through ports.JudgmentStore, never the judgment USE CASE (usecase/analysis is forbidden) and
// never an LLM – so nobody can quietly wire a model into a deliverable. Mirrors report/arch_test.go.
func TestExportPathHasNoLLM(t *testing.T) {
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
	// ports.LLM / ChatRequest / ChatResponse are LLM types living in the (otherwise allowed)
	// ports package; flag them by selector so importing ports for FindingRepository is fine.
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
					t.Errorf("%s imports forbidden package %q – no LLM/agent in the export path", name, p)
				}
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "ports" && forbiddenSelector[sel.Sel.Name] {
				t.Errorf("%s references ports.%s – the export path must not touch an LLM type", name, sel.Sel.Name)
			}
			return true
		})
	}
	if scanned == 0 {
		t.Fatal("scanned no export source files – test wiring is wrong")
	}
}

// TestExportPathHasNoLLMTransitive is defense-in-depth over the direct scan: the export package's
// FULL transitive import graph must reach no LLM implementation or agent-orchestration package –
// catching a model wired in two hops away. domain/agent + usecase/ports are deliberately NOT
// forbidden (export reaches them only via ports, which defines the agent/LLM port TYPES; no model
// runs from a type or an interface). Best-effort: skips if the go toolchain is unavailable.
func TestExportPathHasNoLLMTransitive(t *testing.T) {
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
				t.Errorf("export transitively imports forbidden package %q – no LLM/agent in the export path", dep)
			}
		}
	}
}
