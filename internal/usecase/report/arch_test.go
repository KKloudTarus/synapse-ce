package report

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestReportPathHasNoLLM is the golden-rule-5 tripwire: reports are templated from STORED
// data, with no LLM anywhere in the path. It fails if any non-test source file in this
// package imports an agent/LLM package or references an LLM port type – so nobody can ever
// quietly wire a model into the deterministic report builder. It parses the package's own
// sources (the test's working dir is the package dir under `go test`).
func TestReportPathHasNoLLM(t *testing.T) {
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
					t.Errorf("%s imports forbidden package %q – no LLM/agent in the report path", name, p)
				}
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "ports" && forbiddenSelector[sel.Sel.Name] {
				t.Errorf("%s references ports.%s – the report path must not touch an LLM type", name, sel.Sel.Name)
			}
			return true
		})
	}
	if scanned == 0 {
		t.Fatal("scanned no report source files – test wiring is wrong")
	}
}

// TestReportPathHasNoLLMTransitive is defense-in-depth over the direct-import scan above: it
// asserts the report package's FULL transitive import graph reaches no LLM implementation or
// agent-orchestration package – catching a model wired in two hops away (report → helper →
// llm), which the direct scan cannot see. Note domain/agent + usecase/ports are deliberately
// NOT forbidden: report reaches them only via ports (which defines the agent/LLM port types),
// and no model runs from a type or an interface. Best-effort: skips if the go toolchain is
// unavailable, so the always-on direct scan remains the floor.
func TestReportPathHasNoLLMTransitive(t *testing.T) {
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
				t.Errorf("report transitively imports forbidden package %q – no LLM/agent in the report path", dep)
			}
		}
	}
}
