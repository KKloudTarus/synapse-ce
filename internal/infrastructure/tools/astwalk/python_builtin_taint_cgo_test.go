//go:build cgo

package astwalk

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/pythonprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
)

// TestPythonBuiltinSourceSinkResolution guards that the taint catalog's bare-builtin source (input) and
// code-execution sinks (eval/exec/compile) are actually reachable end to end. They are modeled in
// DefaultPythonCatalog, but a bare call resolves to "builtins.<name>" only when the name is in the resolver's
// builtinCallables allowlist; input/eval/exec/compile were missing, so those source/sink models were dead.
func TestPythonBuiltinSourceSinkResolution(t *testing.T) {
	detect := func(t *testing.T, src string) []string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "m.py"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		doc, err := PythonFactsFor(context.Background(), dir)
		if err != nil {
			t.Fatalf("facts: %v", err)
		}
		res, err := pythonprogram.Resolve(doc)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		g, err := taint.BuildPythonValueGraph(doc, res, taint.DefaultPythonCatalog())
		if err != nil {
			t.Fatalf("graph: %v", err)
		}
		var cwes []string
		for _, p := range g.Vulnerabilities() {
			cwes = append(cwes, p.CWE)
		}
		return cwes
	}
	has := func(cwes []string, want string) bool {
		for _, c := range cwes {
			if c == want {
				return true
			}
		}
		return false
	}

	// input() source flowing into os.system -> command injection (CWE-78).
	if cwes := detect(t, "import os\ndef f():\n    x = input()\n    os.system(x)\n"); !has(cwes, "CWE-78") {
		t.Errorf("input() must be recognized as a taint source into os.system (CWE-78), got %v", cwes)
	}
	// eval() sink on tainted input -> code injection (CWE-94).
	if cwes := detect(t, "import os\ndef f():\n    x = os.getenv(\"X\")\n    eval(x)\n"); !has(cwes, "CWE-94") {
		t.Errorf("eval() must be recognized as a code-execution sink (CWE-94), got %v", cwes)
	}
	// exec() sink on tainted input -> code injection (CWE-94).
	if cwes := detect(t, "import os\ndef f():\n    x = os.getenv(\"X\")\n    exec(x)\n"); !has(cwes, "CWE-94") {
		t.Errorf("exec() must be recognized as a code-execution sink (CWE-94), got %v", cwes)
	}
	// A locally-shadowed builtin must NOT resolve to the builtin (no false source): a user eval() that is a
	// local function is not the code-execution sink.
	if cwes := detect(t, "import os\ndef eval(x):\n    return x\ndef f():\n    y = os.getenv(\"X\")\n    eval(y)\n"); has(cwes, "CWE-94") {
		t.Errorf("a locally-defined eval() must not be treated as the builtin sink, got %v", cwes)
	}
}
