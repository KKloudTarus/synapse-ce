package ssacallgraph_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNotInServerImportGraph structurally enforces that the SSA call-graph
// builder stays OUT of the live server binaries' import graph. BuildGraph uses golang.org/x/tools to LOAD +
// COMPILE untrusted target source (go/packages drives the toolchain – incl. the C compiler for cgo). Doing
// that IN-PROCESS would run target-controlled compilation in the server's address space + privileges (and
// bloat the binary with x/tools), so – like the govulncheck builder – it is meant to run ONLY as a
// sandboxed argv binary (cmd/synapse-callgraph, a follow-up slice) the adapter execs. This test fails loud
// if a future edge wires the builder (or the go/ssa | go/packages libs) directly into synapse-api/worker.
// Best-effort: skips without the toolchain.
func TestNotInServerImportGraph(t *testing.T) {
	const self = "github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ssacallgraph"
	forbidden := func(imp string) bool {
		return imp == self ||
			strings.HasPrefix(imp, "golang.org/x/tools/go/ssa") ||
			strings.HasPrefix(imp, "golang.org/x/tools/go/packages") ||
			strings.HasPrefix(imp, "golang.org/x/tools/go/callgraph")
	}
	for _, server := range []string{
		"github.com/KKloudTarus/synapse-ce/cmd/synapse-api",
		"github.com/KKloudTarus/synapse-ce/cmd/synapse-worker",
	} {
		out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", server).CombinedOutput()
		if err != nil {
			t.Skipf("go toolchain unavailable for the dependency scan (%v); the boundary is otherwise enforced by the argv-binary design", err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			if imp := strings.TrimSpace(line); forbidden(imp) {
				t.Errorf("%s imports %q – the SSA builder compiles UNTRUSTED target source and must stay out of the server; run it only as the sandboxed cmd/synapse-callgraph argv binary", server, imp)
			}
		}
	}
}
