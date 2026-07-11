package taintscan_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNotAgentReachable structurally enforces that the taint coordinator is never imported by the agent
// tool catalog or the orchestrator. The taint engine proposes gated CapSAST judgments under a reserved
// system identity; even though it is propose-only (it cannot move a score), it must remain a
// pipeline-driven, composition-root-only path – never an agent capability. A future edge that wired this
// package into the agent surface would let the agent drive a system-identity proposer; this test fails
// loud if that happens (mirrors reachproof C3). Best-effort: skips without the toolchain.
func TestNotAgentReachable(t *testing.T) {
	const self = "github.com/KKloudTarus/synapse-ce/internal/usecase/taintscan"
	forbidden := []string{
		"github.com/KKloudTarus/synapse-ce/internal/usecase/agenttools",
		"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator",
	}
	for _, pkg := range forbidden {
		out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", pkg).CombinedOutput()
		if err != nil {
			t.Skipf("go toolchain unavailable for the dependency scan (%v); the boundary is otherwise composition-root-only by construction", err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.TrimSpace(line) == self {
				t.Errorf("%s imports the taintscan coordinator – keep the taint engine composition-root-only (never agent-reachable)", pkg)
			}
		}
	}
}
