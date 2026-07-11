package reachproof_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNotAgentReachable structurally enforces that the reachproof coordinator –
// which CAN reach the judgment verify path (the score-mover) – is never imported by the agent tool
// catalog or the agent orchestrator. The agent stays propose-only (it reaches judgments only through the
// propose-only judgmentProposer); a deterministic confirm path must remain composition-root-only. A future
// edge that wired this package into the agent surface would hand the agent a self-confirm path – this test
// fails loud if that happens. Best-effort: skips without the toolchain.
func TestNotAgentReachable(t *testing.T) {
	const self = "github.com/KKloudTarus/synapse-ce/internal/usecase/reachproof"
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
				t.Errorf("%s imports the reachproof coordinator – that would give the agent a deterministic CONFIRM path; keep it composition-root-only", pkg)
			}
		}
	}
}
