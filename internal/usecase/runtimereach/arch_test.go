package runtimereach_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNotAgentReachable structurally enforces that the runtimereach coordinator, which CAN reach the
// judgment verify path (the score-mover), is never imported by the agent tool catalog or the agent
// orchestrator. The agent stays propose-only; a deterministic confirm path must remain
// composition-root-only, or the agent would gain a self-confirm path. Best-effort: skips without the
// toolchain.
func TestNotAgentReachable(t *testing.T) {
	const self = "github.com/KKloudTarus/synapse-ce/internal/usecase/runtimereach"
	forbidden := []string{
		"github.com/KKloudTarus/synapse-ce/internal/usecase/agenttools",
		"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator",
		// synapse-mcp is read/propose-only and must never reach the score-mover (Verify) either.
		"github.com/KKloudTarus/synapse-ce/internal/adapter/mcpserver",
	}
	for _, pkg := range forbidden {
		out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", pkg).CombinedOutput()
		if err != nil {
			t.Skipf("go toolchain unavailable for the dependency scan (%v); the boundary is otherwise composition-root-only by construction", err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.TrimSpace(line) == self {
				t.Errorf("%s imports the runtimereach coordinator; keep it composition-root-only", pkg)
			}
		}
	}
}
