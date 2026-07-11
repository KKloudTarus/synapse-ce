package crosscheckjudge_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNotAgentReachable structurally enforces that the cross-check
// coordinator – whose narrow proposer is satisfied by analysis.Service (which also carries the score-mover
// Verify/Accept) – is never imported by the agent tool catalog or the orchestrator. The agent stays
// propose-only (it reaches judgments only through the propose-only judgmentProposer); a system-identity
// minting path must remain composition-root-only. A future edge that wired this package into the agent
// surface would hand the agent a propose path under a NON-agent (`system:cross-check`) identity – this test
// fails loud if that happens. Best-effort: skips without the toolchain.
func TestNotAgentReachable(t *testing.T) {
	const self = "github.com/KKloudTarus/synapse-ce/internal/usecase/crosscheckjudge"
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
				t.Errorf("%s imports the cross-check coordinator – that would give the agent a system-identity mint path; keep it composition-root-only", pkg)
			}
		}
	}
}
