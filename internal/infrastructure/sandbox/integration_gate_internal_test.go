package sandbox

import (
	"os"
	"testing"
)

// requireSandboxIntegration mirrors the external-package gate for the internal (package sandbox)
// integration tests. See integration_gate_test.go for the rationale.
func requireSandboxIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("SYNAPSE_SANDBOX_INTEGRATION") == "" {
		t.Skip("privileged sandbox integration test: set SYNAPSE_SANDBOX_INTEGRATION=1 on a sandbox-capable host")
	}
}
