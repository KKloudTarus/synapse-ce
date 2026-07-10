package sandbox_test

import (
	"os"
	"testing"
)

// requireSandboxIntegration skips a privileged sandbox integration test unless it is explicitly enabled.
// These tests assert real kernel isolation (mount/user/network namespaces via bubblewrap, egress filtering,
// and cgroup v2 limits), which needs a host that provides all of it: a delegated, writable cgroup subtree
// plus the ability to enforce netns egress. A typical CI runner or an unprivileged container (for example a
// dev workspace running as a non-root user without cgroup delegation) has bubblewrap but cannot enforce
// those controls, so the tests would fail spuriously rather than validate anything. Run them with
// SYNAPSE_SANDBOX_INTEGRATION=1 on a validated Linux host (the sandbox-host validation environment).
func requireSandboxIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("SYNAPSE_SANDBOX_INTEGRATION") == "" {
		t.Skip("privileged sandbox integration test: set SYNAPSE_SANDBOX_INTEGRATION=1 on a sandbox-capable host")
	}
}
