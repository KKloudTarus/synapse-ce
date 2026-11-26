package acquire

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestAcquireGitRefusesInternalHostWithoutSandbox pins the git host check on the direct-exec path
// (#1698). Without a sandbox, git runs on the host with no egress policy, so this check is the only
// thing between a scan target and a loopback or metadata address. It must refuse before a credential
// is resolved or git is started.
func TestAcquireGitRefusesInternalHostWithoutSandbox(t *testing.T) {
	a := New()
	for _, target := range []string{
		"https://127.0.0.1:9200/x.git",
		"https://[::1]/x.git",
		"https://169.254.169.254/latest/meta-data/",
		"https://100.100.100.200/x.git",
	} {
		_, err := a.Acquire(context.Background(), ports.AcquireRequest{Kind: ports.TargetGit, Value: target})
		if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "SSRF") {
			t.Errorf("%s: error = %v, want the SSRF/metadata refusal", target, err)
		}
	}
}
