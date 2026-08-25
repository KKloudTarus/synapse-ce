package fleetagent

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestSamplingPolicyDigestInvalidInputWrapsValidation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		algorithm string
		policyID  string
		version   uint64
	}{
		{name: "missing algorithm", policyID: "policy-1", version: 1},
		{name: "missing policy id", algorithm: "none", version: 1},
		{name: "zero version", algorithm: "none", policyID: "policy-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SamplingPolicyDigest(tc.algorithm, tc.policyID, "seed", tc.version)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("SamplingPolicyDigest() error = %v, want shared.ErrValidation", err)
			}
		})
	}
}
