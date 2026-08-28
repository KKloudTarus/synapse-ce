package sca

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

func TestSecretRuleConfidence(t *testing.T) {
	high := []string{"github-token", "gitlab-pat", "slack-token", "aws-access-key-id", "private-key", "stripe-secret-key"}
	for _, id := range high {
		if got := secretRuleConfidence(id); got != vulnerability.ConfidenceHigh {
			t.Errorf("fixed-prefix rule %q confidence = %q, want high", id, got)
		}
	}
	medium := []string{"generic-secret", "aws-secret-access-key", "db-connection-string", "jwt"}
	for _, id := range medium {
		if got := secretRuleConfidence(id); got != vulnerability.ConfidenceMedium {
			t.Errorf("entropy/context rule %q confidence = %q, want medium", id, got)
		}
	}
}
