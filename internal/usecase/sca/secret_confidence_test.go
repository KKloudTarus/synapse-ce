package sca

import (
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
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

// D6.3: an actively-verified live credential is raised to very_high — strictly above the high base the
// verifiable fixed-prefix rules already carry, so verification is OBSERVABLE (a verified github-token
// outranks an unchecked one). An unverified or unknown verdict keeps the base confidence (never suppressed,
// never lowered). This uses github-token, a rule the real pipeline can actually verify (unlike a
// medium-tier rule that has no provider and can never be verified).
func TestSecretFindingConfidenceUsesVerdict(t *testing.T) {
	// A verifiable fixed-prefix rule (base high), verified live, is elevated to very_high.
	verified := ports.SecretRawFinding{RuleID: "github-token", Verified: ports.SecretVerified}
	if got := secretFindingConfidence(verified); got != vulnerability.ConfidenceVeryHigh {
		t.Errorf("a verified github-token must be very_high (above its high base), got %q", got)
	}
	// The same rule, unverified, keeps its high base (never lowered, never suppressed) — and is strictly
	// below the verified case, so verification is observable.
	unverified := ports.SecretRawFinding{RuleID: "github-token", Verified: ports.SecretUnverified}
	if got := secretFindingConfidence(unverified); got != vulnerability.ConfidenceHigh {
		t.Errorf("an unverified github-token must keep its base high confidence, got %q", got)
	}
	// Unknown (default, verification off) is unchanged from the rule base, and below verified.
	unknown := ports.SecretRawFinding{RuleID: "github-token", Verified: ports.SecretUnknown}
	if got := secretFindingConfidence(unknown); got != vulnerability.ConfidenceHigh {
		t.Errorf("an unknown-verdict github-token keeps its base high confidence, got %q", got)
	}
	// A medium-tier rule keeps medium when not verified (base confidence preserved).
	if got := secretFindingConfidence(ports.SecretRawFinding{RuleID: "generic-secret", Verified: ports.SecretUnknown}); got != vulnerability.ConfidenceMedium {
		t.Errorf("an unchecked generic-secret keeps its medium base, got %q", got)
	}
}

// A verified/unverified verdict is surfaced in the finding description, and an unverified verdict never
// removes the finding (buildSecretFindings still emits it).
func TestBuildSecretFindingsSurfacesVerdict(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	raws := []ports.SecretRawFinding{
		{File: "a.go", Line: 1, RuleID: "github-token", Category: "GitHub", Title: "GitHub token", Severity: shared.SeverityHigh, Match: "ghp****ab", Verified: ports.SecretVerified},
		{File: "b.go", Line: 2, RuleID: "gitlab-pat", Category: "GitLab", Title: "GitLab PAT", Severity: shared.SeverityHigh, Match: "glp****cd", Verified: ports.SecretUnverified},
	}
	out := buildSecretFindings(shared.ID("eng"), raws, now, shared.SeverityInfo, true)
	if len(out) != 2 {
		t.Fatalf("an unverified secret must still be reported (never suppressed); got %d findings", len(out))
	}
	var sawLive, sawNotLive bool
	for _, f := range out {
		if strings.Contains(f.Description, "confirmed this credential is LIVE") {
			sawLive = true
		}
		if strings.Contains(f.Description, "not currently live") {
			sawNotLive = true
		}
	}
	if !sawLive {
		t.Error("a verified finding must note it is live")
	}
	if !sawNotLive {
		t.Error("an unverified finding must note it is not currently live (and still be reported)")
	}
}
