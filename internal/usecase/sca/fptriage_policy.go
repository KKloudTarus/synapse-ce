package sca

import (
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// aiTriagePolicyVersion is sealed with every scan that carries AI triage. Bump it whenever the
// authorization contract changes so an audit can replay which policy could affect a CI gate.
const aiTriagePolicyVersion = "fp-gate-v1"

const (
	aiPolicyNotSuspected      = "not_suspected_false_positive"
	aiPolicyVerifierRequired  = "distinct_verifier_required"
	aiPolicyFindingMissing    = "finding_not_found"
	aiPolicySeverityFloor     = "severity_requires_human"
	aiPolicySecretFloor       = "secret_requires_human"
	aiPolicyDangerousCWEFloor = "cwe_requires_human"
	aiPolicyVerifiedConsensus = "verified_consensus"
)

// humanReviewCWEs are weakness classes where a false negative can directly expose an execution,
// injection, authentication/authorization, request-forgery, traversal, upload, or deserialization
// boundary. Even two agreeing models can only advise on these classes; they never exempt the gate.
var humanReviewCWEs = map[string]struct{}{
	"CWE-22":  {}, // path traversal
	"CWE-23":  {},
	"CWE-36":  {},
	"CWE-78":  {}, // OS command injection
	"CWE-79":  {}, // XSS / output injection
	"CWE-89":  {}, // SQL injection
	"CWE-94":  {}, // code injection
	"CWE-284": {}, // access control
	"CWE-285": {},
	"CWE-287": {}, // authentication
	"CWE-306": {},
	"CWE-434": {}, // unrestricted upload
	"CWE-502": {}, // unsafe deserialization
	"CWE-862": {},
	"CWE-863": {},
	"CWE-918": {}, // SSRF
}

// applyAIGatePolicy separates an AI opinion from authorization to change a gate. It is the single
// policy point used by both CLI and API scans. The triager may propose SuspectedFP, but only a complete
// distinct-model consensus that clears the human-review floor receives GateExempt.
func applyAIGatePolicy(result *ScanResult) {
	if result == nil || len(result.AITriage) == 0 {
		return
	}
	findings := make(map[string]finding.Finding, len(result.Findings))
	for _, item := range result.Findings {
		if key := strings.TrimSpace(item.DedupKey); key != "" {
			findings[key] = item
		}
	}
	for i := range result.AITriage {
		critique := &result.AITriage[i]
		critique.PolicyVersion = aiTriagePolicyVersion
		critique.GateExempt = false
		critique.ReviewRequired = false

		if !critique.SuspectedFP {
			critique.PolicyReason = aiPolicyNotSuspected
			continue
		}
		if !hasVerifiedConsensus(*critique) {
			critique.PolicyReason = aiPolicyVerifierRequired
			critique.ReviewRequired = true
			continue
		}
		item, ok := findings[strings.TrimSpace(critique.DedupKey)]
		if !ok {
			critique.PolicyReason = aiPolicyFindingMissing
			critique.ReviewRequired = true
			continue
		}
		if reason := humanReviewFloor(item); reason != "" {
			critique.PolicyReason = reason
			critique.ReviewRequired = true
			continue
		}
		critique.PolicyReason = aiPolicyVerifiedConsensus
		critique.GateExempt = true
	}
}

// hasVerifiedConsensus validates the full DTO rather than trusting its Verified boolean. This keeps a
// buggy or alternate FPTriager implementation from granting itself gate authority by setting one field.
func hasVerifiedConsensus(c ports.AICritique) bool {
	proposer := strings.TrimSpace(c.ProposerModel)
	verifierModel := strings.TrimSpace(c.VerifierModel)
	return c.Verified &&
		proposer != "" && verifierModel != "" && proposer != verifierModel &&
		c.Verdict == string(judgment.CritiqueRefuted) && c.Confidence >= verdict.EvidenceThreshold &&
		c.VerifierVerdict == string(judgment.CritiqueRefuted) &&
		c.VerifierConfidence >= verdict.EvidenceThreshold
}

func humanReviewFloor(item finding.Finding) string {
	if item.Severity == shared.SeverityCritical || item.Severity == shared.SeverityHigh {
		return aiPolicySeverityFloor
	}
	if item.Kind == finding.KindSecret {
		return aiPolicySecretFloor
	}
	for _, token := range strings.FieldsFunc(strings.ToUpper(item.CWE), func(r rune) bool {
		return r == ',' || r == ';' || r == '|' || r == '/' || r == ' ' || r == '\t' || r == '\n'
	}) {
		if _, protected := humanReviewCWEs[token]; protected {
			return aiPolicyDangerousCWEFloor
		}
	}
	return ""
}
