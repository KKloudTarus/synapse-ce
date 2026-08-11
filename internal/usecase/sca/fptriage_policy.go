package sca

import (
	"strings"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// aiTriagePolicyVersion is sealed with every scan that carries AI triage. Bump it whenever the
// authorization contract changes so an audit can replay which policy could affect a CI gate.
const aiTriagePolicyVersion = "fp-gate-v4"

// EvaluationPolicyVersion returns the immutable policy identity for evaluation report metadata without
// exporting the authorization constant as part of the package API.
func EvaluationPolicyVersion() string { return aiTriagePolicyVersion }

// aiTriageMode controls whether an otherwise-authorized AI consensus can affect a quality gate.
// The zero value is deliberately shadow so missing/invalid composition fails closed.
type aiTriageMode string

const (
	aiTriageModeShadow  aiTriageMode = "shadow"
	aiTriageModeEnforce aiTriageMode = "enforce"
)

const (
	aiPolicyNotSuspected         = "not_suspected_false_positive"
	aiPolicyVerifierRequired     = "distinct_verifier_required"
	aiPolicyIndependenceRequired = "verifier_independence_required"
	aiPolicyFindingMissing       = "finding_not_found"
	aiPolicyFindingIneligible    = "finding_not_eligible"
	aiPolicySeverityFloor        = "severity_requires_human"
	aiPolicySecretFloor          = "secret_requires_human"
	aiPolicyDangerousCWEFloor    = "cwe_requires_human"
	aiPolicyEvidenceRequired     = "evidence_ledger_required"
	aiPolicyShadowMode           = "shadow_mode"
	aiPolicyVerifiedConsensus    = "verified_consensus"
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
	"CWE-259": {}, // hard-coded password
	"CWE-321": {}, // hard-coded cryptographic key
	"CWE-284": {}, // access control
	"CWE-285": {},
	"CWE-287": {}, // authentication
	"CWE-306": {},
	"CWE-434": {}, // unrestricted upload
	"CWE-502": {}, // unsafe deserialization
	"CWE-522": {}, // insufficiently protected credentials
	"CWE-798": {}, // hard-coded credentials
	"CWE-862": {},
	"CWE-863": {},
	"CWE-918": {}, // SSRF
}

// applyAIGatePolicy separates an AI opinion from authorization to change a gate. It is the single
// policy point used by both CLI and API scans. The triager may propose SuspectedFP, but only a complete
// distinct-model consensus that clears the human-review floor receives GateExempt.
func applyAIGatePolicy(result *ScanResult, evidenceAvailable bool, mode aiTriageMode) {
	applyAIGatePolicyWithIndependence(result, evidenceAvailable, mode, ports.AIIndependenceModelFamily)
}

func applyAIGatePolicyWithIndependence(result *ScanResult, evidenceAvailable bool, mode aiTriageMode, independence ports.AIIndependencePolicy) {
	if result == nil || len(result.AITriage) == 0 {
		return
	}
	independence = normalizeAIIndependencePolicy(independence)
	findings := make(map[string]finding.Finding, len(result.Findings))
	for _, item := range result.Findings {
		if key := strings.TrimSpace(item.DedupKey); key != "" {
			findings[key] = item
		}
	}
	for i := range result.AITriage {
		critique := &result.AITriage[i]
		critique.PolicyVersion = aiTriagePolicyVersion
		critique.IndependencePolicy = independence
		critique.Shadow = mode != aiTriageModeEnforce
		critique.WouldGateExempt = false
		critique.GateExempt = false
		critique.ReviewRequired = false

		if !critique.SuspectedFP {
			critique.PolicyReason = aiPolicyNotSuspected
			continue
		}
		if independence == "" {
			critique.PolicyReason = aiPolicyIndependenceRequired
			critique.ReviewRequired = true
			continue
		}
		if strings.TrimSpace(critique.VerifierModel) == "" {
			critique.PolicyReason = aiPolicyVerifierRequired
			critique.ReviewRequired = true
			continue
		}
		if !hasIndependentVerifierIdentity(*critique) {
			critique.PolicyReason = aiPolicyIndependenceRequired
			critique.ReviewRequired = true
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
		if !isFPTriageEligible(item) {
			critique.PolicyReason = aiPolicyFindingIneligible
			critique.ReviewRequired = true
			continue
		}
		if !evidenceAvailable {
			critique.PolicyReason = aiPolicyEvidenceRequired
			critique.ReviewRequired = true
			continue
		}
		if mode != aiTriageModeEnforce {
			critique.PolicyReason = aiPolicyShadowMode
			critique.WouldGateExempt = true
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
	return c.Verified && hasIndependentVerifierIdentity(c) &&
		c.Verdict == string(judgment.CritiqueRefuted) && c.Confidence >= verdict.EvidenceThreshold &&
		c.VerifierVerdict == string(judgment.CritiqueRefuted) &&
		c.VerifierConfidence >= verdict.EvidenceThreshold
}

func hasIndependentVerifierIdentity(c ports.AICritique) bool {
	proposerFamily := agent.CanonicalModelID(c.ProposerModel)
	verifierFamily := agent.CanonicalModelID(c.VerifierModel)
	proposerProvider := agent.CanonicalProviderID(c.ProposerProvider)
	verifierProvider := agent.CanonicalProviderID(c.VerifierProvider)
	return proposerFamily != "" && verifierFamily != "" &&
		c.ProposerModelFamily == proposerFamily && c.VerifierModelFamily == verifierFamily &&
		c.ProposerProvider == proposerProvider && c.VerifierProvider == verifierProvider &&
		agent.IndependentLLMs(proposerProvider, c.ProposerModel, verifierProvider, c.VerifierModel, string(c.IndependencePolicy))
}

func normalizeAIIndependencePolicy(policy ports.AIIndependencePolicy) ports.AIIndependencePolicy {
	switch ports.AIIndependencePolicy(strings.ToLower(strings.TrimSpace(string(policy)))) {
	case ports.AIIndependenceModelFamily:
		return ports.AIIndependenceModelFamily
	case ports.AIIndependenceProvider:
		return ports.AIIndependenceProvider
	default:
		return ""
	}
}

func humanReviewFloor(item finding.Finding) string {
	if item.Severity == shared.SeverityCritical || item.Severity == shared.SeverityHigh {
		return aiPolicySeverityFloor
	}
	if item.Kind == finding.KindSecret {
		return aiPolicySecretFloor
	}
	tokens := cweTokens(item.CWE)
	for _, token := range tokens {
		if _, protected := humanReviewCWEs[token]; protected {
			return aiPolicyDangerousCWEFloor
		}
		// A token that claims to be a CWE but is not well-formed CWE-<digits> after canonicalization
		// (e.g. "CWE-79:" from an embedded separator, "CWE-79A", or a bare "CWE-") must fail closed to
		// human review rather than be treated as a known-but-unprotected weakness — otherwise a
		// dangerous class could slip the floor on a malformed spelling.
		if isMalformedCWE(token) {
			return aiPolicyDangerousCWEFloor
		}
	}
	// Unknown weakness identity is not evidence that a source/config finding is low risk. Until a
	// producer supplies a CWE, keep it in human review rather than defaulting to exemptible.
	if len(tokens) == 0 && (item.Kind == finding.KindSAST || item.Kind == finding.KindMisconfig) {
		return aiPolicyDangerousCWEFloor
	}
	return ""
}

func cweTokens(value string) []string {
	// Split on every listed delimiter plus ALL unicode whitespace (incl. NBSP/\f/\v) and the
	// punctuation that commonly trails a CWE id in imported text ("CWE-79: XSS", "CWE-79."). The
	// separator set must be at least as wide as the canonicalizer's tolerance, or a dangerous CWE
	// spelled with an embedded separator would slip the human-review floor.
	tokens := strings.FieldsFunc(strings.ToUpper(value), func(r rune) bool {
		switch r {
		case ',', ';', '|', '/', ':', '.', '(', ')':
			return true
		}
		return unicode.IsSpace(r)
	})
	for i := range tokens {
		tokens[i] = canonicalCWEToken(tokens[i])
	}
	return tokens
}

// isMalformedCWE reports a token that claims to be a CWE ("CWE-" prefix) but is not well-formed
// CWE-<digits>. Such a token is treated as unparseable and fails closed to human review rather than
// being read as a known-but-unprotected weakness (#452 review follow-up, defense in depth).
func isMalformedCWE(token string) bool {
	const prefix = "CWE-"
	if !strings.HasPrefix(token, prefix) {
		return false
	}
	digits := strings.TrimPrefix(token, prefix)
	if digits == "" {
		return true
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return true
		}
	}
	return false
}

// canonicalCWEToken normalizes numeric CWE aliases without weakening exact-token matching. Synapse's
// rule catalog emits canonical IDs, but imported findings may spell CWE-79 as CWE-0079. Malformed and
// non-CWE tokens are left intact so normalization never guesses at an identifier.
func canonicalCWEToken(token string) string {
	const prefix = "CWE-"
	if !strings.HasPrefix(token, prefix) {
		return token
	}
	digits := strings.TrimPrefix(token, prefix)
	if digits == "" {
		return token
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return token
		}
	}
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		digits = "0"
	}
	return prefix + digits
}

func hasCredentialCWE(value string) bool {
	for _, token := range cweTokens(value) {
		switch token {
		case "CWE-259", "CWE-321", "CWE-522", "CWE-798":
			return true
		}
	}
	return false
}
