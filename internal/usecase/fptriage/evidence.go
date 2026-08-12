package fptriage

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxEvidenceTokens    = 24
	maxEvidenceCitations = 8
)

var (
	evidenceIDRE   = regexp.MustCompile(`^ev:[a-z][a-z0-9_]{0,47}$`)
	evidenceKindRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
)

func evidenceValidationError(format string, args ...any) error {
	return fmt.Errorf("%w: critique evidence: %s", shared.ErrValidation, fmt.Sprintf(format, args...))
}

func normalizeEvidence(tokens []ports.AITriageEvidenceToken, required bool) ([]ports.AITriageEvidenceToken, error) {
	if len(tokens) == 0 {
		if required {
			return nil, evidenceValidationError("deterministic evidence tokens are required")
		}
		return nil, nil
	}
	if len(tokens) > maxEvidenceTokens {
		return nil, evidenceValidationError("%d tokens exceeds limit %d", len(tokens), maxEvidenceTokens)
	}
	out := make([]ports.AITriageEvidenceToken, 0, len(tokens))
	seen := map[string]struct{}{}
	for _, token := range tokens {
		token.ID = strings.TrimSpace(token.ID)
		token.Kind = ports.AITriageEvidenceKind(strings.TrimSpace(string(token.Kind)))
		token.Value = strings.TrimSpace(token.Value)
		if !evidenceIDRE.MatchString(token.ID) || !evidenceKindRE.MatchString(string(token.Kind)) || token.Value == "" {
			return nil, evidenceValidationError("invalid token %q/%q", token.ID, token.Kind)
		}
		if len([]rune(token.Value)) > ports.MaxAITriageEvidenceValueRunes {
			return nil, evidenceValidationError("token %q value exceeds %d runes", token.ID, ports.MaxAITriageEvidenceValueRunes)
		}
		if _, ok := seen[token.ID]; ok {
			return nil, evidenceValidationError("duplicate token id %q", token.ID)
		}
		seen[token.ID] = struct{}{}
		out = append(out, token)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func evidenceEqual(a, b []ports.AITriageEvidenceToken) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func validateEvidenceCitations(citations []string, evidence []ports.AITriageEvidenceToken) ([]string, error) {
	if len(citations) < 1 || len(citations) > maxEvidenceCitations {
		return nil, evidenceValidationError("citations must contain 1..%d token ids", maxEvidenceCitations)
	}
	allowed := make(map[string]ports.AITriageEvidenceToken, len(evidence))
	for _, token := range evidence {
		allowed[token.ID] = token
	}
	out := make([]string, 0, len(citations))
	seen := map[string]struct{}{}
	for _, id := range citations {
		id = strings.TrimSpace(id)
		if _, ok := allowed[id]; !ok {
			return nil, evidenceValidationError("citation %q is not in the current deterministic context", id)
		}
		if _, ok := seen[id]; ok {
			return nil, evidenceValidationError("duplicate citation %q", id)
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

func citedTokens(citations []string, evidence []ports.AITriageEvidenceToken) []ports.AITriageEvidenceToken {
	wanted := make(map[string]struct{}, len(citations))
	for _, id := range citations {
		wanted[id] = struct{}{}
	}
	out := make([]ports.AITriageEvidenceToken, 0, len(citations))
	for _, token := range evidence {
		if _, ok := wanted[token.ID]; ok {
			out = append(out, token)
		}
	}
	return out
}

func citationSupportsClaim(claim judgment.CritiqueClaim, citations []string, evidence []ports.AITriageEvidenceToken) error {
	if claim.Verdict != judgment.CritiqueRefuted {
		return nil
	}
	cited := citedTokens(citations, evidence)
	contains := func(kind ports.AITriageEvidenceKind, terms ...string) bool {
		for _, token := range cited {
			if token.Kind != kind {
				continue
			}
			v := strings.ToLower(token.Value)
			if len(terms) == 0 {
				return true
			}
			for _, term := range terms {
				if strings.Contains(v, term) {
					return true
				}
			}
		}
		return false
	}
	supported := false
	switch claim.Driver {
	case "not_reachable":
		supported = contains(ports.AITriageEvidenceKindReachability, "not_reach", "unreach", "unreferenced", "dead")
	case "input_sanitized":
		supported = contains(ports.AITriageEvidenceKindSanitizer)
	case "framework_autoescape":
		supported = contains(ports.AITriageEvidenceKindFramework, "escape", "auto") || contains(ports.AITriageEvidenceKindCounterEvidence, "escape", "auto") || contains(ports.AITriageEvidenceKindControlEvidence, "escape", "auto")
	case "constant_or_literal":
		supported = contains(ports.AITriageEvidenceKindSource, "literal", "constant") || contains(ports.AITriageEvidenceKindSourceEvidence, "literal", "constant") || contains(ports.AITriageEvidenceKindCounterEvidence, "literal", "constant")
	case "not_attacker_controlled":
		supported = contains(ports.AITriageEvidenceKindSource, "literal", "constant", "trusted", "internal", "server-side") ||
			contains(ports.AITriageEvidenceKindSourceEvidence, "literal", "constant", "trusted", "internal", "server-side") ||
			contains(ports.AITriageEvidenceKindCounterEvidence, "not attacker", "trusted", "internal", "server-side") ||
			contains(ports.AITriageEvidenceKindControlEvidence, "trusted", "internal", "server-side")
	case "test_or_example_code":
		supported = contains(ports.AITriageEvidenceKindSourceLocation, "/test", "_test.", "/example", "/fixture")
	case "false_pattern_match":
		supported = contains(ports.AITriageEvidenceKindCounterEvidence) || contains(ports.AITriageEvidenceKindValidation, "false-positive-static", "not-reportable", "not_reportable")
	case "mitigated_elsewhere":
		supported = contains(ports.AITriageEvidenceKindCounterEvidence) || contains(ports.AITriageEvidenceKindControlEvidence) || contains(ports.AITriageEvidenceKindSanitizer)
	case "intended_behavior":
		supported = contains(ports.AITriageEvidenceKindCounterEvidence, "intended", "expected", "configured", "explicit") || contains(ports.AITriageEvidenceKindControlEvidence, "intended", "expected", "configured", "explicit")
	case "confirmed_exploitable", "attacker_controlled", "insufficient_context":
		supported = false
	default:
		supported = false
	}

	if !supported {
		return evidenceValidationError("driver %q is not supported by the cited deterministic tokens", claim.Driver)
	}
	return nil
}

// ValidateEvidenceReceiptAgainst revalidates the receipt against a fresh server-derived deterministic
// dictionary. A critique's ContextEvidence is audit metadata only: it must exactly match the normalized
// server dictionary, while every citation and semantic support check is resolved against the server copy.
func ValidateEvidenceReceiptAgainst(c ports.AICritique, item finding.Finding, serverEvidence []ports.AITriageEvidenceToken) error {
	if strings.TrimSpace(c.PromptVersion) != evidencePromptVersion {
		return evidenceValidationError("gate authorization requires prompt %s", evidencePromptVersion)
	}
	server, err := normalizeEvidence(serverEvidence, true)
	if err != nil {
		return err
	}
	carried, err := normalizeEvidence(c.ContextEvidence, true)
	if err != nil {
		return err
	}
	if !evidenceEqual(carried, server) {
		return evidenceValidationError("carried context does not match the current server-derived evidence dictionary")
	}
	identity := finding.Identity(item)
	if identity == "" {
		return evidenceValidationError("current finding identity is empty")
	}
	identityBound := false
	for _, token := range server {
		if token.ID != "ev:finding_identity" {
			continue
		}
		if token.Kind != ports.AITriageEvidenceKindFindingIdentity || token.Value != identity {
			return evidenceValidationError("finding identity token does not match current finding")
		}
		identityBound = true
	}
	if !identityBound {
		return evidenceValidationError("finding identity token is required")
	}

	claim := judgment.CritiqueClaim{
		Verdict:    judgment.CritiqueVerdict(strings.ToLower(strings.TrimSpace(c.Verdict))),
		Driver:     strings.TrimSpace(c.Driver),
		Confidence: c.Confidence,
	}
	if err := claim.Validate(); err != nil {
		return evidenceValidationError("proposer claim: %v", err)
	}
	proposerCitations, err := validateEvidenceCitations(c.EvidenceTokens, server)
	if err != nil {
		return err
	}
	if err := citationSupportsClaim(claim, proposerCitations, server); err != nil {
		return err
	}

	if strings.TrimSpace(c.VerifierModel) == "" {
		if len(c.VerifierEvidenceTokens) != 0 {
			return evidenceValidationError("verifier citations require a verifier model")
		}
		return nil
	}
	verifier := judgment.CritiqueClaim{
		Verdict:    judgment.CritiqueVerdict(strings.ToLower(strings.TrimSpace(c.VerifierVerdict))),
		Driver:     strings.TrimSpace(c.VerifierDriver),
		Confidence: c.VerifierConfidence,
	}
	if err := verifier.Validate(); err != nil {
		return evidenceValidationError("verifier claim: %v", err)
	}
	verifierCitations, err := validateEvidenceCitations(c.VerifierEvidenceTokens, server)
	if err != nil {
		return err
	}
	if err := citationSupportsClaim(verifier, verifierCitations, server); err != nil {
		return err
	}
	return nil
}

// ValidateEvidenceReceipt is retained for non-authorizing/internal callers that already possess the
// coordinator-produced dictionary. Gate policy must use ValidateEvidenceReceiptAgainst with a separately
// server-derived dictionary.
func ValidateEvidenceReceipt(c ports.AICritique, item finding.Finding) error {
	return ValidateEvidenceReceiptAgainst(c, item, c.ContextEvidence)
}

func parseCritiqueWithEvidence(content string, evidence []ports.AITriageEvidenceToken) (judgment.CritiqueClaim, []string, error) {
	obj := extractJSONObject(content)
	if obj == "" {
		return judgment.CritiqueClaim{}, nil, fmt.Errorf("critique: no JSON object in model reply")
	}
	var raw struct {
		Verdict        string   `json:"verdict"`
		Driver         string   `json:"driver"`
		Confidence     *int     `json:"confidence"`
		EvidenceTokens []string `json:"evidence_tokens"`
	}
	if err := json.Unmarshal([]byte(obj), &raw); err != nil {
		return judgment.CritiqueClaim{}, nil, fmt.Errorf("critique: decode reply: %w", err)
	}
	if raw.Confidence == nil {
		return judgment.CritiqueClaim{}, nil, fmt.Errorf("critique: confidence is required")
	}
	claim := judgment.CritiqueClaim{
		Verdict:    judgment.CritiqueVerdict(strings.ToLower(strings.TrimSpace(raw.Verdict))),
		Driver:     normalizeDriver(raw.Driver, raw.Verdict),
		Confidence: *raw.Confidence,
	}
	if err := claim.Validate(); err != nil {
		return judgment.CritiqueClaim{}, nil, fmt.Errorf("critique: %w", err)
	}
	citations, err := validateEvidenceCitations(raw.EvidenceTokens, evidence)
	if err != nil {
		return judgment.CritiqueClaim{}, nil, err
	}
	if err := citationSupportsClaim(claim, citations, evidence); err != nil {
		return judgment.CritiqueClaim{}, nil, err
	}
	return claim, citations, nil
}
