// Package export builds deterministic SARIF 2.1.0 + OpenVEX documents from stored
// findings. Templated from data – no LLM in the report path.
package export

import (
	"context"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// judgmentReader is the narrow read slice the OpenVEX justification-by-tier mapping needs:
// list the engagement's judgments. Optional – nil ⇒ the default justification. ports.JudgmentStore
// (memory/postgres) satisfies it. Reads typed data only – no LLM in the report path.
type judgmentReader interface {
	ListByEngagement(ctx context.Context, engagementID shared.ID) ([]judgment.Judgment, error)
}

// Service renders an engagement's findings as SARIF or OpenVEX.
type Service struct {
	findings  ports.FindingRepository
	judgments judgmentReader // optional: confirmed not_reachable judgments refine VEX justification
	clock     ports.Clock
	version   string // tool version recorded in the output
}

// NewService wires the export use case.
func NewService(findings ports.FindingRepository, clock ports.Clock, version string) *Service {
	return &Service{findings: findings, clock: clock, version: version}
}

// SetJudgments wires the reachability-judgment reader so OpenVEX picks the not_affected justification
// by reachability tier. nil ⇒ the default justification.
func (s *Service) SetJudgments(j judgmentReader) { s.judgments = j }

// SARIF returns the engagement's findings as a SARIF 2.1.0 log. It reads through the
// publishability gate so an unproven exploitation finding never ships
// in the exported log.
func (s *Service) SARIF(ctx context.Context, engagementID shared.ID) (*SARIFLog, error) {
	fs, err := s.findings.ListPublishableByEngagement(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	// The store-backed export path has findings only (no SBOM), so no resolvers: SCA findings become
	// repo-level alerts rather than logical-only locations a code-scanning UI would reject, and carry no
	// inline fix version.
	return buildSARIF(fs, s.version, SARIFOptions{}), nil
}

// OpenVEX returns the engagement's vulnerability findings as an OpenVEX document. It
// reads through the publishability gate – consistent with SARIF and the
// report path – so an unproven exploitation finding is never asserted in a VEX statement.
func (s *Service) OpenVEX(ctx context.Context, engagementID shared.ID) (*VEXDoc, error) {
	fs, err := s.findings.ListPublishableByEngagement(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	notReachable, err := s.notReachableTiers(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	vexJust, err := s.vexJustifications(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	return buildOpenVEX(engagementID, fs, notReachable, vexJust, s.clock.Now().UTC(), s.version), nil
}

// vexJustifications maps a finding id → the OpenVEX justification of a PUBLISHABLE (confirmed + verified
// ≥ bar) CapVexJustification judgment about it. It reuses the same judgment reader as the reachability path; the
// first such confirmed claim per finding wins (deterministic by the repo's created_at/id order). Empty
// when judgments are disabled. The export applies it only to a not_affected finding, and only when no
// reachability-tier justification (a deterministic proof) is present – see buildOpenVEX.
func (s *Service) vexJustifications(ctx context.Context, engagementID shared.ID) (map[string]string, error) {
	if s.judgments == nil {
		return nil, nil
	}
	js, err := s.judgments.ListByEngagement(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, j := range js {
		if !j.Publishable() || j.Capability != judgment.CapVexJustification {
			continue
		}
		vc, ok := j.Claim.(judgment.VexJustificationClaim)
		if !ok {
			continue
		}
		if id := j.SubjectID.String(); out[id] == "" { // first confirmed claim per finding wins (deterministic)
			out[id] = string(vc.Justification)
		}
	}
	return out, nil
}

// notReachableTiers maps a finding id → the strongest tier of a PUBLISHABLE (confirmed + evidence-
// gated) not_reachable reachability judgment about it. Empty when judgments are disabled.
func (s *Service) notReachableTiers(ctx context.Context, engagementID shared.ID) (map[string]judgment.ReachabilityTier, error) {
	if s.judgments == nil {
		return nil, nil
	}
	js, err := s.judgments.ListByEngagement(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	out := map[string]judgment.ReachabilityTier{}
	for _, j := range js {
		if !j.Publishable() || j.Capability != judgment.CapReachability {
			continue
		}
		rc, ok := j.Claim.(judgment.ReachabilityClaim)
		if !ok || rc.Reachable != judgment.NotReachable {
			continue
		}
		id := j.SubjectID.String()
		if cur, exists := out[id]; !exists || rc.Tier.Rank() > cur.Rank() {
			out[id] = rc.Tier
		}
	}
	return out, nil
}

// parsedKey is the structured form of a finding dedup key
// ("vuln:<advisory>:<component>:<version>" or "license:<id>").
type parsedKey struct {
	kind      string // "vuln" | "license"
	advisory  string // CVE/GHSA id, or the license id
	component string
	version   string
}

// parseDedup splits a dedup key. Advisory ids and versions never contain ':',
// so the component (which may) is the middle join.
func parseDedup(key string) parsedKey {
	if advisory, component, version, ok := vulnerability.ParseDedupKey(key); ok {
		return parsedKey{kind: "vuln", advisory: advisory, component: component, version: version}
	}
	if rest, ok := strings.CutPrefix(key, "license:"); ok {
		return parsedKey{kind: "license", advisory: rest}
	}
	return parsedKey{advisory: key}
}

// sarifLevel maps a severity to a SARIF result level (error/warning/note).
func sarifLevel(sev shared.Severity) string {
	switch sev {
	case shared.SeverityCritical, shared.SeverityHigh:
		return "error"
	case shared.SeverityLow, shared.SeverityInfo:
		return "note"
	default: // medium / unknown
		return "warning"
	}
}

// vexStatus maps a finding triage status to an OpenVEX status + justification.
func vexStatus(st finding.Status) (status, justification string) {
	switch st {
	case finding.StatusFalsePos:
		return "not_affected", "vulnerable_code_not_present"
	case finding.StatusRemediated:
		return "fixed", ""
	default: // open / triage / confirmed
		return "affected", ""
	}
}
