// Package export builds deterministic SARIF 2.1.0 + OpenVEX documents from stored
// findings. Templated from data – no LLM in the report path.
package export

import (
	"context"
	"errors"
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
	findings         ports.FindingRepository
	judgments        judgmentReader // optional: confirmed not_reachable judgments refine VEX justification
	aiGateExemptions ports.AIGateExemptionReader
	clock            ports.Clock
	version          string // tool version recorded in the output
}

// NewService wires the export use case.
func NewService(findings ports.FindingRepository, clock ports.Clock, version string) *Service {
	return &Service{findings: findings, clock: clock, version: version}
}

// SetJudgments wires the reachability-judgment reader so OpenVEX picks the not_affected justification
// by reachability tier. nil ⇒ the default justification.
func (s *Service) SetJudgments(j judgmentReader) { s.judgments = j }

// SetAIGateExemptions wires the latest-scan policy projection used to annotate retained SARIF results.
// nil keeps legacy exports unannotated.
func (s *Service) SetAIGateExemptions(reader ports.AIGateExemptionReader) {
	s.aiGateExemptions = reader
}

// SARIF returns the engagement's findings as a SARIF 2.1.0 log. It reads through the
// publishability gate so an unproven exploitation finding never ships
// in the exported log.
func (s *Service) SARIF(ctx context.Context, engagementID shared.ID) (*SARIFLog, error) {
	fs, err := s.findings.ListPublishableByEngagement(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	exemptions := map[string]ports.AIGateExemption{}
	if s.aiGateExemptions != nil {
		items, readErr := s.aiGateExemptions.AIGateExemptions(ctx, engagementID, fs)
		if readErr != nil && !errors.Is(readErr, shared.ErrNotFound) {
			return nil, readErr
		}
		for _, exemption := range items {
			if key := strings.TrimSpace(exemption.DedupKey); key != "" {
				exemptions[key] = exemption
			}
		}
	}
	// The store-backed export path has findings only (no SBOM), so no resolvers: SCA findings become
	// repo-level alerts rather than logical-only locations a code-scanning UI would reject, and carry no
	// inline fix version. AI gate metadata comes from the same persisted scan result that authorized the
	// exemption and is revalidated before it reaches this service.
	return buildSARIF(fs, s.version, SARIFOptions{AIGateExemption: func(item finding.Finding) (ports.AIGateExemption, bool) {
		exemption, ok := exemptions[strings.TrimSpace(item.DedupKey)]
		return exemption, ok
	}}), nil
}

// OpenVEX returns the engagement's vulnerability findings as an OpenVEX 0.2 document. It reads through the
// publishability gate – consistent with SARIF and the report path – so an unproven exploitation finding is
// never asserted in a VEX statement. supersedes, when non-empty, is the @id of a prior document this one
// replaces (the caller who re-exports knows it); the document's own @id is content-addressed, so an
// unchanged re-export is idempotent.
func (s *Service) OpenVEX(ctx context.Context, engagementID shared.ID, supersedes string) (*VEXDoc, error) {
	in, err := s.vexInputs(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	return buildOpenVEX(engagementID, in, s.clock.Now().UTC(), s.version, supersedes), nil
}

// CSAFVEX returns the same publishable findings as a CSAF 2.0 VEX document, the enterprise-standard
// companion to OpenVEX. It asserts exactly what OpenVEX asserts, reshaped into CSAF's product-tree +
// per-vulnerability product-status model.
func (s *Service) CSAFVEX(ctx context.Context, engagementID shared.ID) (*CSAFDoc, error) {
	in, err := s.vexInputs(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	return buildCSAFVEX(engagementID, in, s.clock.Now().UTC(), s.version), nil
}

// vexInputData is the shared input set both VEX emitters read.
type vexInputData struct {
	findings     []finding.Finding
	notReachable map[string]judgment.ReachabilityTier // findings soundly PROVED not_reachable (justification source)
	reachable    map[string]bool                      // findings Synapse independently PROVED reachable (#1064 reconciliation)
	vexJust      map[string]string                    // human-confirmed OpenVEX justifications
}

// vexInputs gathers the shared inputs both VEX emitters read: the publishable findings, the not-reachable
// tier map, the reachable-verdict set (for the #1064 reconciliation), and the human VEX justifications.
func (s *Service) vexInputs(ctx context.Context, engagementID shared.ID) (vexInputData, error) {
	fs, err := s.findings.ListPublishableByEngagement(ctx, engagementID)
	if err != nil {
		return vexInputData{}, err
	}
	// One winner snapshot feeds BOTH the not_reachable justification map and the reachable reconciliation set,
	// so the two verdicts can never disagree from separate reads of a store that changes mid-export.
	winner, err := s.reachabilityWinners(ctx, engagementID)
	if err != nil {
		return vexInputData{}, err
	}
	vexJust, err := s.vexJustifications(ctx, engagementID)
	if err != nil {
		return vexInputData{}, err
	}
	return vexInputData{findings: fs, notReachable: notReachableTiersFrom(winner), reachable: reachableFrom(winner), vexJust: vexJust}, nil
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

// reachabilityWinners resolves the WINNING reachability claim per finding id (tier then state, EPIC #1042,
// 0.4): a superseding claim hides a stale one, so both the not_reachable justification and the reachable
// reconciliation read a single, consistent verdict. Empty when judgments are disabled.
func (s *Service) reachabilityWinners(ctx context.Context, engagementID shared.ID) (map[string]judgment.ReachabilityClaim, error) {
	if s.judgments == nil {
		return nil, nil
	}
	js, err := s.judgments.ListByEngagement(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	winner := map[string]judgment.ReachabilityClaim{}
	for _, j := range js {
		if !j.Publishable() || j.Capability != judgment.CapReachability || j.SubjectKind != judgment.SubjectFinding {
			continue
		}
		rc, ok := j.Claim.(judgment.ReachabilityClaim)
		if !ok {
			continue
		}
		id := j.SubjectID.String()
		if cur, exists := winner[id]; !exists || rc.Supersedes(cur) {
			winner[id] = rc
		}
	}
	return winner, nil
}

// notReachableTiersFrom maps a finding id → the strongest tier of a PUBLISHABLE (confirmed + evidence-gated)
// not_reachable reachability judgment about it, derived from a winner snapshot. Only a claim that soundly
// suppresses (ProvedNotReachable, plus entry points on the call-graph tier) may stamp a not_affected
// justification; a partial, blind, or zero-entrypoint negative is not proof of absence (EPIC #1042, 0.6), and
// the finding then falls back to its status-derived VEX.
func notReachableTiersFrom(winner map[string]judgment.ReachabilityClaim) map[string]judgment.ReachabilityTier {
	out := map[string]judgment.ReachabilityTier{}
	for id, rc := range winner {
		if rc.SuppressesFinding() {
			out[id] = rc.Tier
		}
	}
	return out
}

// reachableFrom is the id set of findings whose WINNING reachability claim is `reachable`: Synapse
// independently proved the vulnerable code is reached. A vendor `not_affected` (a mere assertion) must never
// suppress such a finding on export, so collectVEXRecords refuses to emit not_affected for these ids and
// asserts the more-exploitable `affected` instead (EPIC #1042, #1064; the #1-bar reachability reconciliation).
func reachableFrom(winner map[string]judgment.ReachabilityClaim) map[string]bool {
	out := map[string]bool{}
	for id, rc := range winner {
		if rc.Reachable == judgment.Reachable {
			out[id] = true
		}
	}
	return out
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
