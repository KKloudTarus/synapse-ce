// Package judgment is the AI "analysis brain" primitive: a propose→verify→confirm CLAIM
// about a subject (a finding, component, vulnerability, or the engagement), evidence-gated and
// hash-chainable, that generalizes the exploitation gate. It is pure (stdlib + shared
// + the shared verdict value type – NOT finding, R1): a Judgment never imports the Finding
// aggregate. The proposing agent can only PROPOSE (score 0); a DISTINCT verifier's sealed verdict
// (gated capabilities) or a human's acceptance (ungated) is the only thing that confirms it
// .
package judgment

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"
)

// Capability is the CLOSED vocabulary of analysis brains – never an LLM-supplied string. Add one
// (a const + a Gated case + a concrete Claim type + UnmarshalClaim registration) with its epic.
type Capability string

const (
	CapReachability     Capability = "reachability"      // gated
	CapSAST             Capability = "sast"              // gated
	CapCritique         Capability = "critique"          // gated (adversarial refutation of a finding)
	CapRiskNarrative    Capability = "risk_narrative"    // NOT gated (explains, doesn't prove)
	CapThreat           Capability = "threat"            // gated (STRIDE threat over the model, human-ratified)
	CapCorrelation      Capability = "correlation"       // NOT gated (a cross-check disagreement; human-acknowledged, never auto-resolved)
	CapVexJustification Capability = "vex_justification" // gated (AI-proposed OpenVEX not_affected justification, human-ratified)
)

// Valid reports whether c is a known capability.
func (c Capability) Valid() bool {
	switch c {
	case CapReachability, CapSAST, CapCritique, CapRiskNarrative, CapThreat, CapCorrelation, CapVexJustification:
		return true
	}
	return false
}

// Gated reports whether a verdict gates this capability's publishability (R2). Adversarially-
// refutable capabilities (reachability/sast/critique/threat/vex_justification) are gated: publishable only with a sealed
// verdict >= EvidenceThreshold. Descriptive ones (risk_narrative; correlation – a deterministic
// cross-check disagreement) have no "refuted at 75" semantics; they are human-accepted, not score-gated.
func (c Capability) Gated() bool {
	switch c {
	case CapReachability, CapSAST, CapCritique, CapThreat, CapVexJustification:
		return true
	}
	return false
}

// State is the judgment lifecycle.
type State string

const (
	StateProposed  State = "proposed"  // EvidenceScore 0; inert
	StateConfirmed State = "confirmed" // a sealed verdict (gated) or human acceptance (ungated) cleared it
	StateRefuted   State = "refuted"   // a sealed verdict left it below the bar
)

// Valid reports whether s is a known state.
func (s State) Valid() bool {
	switch s {
	case StateProposed, StateConfirmed, StateRefuted:
		return true
	}
	return false
}

// SubjectKind is what a judgment is ABOUT (closed vocabulary).
type SubjectKind string

const (
	SubjectFinding       SubjectKind = "finding"
	SubjectComponent     SubjectKind = "component"
	SubjectVulnerability SubjectKind = "vulnerability"
	SubjectEngagement    SubjectKind = "engagement"
	SubjectDataFlow      SubjectKind = "data_flow" // a threat-model data flow (a boundary crossing)
)

// Valid reports whether k is a known subject kind.
func (k SubjectKind) Valid() bool {
	switch k {
	case SubjectFinding, SubjectComponent, SubjectVulnerability, SubjectEngagement, SubjectDataFlow:
		return true
	}
	return false
}

// Judgment is one propose→verify→confirm unit of AI analysis. It is a CLAIM until a DISTINCT
// verifier seals a verdict (gated capabilities) or a human accepts it (ungated). Tenant-scoped via
// EngagementID (R9). ProposedBy is attribution only – it confers no power to move the score.
type Judgment struct {
	ID            shared.ID
	EngagementID  shared.ID
	Capability    Capability
	SubjectKind   SubjectKind
	SubjectID     shared.ID
	Claim         Claim
	State         State
	EvidenceScore int
	ProposedBy    string
	Version       int
	Audit         shared.Audit
}

// New builds a PROPOSED judgment at EvidenceScore 0 (the proposer can never set a score). It
// validates the closed vocabularies + the typed claim; proposer is recorded for attribution only.
func New(id, engagementID shared.ID, capability Capability, subjectKind SubjectKind, subjectID shared.ID, claim Claim, proposer string, now time.Time) (Judgment, error) {
	if id == "" || engagementID == "" {
		return Judgment{}, fmt.Errorf("%w: judgment needs an id + engagement", shared.ErrValidation)
	}
	if !capability.Valid() {
		return Judgment{}, fmt.Errorf("%w: unknown judgment capability %q", shared.ErrValidation, capability)
	}
	if !subjectKind.Valid() {
		return Judgment{}, fmt.Errorf("%w: unknown subject kind %q", shared.ErrValidation, subjectKind)
	}
	if subjectID == "" {
		return Judgment{}, fmt.Errorf("%w: judgment needs a subject id", shared.ErrValidation)
	}
	if claim == nil {
		return Judgment{}, fmt.Errorf("%w: judgment needs a typed claim", shared.ErrValidation)
	}
	if claim.Capability() != capability {
		return Judgment{}, fmt.Errorf("%w: claim capability %q != judgment %q", shared.ErrValidation, claim.Capability(), capability)
	}
	// Canonicalize through the fail-closed (de)serialization (R8): the stored Claim is a fresh,
	// validated, alias-free copy identical to what persistence seals – a caller can't mutate it
	// post-validation. This also runs the claim's field validation.
	canonical, err := canonicalizeClaim(claim)
	if err != nil {
		return Judgment{}, err
	}
	return Judgment{
		ID: id, EngagementID: engagementID, Capability: capability,
		SubjectKind: subjectKind, SubjectID: subjectID, Claim: canonical,
		State: StateProposed, EvidenceScore: 0, ProposedBy: strings.TrimSpace(proposer),
		Version: 1, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}, nil
}

// ApplyVerdict moves a GATED judgment's score via a DISTINCT verifier's verdict – the only path
// that scores a gated capability. It refuses an ungated capability (use Accept),
// an invalid verdict, and a self-confirming verifier. >= EvidenceThreshold ⇒ confirmed, else
// refuted. Pure state change; the use case MUST have sealed the verdict as evidence first (R10).
func (j Judgment) ApplyVerdict(v verdict.Verdict, now time.Time) (Judgment, error) {
	if j.State != StateProposed {
		return Judgment{}, fmt.Errorf("%w: only a proposed judgment takes a verdict, not %s", shared.ErrValidation, j.State)
	}
	if !j.Capability.Gated() {
		return Judgment{}, fmt.Errorf("%w: capability %s is not evidence-gated; use Accept (human acceptance)", shared.ErrValidation, j.Capability)
	}
	if err := v.Validate(); err != nil {
		return Judgment{}, err
	}
	if verdict.SelfConfirm(v.Verifier, j.ProposedBy) {
		return Judgment{}, fmt.Errorf("%w: the verifier (%s) may not be the proposer", shared.ErrValidation, v.Verifier)
	}
	j.EvidenceScore = v.Score
	if verdict.MeetsBar(v.Score) {
		j.State = StateConfirmed
	} else {
		j.State = StateRefuted
	}
	j.Audit.UpdatedAt = now
	return j, nil
}

// Accept confirms an UNGATED judgment by human acceptance (there is nothing to refute at 75). It
// refuses a gated capability (use ApplyVerdict) and a self-accepting proposer.
func (j Judgment) Accept(by string, now time.Time) (Judgment, error) {
	if j.State != StateProposed {
		return Judgment{}, fmt.Errorf("%w: only a proposed judgment can be accepted, not %s", shared.ErrValidation, j.State)
	}
	if j.Capability.Gated() {
		return Judgment{}, fmt.Errorf("%w: capability %s is evidence-gated; it needs a verdict, not acceptance", shared.ErrValidation, j.Capability)
	}
	if strings.TrimSpace(by) == "" {
		return Judgment{}, fmt.Errorf("%w: acceptance requires an actor", shared.ErrValidation)
	}
	if verdict.SelfConfirm(by, j.ProposedBy) {
		return Judgment{}, fmt.Errorf("%w: the acceptor (%s) may not be the proposer", shared.ErrValidation, by)
	}
	j.State = StateConfirmed
	j.Audit.UpdatedAt = now
	return j, nil
}

// MeetsEvidenceBar reports whether the judgment cleared the shared threshold.
func (j Judgment) MeetsEvidenceBar() bool { return verdict.MeetsBar(j.EvidenceScore) }

// Publishable reports whether a judgment may surface in a customer-facing deliverable (R2): it
// must be confirmed, and for a GATED capability also clear the evidence bar. Ungated capabilities
// are publishable once confirmed (human-accepted). Mirrors finding.Publishable.
func (j Judgment) Publishable() bool {
	if j.State != StateConfirmed {
		return false
	}
	if j.Capability.Gated() {
		return j.MeetsEvidenceBar()
	}
	return true
}
