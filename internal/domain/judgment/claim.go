package judgment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vex"
)

// driverRE constrains a risk-narrative driver to a closed token grammar – a lowercase token,
// optionally with a numeric comparator (e.g. "kev", "reachable", "epss>0.5", "cvss>=9") – so a
// model can never smuggle a free-text sentence into the one []string field of a Claim (so
// no LLM prose reaches a deliverable).
var driverRE = regexp.MustCompile(`^[a-z][a-z0-9_]*((<=|>=|==|!=|<|>)[0-9]+(\.[0-9]+)?)?$`)

// maxClaimPathElems / maxClaimPathElemLen bound a reachability claim's call/dependency path so a
// hostile or runaway proposer (agent or HTTP) cannot seal an unbounded path into the evidence ledger
// + claim JSONB. Generous (a real path is far smaller); fail-closed at the one seam every propose
// path funnels through (judgment.New → canonicalizeClaim → Validate).
const (
	maxClaimPathElems   = 128
	maxClaimPathElemLen = 256
)

// Claim is the TYPED, capability-discriminated payload of a Judgment. It is NEVER free prose
// report templates render its fields; the model's rationale lives only in sealed
// evidence. Each capability has one concrete Claim type; the JSON envelope carries the discriminant
// so a stored claim decodes FAIL-CLOSED on an unknown capability or a body that doesn't match its
// discriminant – no free-text passthrough can reach a deliverable.
type Claim interface {
	Capability() Capability
	Validate() error
}

// ReachabilityState is the closed verdict vocabulary of a reachability judgment. The wire
// values are stable (persisted in the claim JSONB + consumed by OpenVEX justification mapping).
type ReachabilityState string

const (
	Reachable    ReachabilityState = "reachable"
	NotReachable ReachabilityState = "not_reachable"
	ReachUnknown ReachabilityState = "unknown"
)

// Valid reports whether s is a known reachability verdict (fail-closed: anything else is rejected).
func (s ReachabilityState) Valid() bool {
	switch s {
	case Reachable, NotReachable, ReachUnknown:
		return true
	}
	return false
}

// ReachabilityTier is the analysis tier that produced a verdict, ordered by strength of proof
// tier-0 = dependency-graph presence · tier-1 = direct import · tier-1.5 = bounded
// source call-path · tier-2 = call-graph proof. A higher-ranked tier OVERRIDES a lower one.
type ReachabilityTier string

const (
	Tier0   ReachabilityTier = "tier-0"
	Tier1   ReachabilityTier = "tier-1"
	Tier1_5 ReachabilityTier = "tier-1.5"
	Tier2   ReachabilityTier = "tier-2"
)

// Rank orders tiers by strength of proof (higher = stronger); 0 ⇒ unknown/invalid. Compare ranks to
// decide whether a new verdict supersedes a stored one (a Tier-2 proof overrides a Tier-1.5 claim).
func (t ReachabilityTier) Rank() int {
	switch t {
	case Tier0:
		return 1
	case Tier1:
		return 2
	case Tier1_5:
		return 3
	case Tier2:
		return 4
	}
	return 0
}

// Valid reports whether t is a known tier (fail-closed).
func (t ReachabilityTier) Valid() bool { return t.Rank() > 0 }

// ReachabilityClaim is the typed result of a reachability judgment: whether the vulnerable
// symbol is reachable, by which tier, and along what call path. Confidence is 0..100.
type ReachabilityClaim struct {
	Reachable  ReachabilityState `json:"reachable"`
	Tier       ReachabilityTier  `json:"tier"`
	Path       []string          `json:"path,omitempty"`
	Confidence int               `json:"confidence"`
}

// Capability identifies this claim's brain.
func (ReachabilityClaim) Capability() Capability { return CapReachability }

// Supersedes reports whether this claim should override prior – true only when this claim was produced by
// a STRICTLY STRONGER tier of proof (a deterministic Tier-2 call-graph result overrides an
// LLM Tier-1.5 claim, whether they agree or contradict). Same-or-lower tier does NOT supersede: a re-run
// at equal strength leaves the stored verdict standing (no churn), and a weaker re-analysis never
// downgrades a stronger proof. An unknown/invalid tier (Rank 0) can neither supersede nor be preserved
// against any valid tier.
func (c ReachabilityClaim) Supersedes(prior ReachabilityClaim) bool {
	return c.Tier.Rank() > prior.Tier.Rank()
}

// Validate enforces the closed verdict + tier vocabularies and a 0..100 confidence.
func (c ReachabilityClaim) Validate() error {
	if !c.Reachable.Valid() {
		return fmt.Errorf("%w: reachability must be reachable|not_reachable|unknown, got %q", shared.ErrValidation, c.Reachable)
	}
	if !c.Tier.Valid() {
		return fmt.Errorf("%w: reachability tier %q is unknown", shared.ErrValidation, c.Tier)
	}
	if c.Confidence < 0 || c.Confidence > 100 {
		return fmt.Errorf("%w: reachability confidence must be 0..100, got %d", shared.ErrValidation, c.Confidence)
	}
	if len(c.Path) > maxClaimPathElems {
		return fmt.Errorf("%w: reachability path has too many elements (%d > %d)", shared.ErrValidation, len(c.Path), maxClaimPathElems)
	}
	for _, p := range c.Path {
		if len(p) > maxClaimPathElemLen {
			return fmt.Errorf("%w: a reachability path element exceeds %d bytes", shared.ErrValidation, maxClaimPathElemLen)
		}
	}
	return nil
}

// SASTClaim is the typed result of a SAST judgment: the weakness (CWE), where, and the
// rule that fired. No free-text – a "hardcoded secret at L42" finding renders from these fields.
type SASTClaim struct {
	CWE      string `json:"cwe"`
	Location string `json:"location"` // path[:line]
	Rule     string `json:"rule"`
}

// Capability identifies this claim's brain.
func (SASTClaim) Capability() Capability { return CapSAST }

// Validate requires the structured fields that make a SAST hit renderable + dedupable.
func (c SASTClaim) Validate() error {
	if strings.TrimSpace(c.CWE) == "" {
		return fmt.Errorf("%w: sast claim requires a CWE", shared.ErrValidation)
	}
	if strings.TrimSpace(c.Location) == "" {
		return fmt.Errorf("%w: sast claim requires a location", shared.ErrValidation)
	}
	if strings.TrimSpace(c.Rule) == "" {
		return fmt.Errorf("%w: sast claim requires the rule id", shared.ErrValidation)
	}
	return nil
}

// RiskNarrativeClaim explains the Go-computed priority via STRUCTURED drivers (never prose):
// the renderer composes the sentence from these fields. It is NOT evidence-gated – there is
// nothing to "refute at 75"; a human accepts it.
type RiskNarrativeClaim struct {
	Drivers  []string `json:"drivers"`  // e.g. "kev", "epss>0.5", "cvss>=9", "reachable"
	Priority int      `json:"priority"` // 1..5 (mirrors the Go-computed priority)
}

// Capability identifies this claim's brain.
func (RiskNarrativeClaim) Capability() Capability { return CapRiskNarrative }

// Validate requires at least one driver and a 1..5 priority.
func (c RiskNarrativeClaim) Validate() error {
	if len(c.Drivers) == 0 {
		return fmt.Errorf("%w: risk narrative requires at least one driver", shared.ErrValidation)
	}
	for _, d := range c.Drivers {
		if len(d) > 64 || !driverRE.MatchString(d) {
			return fmt.Errorf("%w: risk-narrative driver %q must be a token like kev|reachable|epss>0.5|cvss>=9 (no free text)", shared.ErrValidation, d)
		}
	}
	if c.Priority < 1 || c.Priority > 5 {
		return fmt.Errorf("%w: risk narrative priority must be 1..5, got %d", shared.ErrValidation, c.Priority)
	}
	return nil
}

// CritiqueVerdict is the closed adversarial verdict on a finding: does it survive refutation?
type CritiqueVerdict string

const (
	CritiqueRefuted   CritiqueVerdict = "refuted"   // the finding does not hold – a suspected false positive
	CritiqueSound     CritiqueVerdict = "sound"     // the finding survives adversarial review
	CritiqueUncertain CritiqueVerdict = "uncertain" // inconclusive
)

// Valid reports whether v is a known critique verdict (fail-closed).
func (v CritiqueVerdict) Valid() bool {
	switch v {
	case CritiqueRefuted, CritiqueSound, CritiqueUncertain:
		return true
	}
	return false
}

// CritiqueClaim is the typed result of an adversarial critique: an attempt to REFUTE a finding,
// with a STRUCTURED driver (the refutation category – never free prose) and a confidence. A
// confirmed "refuted" critique flags the finding as suspected-FP for a human; it never auto-suppresses
// (fail-safe – a wrong critique cannot publish a falsehood).
type CritiqueClaim struct {
	Verdict    CritiqueVerdict `json:"verdict"`
	Driver     string          `json:"driver"` // closed token, e.g. "not_reachable", "version_mismatch", "false_match"
	Confidence int             `json:"confidence"`
}

// Capability identifies this claim's brain.
func (CritiqueClaim) Capability() Capability { return CapCritique }

// Validate enforces the closed verdict vocabulary, the driver token grammar, and a 0..100 confidence.
func (c CritiqueClaim) Validate() error {
	if !c.Verdict.Valid() {
		return fmt.Errorf("%w: critique verdict must be refuted|sound|uncertain, got %q", shared.ErrValidation, c.Verdict)
	}
	if len(c.Driver) > 64 || !driverRE.MatchString(c.Driver) {
		return fmt.Errorf("%w: critique driver %q must be a token like not_reachable|version_mismatch (no free text)", shared.ErrValidation, c.Driver)
	}
	if c.Confidence < 0 || c.Confidence > 100 {
		return fmt.Errorf("%w: critique confidence must be 0..100, got %d", shared.ErrValidation, c.Confidence)
	}
	return nil
}

// StrideCategory is one STRIDE threat class (closed vocabulary; the renderer composes the human sentence
// from this + the threatened subject element – never free prose).
type StrideCategory string

const (
	Spoofing             StrideCategory = "spoofing"
	Tampering            StrideCategory = "tampering"
	Repudiation          StrideCategory = "repudiation"
	InfoDisclosure       StrideCategory = "info_disclosure"
	DenialOfService      StrideCategory = "denial_of_service"
	ElevationOfPrivilege StrideCategory = "elevation_of_privilege"
)

// Valid reports whether s is a known STRIDE category.
func (s StrideCategory) Valid() bool {
	switch s {
	case Spoofing, Tampering, Repudiation, InfoDisclosure, DenialOfService, ElevationOfPrivilege:
		return true
	}
	return false
}

// ThreatClaim is a proposed STRIDE threat over the architecture model: the STRIDE
// category, plus the optional Asset.ID at risk (e.g. the classified data an info-disclosure exposes) – both
// STRUCTURED tokens, never free prose. The threatened model element (a component or data flow) is the
// Judgment's SUBJECT (SubjectComponent / SubjectDataFlow), not part of the claim. Gated: a human verifier
// ratifies it ("human-confirmed"); the agent only ever proposes it at score 0.
type ThreatClaim struct {
	Category StrideCategory `json:"category"`
	Asset    string         `json:"asset"` // optional Asset.ID at risk; "" when none
}

// Capability identifies this claim's brain.
func (ThreatClaim) Capability() Capability { return CapThreat }

// Validate enforces the closed STRIDE vocabulary and bounds the optional asset reference (a token-length id,
// never prose).
func (c ThreatClaim) Validate() error {
	if !c.Category.Valid() {
		return fmt.Errorf("%w: STRIDE category must be spoofing|tampering|repudiation|info_disclosure|denial_of_service|elevation_of_privilege, got %q", shared.ErrValidation, c.Category)
	}
	if len(c.Asset) > 128 {
		return fmt.Errorf("%w: threat asset id too long (max 128)", shared.ErrValidation)
	}
	return nil
}

// CorrelationClaim is a cross-check DISAGREEMENT: on a vulnerability, which detection
// sources reported it (Reporters) and which RAN but did not (Missing). It is the deterministic, descriptive
// record that a human acknowledges – NEVER auto-resolved (the disagreement is itself the signal). Both lists
// are source-name tokens (no prose); Missing is non-empty by construction (an agreed vuln is not a claim).
type CorrelationClaim struct {
	Reporters []string `json:"reporters"` // sources that reported the vuln (the minter supplies them sorted+distinct)
	Missing   []string `json:"missing"`   // run sources that did NOT report it (minter-sorted+distinct; Validate requires non-empty)
}

// Capability identifies this claim's brain.
func (CorrelationClaim) Capability() Capability { return CapCorrelation }

// Validate enforces a real disagreement: at least one reporter and at least one missing source, each a
// bounded source-name token (never prose). A claim with nothing missing is not a disagreement.
func (c CorrelationClaim) Validate() error {
	if len(c.Reporters) == 0 {
		return fmt.Errorf("%w: correlation claim needs at least one reporter", shared.ErrValidation)
	}
	if len(c.Missing) == 0 {
		return fmt.Errorf("%w: correlation claim needs at least one missing source (else it is not a disagreement)", shared.ErrValidation)
	}
	for _, s := range append(append([]string{}, c.Reporters...), c.Missing...) {
		if s == "" || len(s) > 64 {
			return fmt.Errorf("%w: correlation source name must be a non-empty token (<=64 chars), got %q", shared.ErrValidation, s)
		}
	}
	return nil
}

// VexJustificationClaim is a proposed OpenVEX justification for why a finding is NOT_AFFECTED – the
// AI's STRUCTURED choice from the CLOSED OpenVEX justification set, never free prose. The finding it
// applies to is the Judgment's SUBJECT (SubjectFinding), not part of the claim. Gated: a distinct human
// verifier ratifies it before the export trusts it (it asserts "not affected" in a published deliverable);
// the agent only proposes it at score 0. It COMPLEMENTS the deterministic reachability-tier justification
// (which wins where a confirmed not_reachable proof exists); this carries the OTHER not_affected
// reasons (component_not_present / cannot_be_controlled / inline_mitigations / code_not_present).
type VexJustificationClaim struct {
	Justification vex.OpenVexJustification `json:"justification"`
}

// Capability identifies this claim's brain.
func (VexJustificationClaim) Capability() Capability { return CapVexJustification }

// Validate enforces the closed OpenVEX justification vocabulary (fail-closed; never a free-text reason).
func (c VexJustificationClaim) Validate() error {
	if !c.Justification.Valid() {
		return fmt.Errorf("%w: OpenVEX justification must be one of component_not_present|vulnerable_code_not_present|vulnerable_code_not_in_execute_path|vulnerable_code_cannot_be_controlled_by_adversary|inline_mitigations_already_exist, got %q", shared.ErrValidation, c.Justification)
	}
	return nil
}

// envelope is the discriminated wire form: {capability, claim}. The discriminant is checked on
// decode so a tampered/unknown body fails closed.
type envelope struct {
	Capability Capability      `json:"capability"`
	Claim      json.RawMessage `json:"claim"`
}

// MarshalClaim encodes a Claim as a discriminated envelope. It requires a non-nil claim with a
// known capability; field-level validity is the caller's job (New / UnmarshalClaim enforce it).
func MarshalClaim(c Claim) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil claim", shared.ErrValidation)
	}
	if !c.Capability().Valid() {
		return nil, fmt.Errorf("%w: unknown claim capability %q", shared.ErrValidation, c.Capability())
	}
	if err := c.Validate(); err != nil { // fail-closed on the write path too (symmetry with decode)
		return nil, err
	}
	body, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshal claim body: %w", err)
	}
	return json.Marshal(envelope{Capability: c.Capability(), Claim: body})
}

// UnmarshalClaim decodes a discriminated envelope into the concrete Claim for its capability,
// FAIL-CLOSED: an unknown/unregistered capability, a body carrying unknown fields, a body
// whose reported capability disagrees with the envelope, or a body that fails Validate is all
// rejected – never a free-text passthrough.
func UnmarshalClaim(data []byte) (Claim, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("%w: malformed claim envelope: %v", shared.ErrValidation, err)
	}
	if !env.Capability.Valid() {
		return nil, fmt.Errorf("%w: unknown claim capability %q", shared.ErrValidation, env.Capability)
	}
	var c Claim
	switch env.Capability {
	case CapReachability:
		var rc ReachabilityClaim
		if err := strictDecode(env.Claim, &rc); err != nil {
			return nil, err
		}
		c = rc
	case CapSAST:
		var sc SASTClaim
		if err := strictDecode(env.Claim, &sc); err != nil {
			return nil, err
		}
		c = sc
	case CapCritique:
		var cc CritiqueClaim
		if err := strictDecode(env.Claim, &cc); err != nil {
			return nil, err
		}
		c = cc
	case CapRiskNarrative:
		var nc RiskNarrativeClaim
		if err := strictDecode(env.Claim, &nc); err != nil {
			return nil, err
		}
		c = nc
	case CapThreat:
		var tc ThreatClaim
		if err := strictDecode(env.Claim, &tc); err != nil {
			return nil, err
		}
		c = tc
	case CapCorrelation:
		var cc CorrelationClaim
		if err := strictDecode(env.Claim, &cc); err != nil {
			return nil, err
		}
		c = cc
	case CapVexJustification:
		var vc VexJustificationClaim
		if err := strictDecode(env.Claim, &vc); err != nil {
			return nil, err
		}
		c = vc
	default:
		// In the Valid() vocabulary but no decoder yet – registered alongside the capability.
		return nil, fmt.Errorf("%w: no claim decoder for capability %q", shared.ErrValidation, env.Capability)
	}
	if c.Capability() != env.Capability {
		return nil, fmt.Errorf("%w: claim body capability %q != envelope %q", shared.ErrValidation, c.Capability(), env.Capability)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// canonicalizeClaim round-trips a claim through the fail-closed envelope so the result is a fresh,
// validated, alias-free copy identical to what persistence will seal – closing the slice-aliasing
// footgun (a caller cannot mutate a constructed judgment's claim post-validation).
func canonicalizeClaim(c Claim) (Claim, error) {
	data, err := MarshalClaim(c)
	if err != nil {
		return nil, err
	}
	return UnmarshalClaim(data)
}

// strictDecode rejects unknown fields so nothing (e.g. a smuggled free-text "notes") rides in
// alongside the typed claim.
func strictDecode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: claim body: %v", shared.ErrValidation, err)
	}
	return nil
}
