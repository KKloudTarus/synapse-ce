package judgment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vex"
)

// driverRE constrains a risk-narrative driver to a closed token grammar – a lowercase token,
// optionally with a numeric comparator (e.g. "kev", "reachable", "epss>0.5", "cvss>=9") – so a
// model can never smuggle a free-text sentence into the one []string field of a Claim (so
// no LLM prose reaches a deliverable).
var driverRE = regexp.MustCompile(`^[a-z][a-z0-9_]*((<=|>=|==|!=|<|>)[0-9]+(\.[0-9]+)?)?$`)
var fingerprintRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$|^[a-z][a-z0-9_]{0,15}_[a-f0-9]{64}$`)
var promotionRuleKeyRE = regexp.MustCompile(`^promotion\.[a-z][a-z0-9_.]*$`)
var promotionFingerprintRE = regexp.MustCompile(`^[a-f0-9]{64}$`)

// These fields can be proposed by an LLM before a verifier reviews the claim. Keep their wire
// representation bounded and token-shaped at the domain seam so model prose/control characters
// cannot be persisted and later rendered as a deterministic SAST finding.
var (
	cweRE      = regexp.MustCompile(`^CWE-[0-9]{1,9}$`)
	sastRuleRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)
)

// Stable promotion rule identifiers. These constants are the canonical source of truth; the
// promotion catalog in internal/domain/promotion reuses them to avoid duplicated string
// vocabularies across domain packages.
const (
	RuleRuntimeReachableExposed  = "promotion.escalate.runtime_reachable_exposed"
	RuleDeterministicUnreachable = "promotion.deescalate.deterministic_unreachable"
	RuleUncertainCorroboration   = "promotion.review.uncertain_corroboration"
	RuleCorroboratingSignalLoss  = "promotion.deescalate.corroborating_signal_loss"
)

// ExpectedEffect returns the PromotionChange that the given rule is allowed to produce.
// Unknown rules are rejected so claims cannot introduce new promotion behavior.
func ExpectedEffect(rule string) (PromotionChange, bool) {
	switch rule {
	case RuleRuntimeReachableExposed:
		return PromotionEscalate, true
	case RuleDeterministicUnreachable, RuleCorroboratingSignalLoss:
		return PromotionDeescalate, true
	case RuleUncertainCorroboration:
		return PromotionFlagForReview, true
	default:
		return "", false
	}
}

// Reserved deterministic reachability proof identities. These are domain provenance
// vocabulary; use cases may mint claims with them but cannot define new proof engines.
const (
	ProofActorCallgraphScan    = "system:callgraph-scan"
	ProofActorCallgraphEngine  = "system:callgraph-engine"
	ProofActorJSSymbolScan     = "system:jssymbol-scan"
	ProofActorJSSymbolEngine   = "system:jssymbol-engine"
	ProofActorPySemanticScan   = "system:pysemantic-scan"
	ProofActorPySemanticEngine = "system:pysemantic-engine"
	ProofActorJSImportScan     = "system:jsimport-scan"
	ProofActorJSImportEngine   = "system:jsimport-engine"
	ProofActorPyImportScan     = "system:pyimport-scan"
	ProofActorPyImportEngine   = "system:pyimport-engine"
	ProofActorRustImportScan   = "system:rustimport-scan"
	ProofActorRustImportEngine = "system:rustimport-engine"
	ProofActorPHPImportScan    = "system:phpimport-scan"
	ProofActorPHPImportEngine  = "system:phpimport-engine"
	ProofActorRubyImportScan   = "system:rubyimport-scan"
	ProofActorRubyImportEngine = "system:rubyimport-engine"
)

// IsDeterministicReachabilityProof reports whether the distinct reserved identities
// prove the supplied reachability tier. Unknown identities fail closed.
func IsDeterministicReachabilityProof(tier ReachabilityTier, proposer, verifier string) bool {
	switch tier {
	case Tier2:
		return (proposer == ProofActorCallgraphScan && verifier == ProofActorCallgraphEngine) ||
			(proposer == ProofActorJSSymbolScan && verifier == ProofActorJSSymbolEngine) ||
			(proposer == ProofActorPySemanticScan && verifier == ProofActorPySemanticEngine)
	case Tier1:
		return (proposer == ProofActorJSImportScan && verifier == ProofActorJSImportEngine) ||
			(proposer == ProofActorPyImportScan && verifier == ProofActorPyImportEngine) ||
			(proposer == ProofActorRustImportScan && verifier == ProofActorRustImportEngine) ||
			(proposer == ProofActorPHPImportScan && verifier == ProofActorPHPImportEngine) ||
			(proposer == ProofActorRubyImportScan && verifier == ProofActorRubyImportEngine)
	default:
		return false
	}
}

// maxClaimPathElems / maxClaimPathElemLen bound a reachability claim's call/dependency path so a
// hostile or runaway proposer (agent or HTTP) cannot seal an unbounded path into the evidence ledger
// + claim JSONB. Generous (a real path is far smaller); fail-closed at the one seam every propose
// path funnels through (judgment.New → canonicalizeClaim → Validate).
const (
	maxClaimPathElems   = 128
	maxClaimPathElemLen = 256
	maxSASTLocationLen  = 512
	maxSASTRuleLen      = 128
	// MaxSASTDataFlowSteps caps the structured witness admitted to the judgment ledger.
	MaxSASTDataFlowSteps = 64
	maxRiskDrivers       = 32
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
	CWE      string        `json:"cwe"`
	Location string        `json:"location"` // path[:line]
	Rule     string        `json:"rule"`
	AssetID  shared.ID     `json:"asset_id"`
	DataFlow *SASTDataFlow `json:"data_flow,omitempty"`
}

// SASTFlowLocation is a source-only point in a repository-relative file. Columns are zero-based UTF-8
// byte offsets. It intentionally carries no source line, expression text, value id, or local root path.
type SASTFlowLocation struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

// SASTDataFlow is a bounded source-to-sink witness attached to a proposed SAST claim. Steps are ordered
// and include Source and Sink. CoverageComplete describes the whole semantic analysis, not confidence in
// the positive witness; GraphTruncated is surfaced separately so consumers never infer a clean result.
type SASTDataFlow struct {
	Language         string             `json:"language"`
	Source           SASTFlowLocation   `json:"source"`
	Sink             SASTFlowLocation   `json:"sink"`
	Steps            []SASTFlowLocation `json:"steps"`
	CoverageComplete bool               `json:"coverage_complete"`
	GraphTruncated   bool               `json:"graph_truncated"`
}

func (l SASTFlowLocation) validate() error {
	canonical, err := measure.CanonicalPath(l.File)
	if err != nil || canonical == "" || canonical != l.File || len(l.File) > maxSASTLocationLen {
		return fmt.Errorf("%w: sast data-flow file must be a bounded canonical relative path", shared.ErrValidation)
	}
	if l.Line < 1 || l.Column < 0 {
		return fmt.Errorf("%w: sast data-flow position is invalid", shared.ErrValidation)
	}
	return nil
}

func (d SASTDataFlow) validate() error {
	if d.Language != "python" {
		return fmt.Errorf("%w: sast data-flow language is unknown", shared.ErrValidation)
	}
	if len(d.Steps) == 0 || len(d.Steps) > MaxSASTDataFlowSteps {
		return fmt.Errorf("%w: sast data-flow must have 1..%d steps", shared.ErrValidation, MaxSASTDataFlowSteps)
	}
	if err := d.Source.validate(); err != nil {
		return err
	}
	if err := d.Sink.validate(); err != nil {
		return err
	}
	for _, step := range d.Steps {
		if err := step.validate(); err != nil {
			return err
		}
	}
	if d.Steps[0] != d.Source || d.Steps[len(d.Steps)-1] != d.Sink {
		return fmt.Errorf("%w: sast data-flow steps must be anchored by source and sink", shared.ErrValidation)
	}
	return nil
}

// DASTClaim is the typed result of a dynamic check. Source and Fingerprint are
// stable tokens supplied by the first-party check corpus and identify the exact
// runtime observation without carrying response content or credentials.
type DASTClaim struct {
	CWE             string `json:"cwe"`
	Location        string `json:"location"`
	Rule            string `json:"rule"`
	Source          string `json:"source"`
	Fingerprint     string `json:"fingerprint"`
	ProofEvidenceID string `json:"proof_evidence_id"`
}

// Capability identifies this claim's brain.
func (DASTClaim) Capability() Capability { return CapDAST }

// Validate requires structured finding fields and stable, secret-free dedup tokens.
func (c DASTClaim) Validate() error {
	if strings.TrimSpace(c.CWE) == "" || strings.TrimSpace(c.Location) == "" || strings.TrimSpace(c.Rule) == "" {
		return fmt.Errorf("%w: dast claim requires a CWE, location, and rule", shared.ErrValidation)
	}
	if !driverRE.MatchString(c.Source) || !fingerprintRE.MatchString(c.Fingerprint) {
		return fmt.Errorf("%w: dast claim source and fingerprint must be lowercase tokens", shared.ErrValidation)
	}
	if strings.TrimSpace(c.ProofEvidenceID) == "" {
		return fmt.Errorf("%w: dast claim requires sealed proof evidence", shared.ErrValidation)
	}
	return nil
}

// Capability identifies this claim's brain.
func (SASTClaim) Capability() Capability { return CapSAST }

// Validate requires bounded, structured fields that make a SAST hit renderable + dedupable.
func (c SASTClaim) Validate() error {
	if !cweRE.MatchString(c.CWE) {
		return fmt.Errorf("%w: sast claim CWE must be a token like CWE-89", shared.ErrValidation)
	}
	if strings.TrimSpace(c.Location) == "" {
		return fmt.Errorf("%w: sast claim requires a location", shared.ErrValidation)
	}
	if len(c.Location) > maxSASTLocationLen {
		return fmt.Errorf("%w: sast claim location exceeds %d bytes", shared.ErrValidation, maxSASTLocationLen)
	}
	for _, r := range c.Location {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: sast claim location contains control characters", shared.ErrValidation)
		}
	}
	if len(c.Rule) > maxSASTRuleLen || !sastRuleRE.MatchString(c.Rule) {
		return fmt.Errorf("%w: sast claim rule must be a structured token of at most %d bytes", shared.ErrValidation, maxSASTRuleLen)
	}
	if c.DataFlow != nil {
		if err := c.DataFlow.validate(); err != nil {
			return err
		}
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
	if len(c.Drivers) > maxRiskDrivers {
		return fmt.Errorf("%w: risk narrative has too many drivers (%d > %d)", shared.ErrValidation, len(c.Drivers), maxRiskDrivers)
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
	Asset    string         `json:"asset"` // legacy display text; never used for asset attribution
	AssetID  shared.ID      `json:"asset_id"`
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

// PromotionChange is the closed set of finding-priority effects a cross-pillar rule may propose.
type PromotionChange string

const (
	PromotionEscalate      PromotionChange = "escalate"
	PromotionDeescalate    PromotionChange = "de_escalate"
	PromotionFlagForReview PromotionChange = "flag_for_review"
)

func (c PromotionChange) Valid() bool {
	return c == PromotionEscalate || c == PromotionDeescalate || c == PromotionFlagForReview
}

// PromotionInputKind identifies a typed record that supports or contradicts a promotion.
type PromotionInputKind string

const (
	PromotionInputReachability PromotionInputKind = "reachability_judgment"
	PromotionInputAttackPath   PromotionInputKind = "attack_path"
	PromotionInputDetection    PromotionInputKind = "detection"
	PromotionInputPrior        PromotionInputKind = "prior_promotion"
)

func (k PromotionInputKind) Valid() bool {
	return k == PromotionInputReachability || k == PromotionInputAttackPath || k == PromotionInputDetection || k == PromotionInputPrior
}

// PromotionInput links a promotion to the exact record and, where available, its sealed evidence.
type PromotionInput struct {
	Kind       PromotionInputKind `json:"kind"`
	ID         shared.ID          `json:"id"`
	EvidenceID shared.ID          `json:"evidence_id,omitempty"`
}

// PromotionClaim proposes a deterministic priority change. It is inert until a distinct verifier's
// sealed verdict clears the evidence bar. Uncertain inputs may only produce a review flag.
type PromotionClaim struct {
	FindingID      shared.ID        `json:"finding_id"`
	Rule           string           `json:"rule"`
	Inputs         []PromotionInput `json:"inputs"`
	Proposed       PromotionChange  `json:"proposed"`
	Uncertainty    []string         `json:"uncertainty,omitempty"`
	Fingerprint    string           `json:"fingerprint"`
	FindingVersion int              `json:"finding_version"`
	BeforePriority int              `json:"before_priority"`
	AfterPriority  int              `json:"after_priority"`
}

func (PromotionClaim) Capability() Capability { return CapPromotion }

func (c PromotionClaim) Validate() error {
	if c.FindingID.IsZero() {
		return fmt.Errorf("%w: promotion finding id is required", shared.ErrValidation)
	}
	if len(c.Rule) > 128 || !promotionRuleKeyRE.MatchString(c.Rule) {
		return fmt.Errorf("%w: promotion rule must be a stable promotion.* token", shared.ErrValidation)
	}
	expectEffect, ok := ExpectedEffect(c.Rule)
	if !ok {
		return fmt.Errorf("%w: unknown promotion rule %q", shared.ErrValidation, c.Rule)
	}
	if c.Proposed != expectEffect {
		return fmt.Errorf("%w: promotion rule %q produces %s, got %s", shared.ErrValidation, c.Rule, expectEffect, c.Proposed)
	}
	if !promotionFingerprintRE.MatchString(c.Fingerprint) {
		return fmt.Errorf("%w: promotion fingerprint must be a lowercase SHA-256 digest", shared.ErrValidation)
	}
	if !c.Proposed.Valid() {
		return fmt.Errorf("%w: promotion change must be escalate|de_escalate|flag_for_review", shared.ErrValidation)
	}
	if c.FindingVersion < 1 || c.BeforePriority < 1 || c.BeforePriority > 5 || c.AfterPriority < 1 || c.AfterPriority > 5 {
		return fmt.Errorf("%w: promotion requires a positive finding version and priorities in 1..5", shared.ErrValidation)
	}
	if len(c.Inputs) == 0 || len(c.Inputs) > 32 {
		return fmt.Errorf("%w: promotion requires 1..32 inputs", shared.ErrValidation)
	}
	for i, in := range c.Inputs {
		if !in.Kind.Valid() || in.ID.IsZero() {
			return fmt.Errorf("%w: promotion input %d has invalid kind or id", shared.ErrValidation, i)
		}
		if i > 0 {
			prev := c.Inputs[i-1]
			if prev.Kind > in.Kind || prev.Kind == in.Kind && (prev.ID > in.ID || prev.ID == in.ID && prev.EvidenceID >= in.EvidenceID) {
				return fmt.Errorf("%w: promotion inputs must be sorted and distinct", shared.ErrValidation)
			}
		}
	}
	if len(c.Uncertainty) > 8 {
		return fmt.Errorf("%w: promotion has too many uncertainty tokens", shared.ErrValidation)
	}
	for i, token := range c.Uncertainty {
		if len(token) > 64 || !driverRE.MatchString(token) || i > 0 && c.Uncertainty[i-1] >= token {
			return fmt.Errorf("%w: promotion uncertainty must be sorted distinct tokens", shared.ErrValidation)
		}
	}
	if len(c.Uncertainty) > 0 && c.Proposed != PromotionFlagForReview {
		return fmt.Errorf("%w: uncertain promotion can only flag for review", shared.ErrValidation)
	}
	switch c.Proposed {
	case PromotionEscalate:
		// Escalation is always exactly one level toward P1.
		if c.AfterPriority != c.BeforePriority-1 {
			return fmt.Errorf("%w: escalation must move priority one level toward P1", shared.ErrValidation)
		}
	case PromotionDeescalate:
		if c.AfterPriority <= c.BeforePriority || c.AfterPriority > 5 {
			return fmt.Errorf("%w: de-escalation must move priority toward P5", shared.ErrValidation)
		}
		if c.Rule == RuleCorroboratingSignalLoss {
			// Multi-level reversal: requires at least one prior_promotion input
			// and must restore a strictly higher prior priority.
			hasPrior := false
			for _, in := range c.Inputs {
				if in.Kind == PromotionInputPrior {
					hasPrior = true
					break
				}
			}
			if !hasPrior {
				return fmt.Errorf("%w: corroborating_signal_loss requires at least one prior_promotion input", shared.ErrValidation)
			}
			if c.AfterPriority <= c.BeforePriority {
				return fmt.Errorf("%w: corroborating_signal_loss must restore a higher priority", shared.ErrValidation)
			}
		} else {
			// Ordinary de-escalation: exactly one level.
			if c.AfterPriority != c.BeforePriority+1 {
				return fmt.Errorf("%w: ordinary de-escalation must move exactly one level toward P5", shared.ErrValidation)
			}
		}
	case PromotionFlagForReview:
		if c.AfterPriority != c.BeforePriority {
			return fmt.Errorf("%w: review flag cannot change priority", shared.ErrValidation)
		}
	}
	return nil
}

// VexJustificationClaim is a proposed OpenVEX justification for why a finding is NOT_AFFECTED – the
// AI's STRUCTURED choice from the CLOSED OpenVEX justification set, never free prose. The finding it
// applies to is the Judgment's SUBJECT (SubjectFinding), not part of the claim. Gated: a distinct human
// verifier ratifies it before the export trusts it (it asserts "not affected" in a published deliverable);
// the agent only proposes it at score 0. It COMPLEMENTS the deterministic reachability-tier justification.
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
	case CapDAST:
		var dc DASTClaim
		if err := strictDecode(env.Claim, &dc); err != nil {
			return nil, err
		}
		c = dc
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
	case CapPromotion:
		var pc PromotionClaim
		if err := strictDecode(env.Claim, &pc); err != nil {
			return nil, err
		}
		c = pc
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
