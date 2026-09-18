package judgment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"
)

// SuppressionProvenanceGap records why a negative reachability result cannot
// exercise suppression authority. A gap is explicit evidence of uncertainty;
// it never grants authority by itself.
type SuppressionProvenanceGap string

const (
	ProvenanceMissingSubject              SuppressionProvenanceGap = "missing_subject"
	ProvenanceMissingBoundary             SuppressionProvenanceGap = "missing_boundary"
	ProvenanceMissingSourceSnapshot       SuppressionProvenanceGap = "missing_source_snapshot"
	ProvenanceMissingSBOMSnapshot         SuppressionProvenanceGap = "missing_sbom_snapshot"
	ProvenanceMissingRunSnapshot          SuppressionProvenanceGap = "missing_run_snapshot"
	ProvenanceMissingAnalyzer             SuppressionProvenanceGap = "missing_analyzer"
	ProvenanceMissingConfiguration        SuppressionProvenanceGap = "missing_configuration"
	ProvenanceMissingCompletenessContract SuppressionProvenanceGap = "missing_completeness_contract"
	ProvenanceMissingAuthorityCheckpoint  SuppressionProvenanceGap = "missing_authority_checkpoint"
	ProvenanceIncomplete                  SuppressionProvenanceGap = "incomplete"
	ProvenanceStale                       SuppressionProvenanceGap = "stale"
	ProvenanceMismatched                  SuppressionProvenanceGap = "mismatched"
	ProvenanceLegacy                      SuppressionProvenanceGap = "legacy"
	ProvenanceUnsupported                 SuppressionProvenanceGap = "unsupported"
	ProvenanceSkipped                     SuppressionProvenanceGap = "skipped"
	ProvenanceOpaque                      SuppressionProvenanceGap = "opaque"
	ProvenancePartial                     SuppressionProvenanceGap = "partial"
	ProvenanceFailed                      SuppressionProvenanceGap = "failed"
	ProvenanceMalformed                   SuppressionProvenanceGap = "malformed"
)

func (g SuppressionProvenanceGap) Valid() bool {
	switch g {
	case ProvenanceMissingSubject, ProvenanceMissingBoundary, ProvenanceMissingSourceSnapshot,
		ProvenanceMissingSBOMSnapshot, ProvenanceMissingRunSnapshot, ProvenanceMissingAnalyzer,
		ProvenanceMissingConfiguration, ProvenanceMissingCompletenessContract,
		ProvenanceMissingAuthorityCheckpoint, ProvenanceIncomplete, ProvenanceStale,
		ProvenanceMismatched, ProvenanceLegacy, ProvenanceUnsupported, ProvenanceSkipped,
		ProvenanceOpaque, ProvenancePartial, ProvenanceFailed, ProvenanceMalformed:
		return true
	}
	return false
}

type suppressionProofStage string

const (
	suppressionProofDraft          suppressionProofStage = "draft"
	suppressionProofProposalSealed suppressionProofStage = "proposal_sealed"
	suppressionProofVerdictSealed  suppressionProofStage = "verdict_sealed"
)

// ReachabilitySuppressionProofInput is the persistable, domain-owned identity
// needed to give a negative reachability judgment suppression authority. It is
// intentionally independent of reachbench: all values are generic immutable
// identities rather than use-case contract types.
type ReachabilitySuppressionProofInput struct {
	SubjectID            shared.ID
	BoundaryID           string
	Cohort               string
	Mode                 string
	Snapshot             ReachabilitySnapshotIdentity
	Analyzer             ArtifactIdentity
	Configuration        ArtifactIdentity
	CompletenessContract ArtifactIdentity
	Authority            SuppressionAuthority
	AuthorityCheckpoint  ArtifactIdentity
	Proposer             string
	Verifier             string
	MissingProvenance    []SuppressionProvenanceGap
}

// ReachabilitySuppressionProof is immutable provenance attached to one
// reachability judgment. Proposal and verdict evidence are added only by the
// judgment lifecycle after the corresponding evidence link is sealed.
type ReachabilitySuppressionProof struct {
	subjectID            shared.ID
	boundaryID           string
	cohort               string
	mode                 string
	snapshot             ReachabilitySnapshotIdentity
	analyzer             ArtifactIdentity
	configuration        ArtifactIdentity
	completenessContract ArtifactIdentity
	authority            SuppressionAuthority
	authorityCheckpoint  ArtifactIdentity
	proposer             string
	verifier             string
	proposalEvidence     ArtifactIdentity
	verdictEvidence      ArtifactIdentity
	missingProvenance    []SuppressionProvenanceGap
	stage                suppressionProofStage
}

// NewReachabilitySuppressionProof validates the immutable analysis identity.
// It creates a draft because proposal and verdict evidence do not exist until
// the evidence-gated lifecycle seals them.
func NewReachabilitySuppressionProof(input ReachabilitySuppressionProofInput) (ReachabilitySuppressionProof, error) {
	proof := ReachabilitySuppressionProof{
		subjectID:            input.SubjectID,
		boundaryID:           input.BoundaryID,
		cohort:               input.Cohort,
		mode:                 input.Mode,
		snapshot:             input.Snapshot,
		analyzer:             input.Analyzer,
		configuration:        input.Configuration,
		completenessContract: input.CompletenessContract,
		authority:            input.Authority,
		authorityCheckpoint:  input.AuthorityCheckpoint,
		proposer:             input.Proposer,
		verifier:             input.Verifier,
		missingProvenance:    canonicalProvenanceGaps(input.MissingProvenance),
		stage:                suppressionProofDraft,
	}
	if err := proof.validateDraft(); err != nil {
		return ReachabilitySuppressionProof{}, err
	}
	return proof, nil
}

// SubjectID returns the finding subject bound by this proof.
func (p ReachabilitySuppressionProof) SubjectID() shared.ID { return p.subjectID }

// BoundaryID returns the stable production boundary identity.
func (p ReachabilitySuppressionProof) BoundaryID() string { return p.boundaryID }

// Cohort returns the policy cohort.
func (p ReachabilitySuppressionProof) Cohort() string { return p.cohort }

// Mode returns the policy mode.
func (p ReachabilitySuppressionProof) Mode() string { return p.mode }

// Snapshot returns the source, SBOM, and run identity bound to the result.
func (p ReachabilitySuppressionProof) Snapshot() ReachabilitySnapshotIdentity { return p.snapshot }

// Analyzer returns the immutable analyzer identity.
func (p ReachabilitySuppressionProof) Analyzer() ArtifactIdentity { return p.analyzer }

// Configuration returns the immutable analysis configuration identity.
func (p ReachabilitySuppressionProof) Configuration() ArtifactIdentity { return p.configuration }

// CompletenessContract returns the exact completeness contract identity.
func (p ReachabilitySuppressionProof) CompletenessContract() ArtifactIdentity {
	return p.completenessContract
}

// Authority returns the frozen authority class bound to the proof.
func (p ReachabilitySuppressionProof) Authority() SuppressionAuthority { return p.authority }

// AuthorityCheckpoint returns the authority/checkpoint identity bound to the proof.
func (p ReachabilitySuppressionProof) AuthorityCheckpoint() ArtifactIdentity {
	return p.authorityCheckpoint
}

// Proposer returns the proof proposer identity.
func (p ReachabilitySuppressionProof) Proposer() string { return p.proposer }

// Verifier returns the proof verifier identity.
func (p ReachabilitySuppressionProof) Verifier() string { return p.verifier }

// ProposalEvidence returns the sealed proposal evidence identity, if present.
func (p ReachabilitySuppressionProof) ProposalEvidence() ArtifactIdentity { return p.proposalEvidence }

// VerdictEvidence returns the sealed verdict evidence identity, if present.
func (p ReachabilitySuppressionProof) VerdictEvidence() ArtifactIdentity { return p.verdictEvidence }

// MissingProvenance returns a copy of explicit uncertainty markers.
func (p ReachabilitySuppressionProof) MissingProvenance() []SuppressionProvenanceGap {
	return append([]SuppressionProvenanceGap(nil), p.missingProvenance...)
}

// WithProposalEvidence binds the proof to a sealed proposal evidence link.
func (p ReachabilitySuppressionProof) WithProposalEvidence(evidence ArtifactIdentity) (ReachabilitySuppressionProof, error) {
	if err := p.validateDraft(); err != nil {
		return ReachabilitySuppressionProof{}, err
	}
	if !evidence.Valid() {
		return ReachabilitySuppressionProof{}, fmt.Errorf("%w: suppression proof requires sealed proposal evidence identity", shared.ErrValidation)
	}
	p.proposalEvidence = evidence
	p.stage = suppressionProofProposalSealed
	if err := p.validatePersisted(); err != nil {
		return ReachabilitySuppressionProof{}, err
	}
	return p, nil
}

// WithVerdictEvidence binds the proof to a sealed verdict evidence link. The
// verdict cannot be associated before the proposal link exists.
func (p ReachabilitySuppressionProof) WithVerdictEvidence(evidence ArtifactIdentity) (ReachabilitySuppressionProof, error) {
	if err := p.validatePersisted(); err != nil || p.stage != suppressionProofProposalSealed {
		return ReachabilitySuppressionProof{}, fmt.Errorf("%w: suppression proof requires sealed proposal evidence before verdict evidence", shared.ErrValidation)
	}
	if !evidence.Valid() {
		return ReachabilitySuppressionProof{}, fmt.Errorf("%w: suppression proof requires sealed verdict evidence identity", shared.ErrValidation)
	}
	p.verdictEvidence = evidence
	p.stage = suppressionProofVerdictSealed
	if err := p.validatePersisted(); err != nil {
		return ReachabilitySuppressionProof{}, err
	}
	return p, nil
}

func (p ReachabilitySuppressionProof) validateDraft() error {
	if !validSuppressionProofCore(p) {
		return fmt.Errorf("%w: invalid reachability suppression provenance", shared.ErrValidation)
	}
	if p.stage != suppressionProofDraft || p.proposalEvidence.Valid() || p.verdictEvidence.Valid() {
		return fmt.Errorf("%w: invalid draft suppression proof evidence state", shared.ErrValidation)
	}
	return nil
}

func (p ReachabilitySuppressionProof) validatePersisted() error {
	if !validSuppressionProofCore(p) {
		return fmt.Errorf("%w: invalid reachability suppression provenance", shared.ErrValidation)
	}
	switch p.stage {
	case suppressionProofProposalSealed:
		if !p.proposalEvidence.Valid() || p.verdictEvidence.Valid() {
			return fmt.Errorf("%w: invalid proposal-sealed suppression proof", shared.ErrValidation)
		}
	case suppressionProofVerdictSealed:
		if !p.proposalEvidence.Valid() || !p.verdictEvidence.Valid() {
			return fmt.Errorf("%w: invalid verdict-sealed suppression proof", shared.ErrValidation)
		}
	default:
		return fmt.Errorf("%w: invalid persisted suppression proof stage", shared.ErrValidation)
	}
	return nil
}

func validSuppressionProofCore(p ReachabilitySuppressionProof) bool {
	if !validProvenanceGaps(p.missingProvenance) || !validActorIdentity(p.proposer) || !validActorIdentity(p.verifier) || p.proposer == p.verifier {
		return false
	}
	if !hasProvenanceGap(p.missingProvenance, ProvenanceMissingSubject) && p.subjectID.IsZero() {
		return false
	}
	if !hasProvenanceGap(p.missingProvenance, ProvenanceMissingBoundary) && !validStableIdentity(p.boundaryID) {
		return false
	}
	if _, err := NewCohortModePolicyKey(p.cohort, p.mode); err != nil {
		return false
	}
	if err := p.authority.Validate(); err != nil {
		return false
	}
	return optionalArtifactValid(p.snapshot.Source(), p.missingProvenance, ProvenanceMissingSourceSnapshot) &&
		optionalArtifactValid(p.snapshot.SBOM(), p.missingProvenance, ProvenanceMissingSBOMSnapshot) &&
		optionalArtifactValid(p.snapshot.Run(), p.missingProvenance, ProvenanceMissingRunSnapshot) &&
		optionalArtifactValid(p.analyzer, p.missingProvenance, ProvenanceMissingAnalyzer) &&
		optionalArtifactValid(p.configuration, p.missingProvenance, ProvenanceMissingConfiguration) &&
		optionalArtifactValid(p.completenessContract, p.missingProvenance, ProvenanceMissingCompletenessContract) &&
		optionalArtifactValid(p.authorityCheckpoint, p.missingProvenance, ProvenanceMissingAuthorityCheckpoint)
}

func optionalArtifactValid(identity ArtifactIdentity, gaps []SuppressionProvenanceGap, missingGap SuppressionProvenanceGap) bool {
	return identity.Valid() || hasProvenanceGap(gaps, missingGap) && identity == (ArtifactIdentity{})
}

func validProvenanceGaps(gaps []SuppressionProvenanceGap) bool {
	for index, gap := range gaps {
		if !gap.Valid() || index > 0 && gaps[index-1] >= gap {
			return false
		}
	}
	return true
}

func canonicalProvenanceGaps(gaps []SuppressionProvenanceGap) []SuppressionProvenanceGap {
	if len(gaps) == 0 {
		return nil
	}
	out := append([]SuppressionProvenanceGap(nil), gaps...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func hasProvenanceGap(gaps []SuppressionProvenanceGap, target SuppressionProvenanceGap) bool {
	for _, gap := range gaps {
		if gap == target {
			return true
		}
	}
	return false
}

func cloneReachabilitySuppressionProof(proof ReachabilitySuppressionProof) ReachabilitySuppressionProof {
	proof.missingProvenance = append([]SuppressionProvenanceGap(nil), proof.missingProvenance...)
	return proof
}

func sameSuppressionProofCore(left, right ReachabilitySuppressionProof) bool {
	if left.subjectID != right.subjectID || left.boundaryID != right.boundaryID || left.cohort != right.cohort || left.mode != right.mode ||
		!left.snapshot.Equal(right.snapshot) || !left.analyzer.Equal(right.analyzer) || !left.configuration.Equal(right.configuration) ||
		!left.completenessContract.Equal(right.completenessContract) || left.authority != right.authority || !left.authorityCheckpoint.Equal(right.authorityCheckpoint) ||
		left.proposer != right.proposer || left.verifier != right.verifier || len(left.missingProvenance) != len(right.missingProvenance) {
		return false
	}
	for index, gap := range left.missingProvenance {
		if gap != right.missingProvenance[index] {
			return false
		}
	}
	return true
}

// ReachabilitySuppressionContext is independently resolved current authority.
// Consumers with no honest source of this context must pass nil; suppression then
// fails closed while positive reachability remains usable.
type ReachabilitySuppressionContext struct {
	Snapshot            ReachabilitySnapshotIdentity
	BoundaryID          string
	Analyzer            ArtifactIdentity
	Configuration       ArtifactIdentity
	AuthorityCheckpoint ArtifactIdentity
	ProposalEvidence    ArtifactIdentity
	VerdictEvidence     ArtifactIdentity
}

func (c ReachabilitySuppressionContext) valid() bool {
	return c.Snapshot.Valid() && validStableIdentity(c.BoundaryID) && c.Analyzer.Valid() &&
		c.Configuration.Valid() && c.AuthorityCheckpoint.Valid() && c.ProposalEvidence.Valid() &&
		c.VerdictEvidence.Valid()
}

// ReachabilityDisposition is the one consumer-facing result of central
// reachability selection. Suppresses is true only when the winning negative has
// a complete, current, sealed, policy-approved proof.
type ReachabilityDisposition struct {
	JudgmentID    shared.ID
	State         ReachabilityState
	Tier          ReachabilityTier
	Path          []string
	Suppresses    bool
	EvidenceScore int
	Version       int
	UpdatedAt     time.Time
}

// WinningReachabilityDispositions selects one publishable finding-scoped
// result per subject. Invalid, legacy, stale, or incomplete negatives have no
// authority rank, so they cannot shadow an independently proven reachable
// judgment. A nil context intentionally disables suppression only.
func WinningReachabilityDispositions(judgments []Judgment, context *ReachabilitySuppressionContext) map[string]ReachabilityDisposition {
	out := map[string]ReachabilityDisposition{}
	for _, item := range judgments {
		if !item.Publishable() || item.Capability != CapReachability || item.SubjectKind != SubjectFinding {
			continue
		}
		claim, ok := item.Claim.(ReachabilityClaim)
		if !ok {
			continue
		}
		candidate := ReachabilityDisposition{
			JudgmentID:    item.ID,
			State:         claim.Reachable,
			Tier:          claim.Tier,
			Path:          append([]string(nil), claim.Path...),
			Suppresses:    suppressionAuthorized(item, claim, context),
			EvidenceScore: item.EvidenceScore,
			Version:       item.Version,
			UpdatedAt:     item.Audit.UpdatedAt,
		}
		key := item.SubjectID.String()
		current, exists := out[key]
		if !exists || dispositionSupersedes(candidate, current) {
			out[key] = candidate
		}
	}
	return out
}

func suppressionAuthorized(item Judgment, claim ReachabilityClaim, context *ReachabilitySuppressionContext) bool {
	if claim.Reachable != NotReachable || !claim.ProvedNotReachable() || item.EvidenceScore < verdict.DeterministicProofScore || context == nil || !context.valid() || item.SuppressionProof == nil {
		return false
	}
	proof := *item.SuppressionProof
	if err := proof.validatePersisted(); err != nil || proof.stage != suppressionProofVerdictSealed || len(proof.missingProvenance) != 0 {
		return false
	}
	if proof.subjectID != item.SubjectID || proof.proposer != item.ProposedBy || proof.verifier != item.VerifiedBy || proof.boundaryID != context.BoundaryID || !proof.analyzer.Equal(context.Analyzer) || !proof.configuration.Equal(context.Configuration) || !proof.authorityCheckpoint.Equal(context.AuthorityCheckpoint) || !proof.proposalEvidence.Equal(context.ProposalEvidence) || !proof.verdictEvidence.Equal(context.VerdictEvidence) {
		return false
	}
	registry, err := NewInitialReachabilityAuthorityRegistry()
	if err != nil {
		return false
	}
	return registry.ValidateSuppression(proof.cohort, proof.mode, context.Snapshot, SuppressionAuthorityRequest{
		Snapshot:       proof.snapshot,
		ContractID:     proof.completenessContract.ID(),
		ContractDigest: proof.completenessContract.Digest(),
		Proposer:       proof.proposer,
		Verifier:       proof.verifier,
		Authority:      proof.authority,
	}) == nil
}

func dispositionSupersedes(candidate, current ReachabilityDisposition) bool {
	candidateTier, candidateState := ReachabilitySignalRank(candidate.Tier, candidate.State, candidate.Suppresses)
	currentTier, currentState := ReachabilitySignalRank(current.Tier, current.State, current.Suppresses)
	if candidateTier != currentTier {
		return candidateTier > currentTier
	}
	if candidateState != currentState {
		return candidateState > currentState
	}
	return candidate.JudgmentID != "" && (current.JudgmentID == "" || candidate.JudgmentID < current.JudgmentID)
}

// SuppressionResistantDispositionIDs returns results that vendor or human
// assertions may not suppress because Synapse has positive reachability evidence.
func SuppressionResistantDispositionIDs(winner map[string]ReachabilityDisposition) map[string]bool {
	out := map[string]bool{}
	for id, result := range winner {
		if result.State == Reachable || result.State == ConditionallyReachable {
			out[id] = true
		}
	}
	return out
}

// MalformedReachabilitySuppressionProof records malformed persisted provenance
// as explicit uncertainty. It is intentionally invalid for all suppression use.
func MalformedReachabilitySuppressionProof() *ReachabilitySuppressionProof {
	return &ReachabilitySuppressionProof{missingProvenance: []SuppressionProvenanceGap{ProvenanceMalformed}}
}

const reachabilitySuppressionProofSchemaVersion = "synapse-reachability-suppression-proof-v1"

type reachabilitySuppressionProofWire struct {
	SchemaVersion        string                     `json:"schema_version"`
	SubjectID            shared.ID                  `json:"subject_id"`
	BoundaryID           string                     `json:"boundary_id"`
	Cohort               string                     `json:"cohort"`
	Mode                 string                     `json:"mode"`
	Snapshot             reachabilitySnapshotWire   `json:"snapshot"`
	Analyzer             artifactIdentityWire       `json:"analyzer"`
	Configuration        artifactIdentityWire       `json:"configuration"`
	CompletenessContract artifactIdentityWire       `json:"completeness_contract"`
	Authority            SuppressionAuthority       `json:"authority"`
	AuthorityCheckpoint  artifactIdentityWire       `json:"authority_checkpoint"`
	Proposer             string                     `json:"proposer"`
	Verifier             string                     `json:"verifier"`
	ProposalEvidence     artifactIdentityWire       `json:"proposal_evidence,omitempty"`
	VerdictEvidence      artifactIdentityWire       `json:"verdict_evidence,omitempty"`
	MissingProvenance    []SuppressionProvenanceGap `json:"missing_provenance,omitempty"`
	Stage                suppressionProofStage      `json:"stage"`
}

type artifactIdentityWire struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

type reachabilitySnapshotWire struct {
	Source artifactIdentityWire `json:"source"`
	SBOM   artifactIdentityWire `json:"sbom"`
	Run    artifactIdentityWire `json:"run"`
}

// MarshalReachabilitySuppressionProposalProof encodes the validated draft proof
// that is sealed with the judgment proposal. Persistence remains stricter and
// rejects drafts; this representation exists only to bind the immutable proof
// core into the append-only evidence chain before its evidence reference exists.
func MarshalReachabilitySuppressionProposalProof(proof *ReachabilitySuppressionProof) ([]byte, error) {
	if proof == nil {
		return nil, nil
	}
	if err := proof.validateDraft(); err != nil {
		return nil, err
	}
	return json.Marshal(proofWire(*proof))
}

// MarshalReachabilitySuppressionVerdictProof encodes the proposal-sealed proof
// into verdict evidence. It includes the proposal evidence identity but excludes
// the not-yet-created verdict reference, avoiding a self-referential digest.
func MarshalReachabilitySuppressionVerdictProof(proof *ReachabilitySuppressionProof) ([]byte, error) {
	if proof == nil {
		return nil, nil
	}
	if err := proof.validatePersisted(); err != nil || proof.stage != suppressionProofProposalSealed {
		return nil, fmt.Errorf("%w: verdict evidence requires a proposal-sealed suppression proof", shared.ErrValidation)
	}
	return json.Marshal(proofWire(*proof))
}

// MarshalReachabilitySuppressionProof encodes an immutable proof for JSONB persistence.
func MarshalReachabilitySuppressionProof(proof *ReachabilitySuppressionProof) ([]byte, error) {
	if proof == nil {
		return nil, nil
	}
	if err := proof.validatePersisted(); err != nil {
		return nil, err
	}
	return json.Marshal(proofWire(*proof))
}

// UnmarshalReachabilitySuppressionProof decodes strict persisted provenance.
func UnmarshalReachabilitySuppressionProof(data []byte) (*ReachabilitySuppressionProof, error) {
	if len(bytes.TrimSpace(data)) == 0 || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil, nil
	}
	var wire reachabilitySuppressionProofWire
	if err := strictDecode(data, &wire); err != nil || wire.SchemaVersion != reachabilitySuppressionProofSchemaVersion {
		return nil, fmt.Errorf("%w: malformed reachability suppression provenance", shared.ErrValidation)
	}
	proof := proofFromWire(wire)
	if err := proof.validatePersisted(); err != nil {
		return nil, err
	}
	return &proof, nil
}

func proofWire(proof ReachabilitySuppressionProof) reachabilitySuppressionProofWire {
	return reachabilitySuppressionProofWire{
		SchemaVersion: reachabilitySuppressionProofSchemaVersion,
		SubjectID:     proof.subjectID, BoundaryID: proof.boundaryID, Cohort: proof.cohort, Mode: proof.mode,
		Snapshot: reachabilitySnapshotWire{Source: artifactWire(proof.snapshot.Source()), SBOM: artifactWire(proof.snapshot.SBOM()), Run: artifactWire(proof.snapshot.Run())},
		Analyzer: artifactWire(proof.analyzer), Configuration: artifactWire(proof.configuration), CompletenessContract: artifactWire(proof.completenessContract),
		Authority: proof.authority, AuthorityCheckpoint: artifactWire(proof.authorityCheckpoint), Proposer: proof.proposer, Verifier: proof.verifier,
		ProposalEvidence: artifactWire(proof.proposalEvidence), VerdictEvidence: artifactWire(proof.verdictEvidence),
		MissingProvenance: append([]SuppressionProvenanceGap(nil), proof.missingProvenance...), Stage: proof.stage,
	}
}

func proofFromWire(wire reachabilitySuppressionProofWire) ReachabilitySuppressionProof {
	return ReachabilitySuppressionProof{
		subjectID: wire.SubjectID, boundaryID: wire.BoundaryID, cohort: wire.Cohort, mode: wire.Mode,
		snapshot: ReachabilitySnapshotIdentity{source: artifactFromWire(wire.Snapshot.Source), sbom: artifactFromWire(wire.Snapshot.SBOM), run: artifactFromWire(wire.Snapshot.Run)},
		analyzer: artifactFromWire(wire.Analyzer), configuration: artifactFromWire(wire.Configuration), completenessContract: artifactFromWire(wire.CompletenessContract),
		authority: wire.Authority, authorityCheckpoint: artifactFromWire(wire.AuthorityCheckpoint), proposer: wire.Proposer, verifier: wire.Verifier,
		proposalEvidence: artifactFromWire(wire.ProposalEvidence), verdictEvidence: artifactFromWire(wire.VerdictEvidence),
		missingProvenance: append([]SuppressionProvenanceGap(nil), wire.MissingProvenance...), stage: wire.Stage,
	}
}

func artifactWire(identity ArtifactIdentity) artifactIdentityWire {
	return artifactIdentityWire{ID: identity.ID(), Digest: identity.Digest()}
}

func artifactFromWire(wire artifactIdentityWire) ArtifactIdentity {
	return ArtifactIdentity{id: wire.ID, digest: wire.Digest}
}
