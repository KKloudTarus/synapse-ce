package fleetagent

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// detectionEvidenceContext domain-separates the permanent detection-evidence commitment. It is carried
// INSIDE the sealed content (not just as the chain kind) so a link decoded on its own is unambiguously a
// detection-evidence envelope and cannot be reinterpreted as another sealed artifact.
const detectionEvidenceContext = "synapse-detection-evidence:v1"

// DetectionEvidenceEnvelopeVersion is the envelope schema version, carried in every envelope so the
// permanent chain link stays decodable as the shape evolves.
const DetectionEvidenceEnvelopeVersion = 1

// ProvenanceState is the durability/consistency state of a sealed detection's evidence (A5, #626).
//
// What the IMMUTABLE envelope records is the detection-evidence commitment at admission: once the detection
// (and its own embedded evidence) is sealed into the permanent chain it is ProvenanceComplete — that is the
// only state a stable, content-compared seal may honestly assert, since the sealed bytes must be identical
// across an idempotent re-seal. The remaining states are the QUERY/READ-LAYER lifecycle over a detection's
// evidence: Pending while the SEPARATE raw-telemetry stream (A3) that a detection summarizes is not yet
// confirmed durable, Expired when the expirable projection is swept, Broken when chain verification fails.
// Those transitions are tracked on the mutable projection, never by rewriting the immutable link — wiring
// the live telemetry-durability cross-check is the remaining A5 tail.
type ProvenanceState string

const (
	// ProvenancePending: read-layer state — the raw telemetry stream a detection summarizes is not yet
	// confirmed durable. A detection over not-yet-durable telemetry must NOT be presented as complete.
	ProvenancePending ProvenanceState = "pending"
	// ProvenanceComplete: the detection evidence is durably sealed into the permanent chain. This is the
	// admission state carried by the immutable envelope.
	ProvenanceComplete ProvenanceState = "complete"
	// ProvenanceExpired: read-layer state — the expirable projection view has aged out under retention; the
	// permanent envelope still stands and remains verifiable on its own.
	ProvenanceExpired ProvenanceState = "expired"
	// ProvenanceBroken: read-layer state — chain/consistency verification failed for this detection's evidence.
	ProvenanceBroken ProvenanceState = "broken"
)

// Valid reports whether p is a known provenance state.
func (p ProvenanceState) Valid() bool {
	switch p {
	case ProvenancePending, ProvenanceComplete, ProvenanceExpired, ProvenanceBroken:
		return true
	default:
		return false
	}
}

// DetectionEvidenceEnvelope is the SELF-CONTAINED permanent chain link for a sealed detection (A5, #626).
// It carries everything needed to attribute and verify the detection — tenant/agent/asset/engagement,
// the batch identity that admitted it, the agent's content commitment (ContentSHA256, the same digest the
// agent signed), the rule provenance, and the detection itself — so the link remains verifiable and
// explainable AFTER the expirable projection row is swept. It deliberately carries NO wall-clock "sealed
// at": the sealed bytes must be byte-identical across an idempotent re-seal (SealOnce compares content),
// so every field is derived from the batch/detection, never from the ingest clock.
type DetectionEvidenceEnvelope struct {
	Context         string              `json:"context"`
	EnvelopeVersion int                 `json:"envelope_version"`
	TenantID        shared.ID           `json:"tenant_id"`
	EngagementID    shared.ID           `json:"engagement_id"`
	AgentID         shared.ID           `json:"agent_id"`
	AssetID         shared.ID           `json:"asset_id"`
	DetectionID     shared.ID           `json:"detection_id"`
	BatchSequence   uint64              `json:"batch_sequence"`
	KeyID           string              `json:"key_id"`
	RuleID          string              `json:"rule_id"`
	RuleVersion     int                 `json:"rule_version"`
	ContentSHA256   string              `json:"content_sha256"`
	Provenance      ProvenanceState     `json:"provenance"`
	ObservedAt      time.Time           `json:"observed_at"`
	Detection       detection.Detection `json:"detection"`
}

// NewDetectionEvidenceEnvelope builds a validated envelope from the admitted batch identity and detection.
// contentSHA256 is the agent-signed content commitment (the verified DetectionContentHash), embedded so the
// link is self-verifying against its detection without the projection.
func NewDetectionEvidenceEnvelope(tenantID, engagementID, agentID, assetID, detectionID shared.ID, batchSequence uint64, keyID, contentSHA256 string, prov ProvenanceState, det detection.Detection) (DetectionEvidenceEnvelope, error) {
	env := DetectionEvidenceEnvelope{
		Context:         detectionEvidenceContext,
		EnvelopeVersion: DetectionEvidenceEnvelopeVersion,
		TenantID:        tenantID,
		EngagementID:    engagementID,
		AgentID:         agentID,
		AssetID:         assetID,
		DetectionID:     detectionID,
		BatchSequence:   batchSequence,
		KeyID:           keyID,
		RuleID:          det.RuleID,
		RuleVersion:     det.RuleVersion,
		ContentSHA256:   contentSHA256,
		Provenance:      prov,
		ObservedAt:      det.Observed.UTC(),
		Detection:       det,
	}
	if err := env.Validate(); err != nil {
		return DetectionEvidenceEnvelope{}, err
	}
	return env, nil
}

// Validate checks the envelope is well-formed and internally consistent.
func (e DetectionEvidenceEnvelope) Validate() error {
	if e.Context != detectionEvidenceContext {
		return fmt.Errorf("%w: detection evidence envelope has the wrong domain-separation context", shared.ErrValidation)
	}
	if e.EnvelopeVersion < 1 {
		return fmt.Errorf("%w: detection evidence envelope version must be >= 1", shared.ErrValidation)
	}
	if e.TenantID.IsZero() || e.EngagementID.IsZero() || e.AgentID.IsZero() || e.AssetID.IsZero() || e.DetectionID.IsZero() {
		return fmt.Errorf("%w: detection evidence envelope needs tenant, engagement, agent, asset and detection ids", shared.ErrValidation)
	}
	if e.KeyID == "" {
		return fmt.Errorf("%w: detection evidence envelope has no signing key id", shared.ErrValidation)
	}
	if e.ContentSHA256 == "" {
		return fmt.Errorf("%w: detection evidence envelope has no content commitment", shared.ErrValidation)
	}
	if !e.Provenance.Valid() {
		return fmt.Errorf("%w: detection evidence envelope has an unknown provenance %q", shared.ErrValidation, e.Provenance)
	}
	if err := e.Detection.Validate(); err != nil {
		return fmt.Errorf("%w: detection evidence envelope carries a malformed detection: %w", shared.ErrValidation, err)
	}
	return nil
}

// Canonical returns the deterministic bytes sealed into the evidence chain. It is stable across an
// idempotent re-seal (no wall-clock fields), so SealOnce's content comparison converges on a retry.
func (e DetectionEvidenceEnvelope) Canonical() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

// VerifyContent recomputes the detection content commitment and checks it equals the embedded, agent-signed
// ContentSHA256 — so a link tampered after sealing (detection body changed) is detectable from the envelope
// alone, with no projection needed.
func (e DetectionEvidenceEnvelope) VerifyContent() error {
	payload, err := json.Marshal(e.Detection)
	if err != nil {
		return fmt.Errorf("marshal envelope detection: %w", err)
	}
	if got := DetectionContentHash(payload, e.AssetID); got != e.ContentSHA256 {
		return fmt.Errorf("%w: detection evidence envelope content does not match its commitment", shared.ErrValidation)
	}
	return nil
}

// DecodeDetectionEvidenceEnvelope parses a sealed chain link's content back into a validated envelope, so
// a detection stays explainable from the permanent chain after its projection has expired.
func DecodeDetectionEvidenceEnvelope(content []byte) (DetectionEvidenceEnvelope, error) {
	var e DetectionEvidenceEnvelope
	if err := json.Unmarshal(content, &e); err != nil {
		return DetectionEvidenceEnvelope{}, fmt.Errorf("%w: cannot decode detection evidence envelope: %v", shared.ErrValidation, err)
	}
	if err := e.Validate(); err != nil {
		return DetectionEvidenceEnvelope{}, err
	}
	return e, nil
}
