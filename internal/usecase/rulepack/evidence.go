package rulepack

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/purplecoverage"
	rulepackdomain "github.com/KKloudTarus/synapse-ce/internal/domain/rulepack"
)

const (
	// GateEvidenceAttestationContext domain-separates RulePack release evidence from the repository's
	// evidence/audit chain-head attestations even when the same infrastructure signer key is reused.
	GateEvidenceAttestationContext = "synapse-rulepack-gate-evidence:v1"
	gateEvidenceDigestPrefix       = "rulepack-gate-evidence-sha256:"
)

// GateEvidenceSigner is satisfied by the existing infrastructure/signing.Ed25519Signer. The composition
// root must configure it with GateEvidenceAttestationContext before giving it to the collector.
type GateEvidenceSigner interface {
	Sign(ctx context.Context, head string) (evidence.Attestation, error)
}

// GateEvidenceRequest contains operator-owned policy/measurements plus selectors for evidence that must
// be collected from authoritative telemetry and purple-coverage services. Callers cannot inject raw
// RetroEvidence or purplecoverage.Coverage into this boundary.
type GateEvidenceRequest struct {
	Deployment   rulepackdomain.RulePackDeployment `json:"deployment"`
	Policy       GatePolicy                        `json:"policy"`
	Costs        []RuleCostObservation             `json:"costs"`
	RetroCases   []RetroCase                       `json:"retro_cases"`
	Purple       PurpleRequest                     `json:"purple_request"`
	Evaluation   QualitySample                     `json:"evaluation"`
	Canary       *QualitySample                    `json:"canary,omitempty"`
	Production   *QualitySample                    `json:"production,omitempty"`
}

// SignedGateEvidence is the immutable release-evidence envelope consumed by synapse-cli rulepack gate.
// Its attestation covers the exact RulePack identity and canonical GateInput; verification pins the
// evidence producer key externally, independently of the RulePack content-signing key.
type SignedGateEvidence struct {
	PackID      string               `json:"pack_id"`
	PackVersion int                  `json:"pack_version"`
	PackDigest  string               `json:"pack_digest"`
	Input       GateInput            `json:"input"`
	Attestation evidence.Attestation `json:"attestation"`
}

// EvidenceCollector obtains the release evidence whose provenance matters from the existing authoritative
// seams, then attests to the deterministic envelope. It performs no persistence itself.
type EvidenceCollector struct {
	hunter TelemetryHunter
	purple PurpleReader
	signer GateEvidenceSigner
}

// NewEvidenceCollector validates the release-evidence dependencies.
func NewEvidenceCollector(hunter TelemetryHunter, purple PurpleReader, signer GateEvidenceSigner) (*EvidenceCollector, error) {
	if hunter == nil || purple == nil || signer == nil {
		return nil, fmt.Errorf("rulepack evidence collector requires telemetry, purple coverage, and signer dependencies")
	}
	return &EvidenceCollector{hunter: hunter, purple: purple, signer: signer}, nil
}

// Collect obtains retro-hunt and purple evidence from their authoritative services and returns an
// attested envelope. A valid-but-failing release (for example a real purple gap) is still attestable;
// malformed evidence is refused before it can acquire provenance.
func (c *EvidenceCollector) Collect(ctx context.Context, p rulepackdomain.RulePack, req GateEvidenceRequest) (SignedGateEvidence, error) {
	if err := p.Validate(); err != nil {
		return SignedGateEvidence{}, fmt.Errorf("validate rulepack: %w", err)
	}
	retro, err := CollectRetroEvidence(ctx, p, c.hunter, req.RetroCases)
	if err != nil {
		return SignedGateEvidence{}, err
	}
	purple, err := CollectPurpleEvidence(ctx, c.purple, req.Purple)
	if err != nil {
		return SignedGateEvidence{}, err
	}
	input := GateInput{
		Deployment: req.Deployment,
		Policy:     req.Policy,
		Costs:      append([]RuleCostObservation(nil), req.Costs...),
		Retro:      retro,
		Purple:     clonePurpleCoverage(purple),
		Evaluation: cloneQualitySample(req.Evaluation),
		Canary:     cloneQualitySamplePtr(req.Canary),
		Production: cloneQualitySamplePtr(req.Production),
	}
	// Evaluate validates the complete evidence shape. Threshold failures produce a report rather than an
	// error and therefore remain attestable evidence; malformed or internally inconsistent inputs do not.
	if _, err := Evaluate(p, input); err != nil {
		return SignedGateEvidence{}, fmt.Errorf("validate rulepack gate evidence: %w", err)
	}
	head, err := gateEvidenceHead(p.ID, p.Version, p.Digest, input)
	if err != nil {
		return SignedGateEvidence{}, err
	}
	att, err := c.signer.Sign(ctx, head)
	if err != nil {
		return SignedGateEvidence{}, fmt.Errorf("attest rulepack gate evidence: %w", err)
	}
	if att.Context != GateEvidenceAttestationContext || att.Head != head {
		return SignedGateEvidence{}, fmt.Errorf("rulepack evidence signer returned the wrong attestation context or head")
	}
	if err := evidence.VerifyAttestation(att); err != nil {
		return SignedGateEvidence{}, fmt.Errorf("self-verify rulepack gate evidence attestation: %w", err)
	}
	return SignedGateEvidence{
		PackID: p.ID, PackVersion: p.Version, PackDigest: p.Digest,
		Input: cloneGateInput(input), Attestation: att,
	}, nil
}

// VerifyGateEvidence verifies that s was produced by a trusted evidence collector for this exact
// RulePack. The attestation's embedded public key is never self-authorizing: it must byte-match the
// externally pinned trustedPub supplied by the caller.
func VerifyGateEvidence(s SignedGateEvidence, p rulepackdomain.RulePack, trustedPub ed25519.PublicKey) (GateInput, error) {
	if err := p.Validate(); err != nil {
		return GateInput{}, fmt.Errorf("validate rulepack: %w", err)
	}
	if len(trustedPub) != ed25519.PublicKeySize {
		return GateInput{}, fmt.Errorf("trusted rulepack gate-evidence public key has invalid size")
	}
	if s.PackID != p.ID || s.PackVersion != p.Version || s.PackDigest != p.Digest {
		return GateInput{}, fmt.Errorf("rulepack gate evidence does not identify the verified RulePack")
	}
	if s.Attestation.Context != GateEvidenceAttestationContext {
		return GateInput{}, fmt.Errorf("rulepack gate evidence has unexpected attestation context %q", s.Attestation.Context)
	}
	head, err := gateEvidenceHead(s.PackID, s.PackVersion, s.PackDigest, s.Input)
	if err != nil {
		return GateInput{}, err
	}
	if s.Attestation.Head != head {
		return GateInput{}, fmt.Errorf("rulepack gate evidence head does not match its content")
	}
	if err := evidence.VerifyAttestation(s.Attestation); err != nil {
		return GateInput{}, fmt.Errorf("verify rulepack gate evidence attestation: %w", err)
	}
	embedded, err := base64.StdEncoding.DecodeString(s.Attestation.PublicKey)
	if err != nil || len(embedded) != ed25519.PublicKeySize || !bytes.Equal(embedded, trustedPub) {
		return GateInput{}, fmt.Errorf("rulepack gate evidence signer is not the externally trusted key")
	}
	input := cloneGateInput(s.Input)
	if _, err := Evaluate(p, input); err != nil {
		return GateInput{}, fmt.Errorf("validate attested rulepack gate evidence: %w", err)
	}
	return input, nil
}

func gateEvidenceHead(packID string, packVersion int, packDigest string, input GateInput) (string, error) {
	payload := struct {
		PackID      string    `json:"pack_id"`
		PackVersion int       `json:"pack_version"`
		PackDigest  string    `json:"pack_digest"`
		Input       GateInput `json:"input"`
	}{packID, packVersion, packDigest, canonicalGateInput(input)}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("canonicalize rulepack gate evidence: %w", err)
	}
	sum := sha256.Sum256(b)
	return gateEvidenceDigestPrefix + hex.EncodeToString(sum[:]), nil
}

func canonicalGateInput(in GateInput) GateInput {
	out := cloneGateInput(in)
	sort.Slice(out.Deployment.Sensors, func(i, j int) bool { return out.Deployment.Sensors[i].ID < out.Deployment.Sensors[j].ID })
	sort.Slice(out.Deployment.AvailableFields, func(i, j int) bool { return out.Deployment.AvailableFields[i] < out.Deployment.AvailableFields[j] })
	sort.Slice(out.Costs, func(i, j int) bool { return out.Costs[i].RuleID < out.Costs[j].RuleID })
	sort.Slice(out.Retro, func(i, j int) bool { return out.Retro[i].RuleID < out.Retro[j].RuleID })
	for i := range out.Purple {
		sort.Strings(out.Purple[i].Actual)
		out.Purple[i].ComputedAt = out.Purple[i].ComputedAt.UTC()
	}
	sort.Slice(out.Purple, func(i, j int) bool {
		if out.Purple[i].TechniqueID != out.Purple[j].TechniqueID {
			return out.Purple[i].TechniqueID < out.Purple[j].TechniqueID
		}
		if out.Purple[i].TaxonomyRef != out.Purple[j].TaxonomyRef {
			return out.Purple[i].TaxonomyRef < out.Purple[j].TaxonomyRef
		}
		return out.Purple[i].Expected < out.Purple[j].Expected
	})
	sortQualityFields(&out.Evaluation)
	if out.Canary != nil {
		sortQualityFields(out.Canary)
	}
	if out.Production != nil {
		sortQualityFields(out.Production)
	}
	return out
}

func cloneGateInput(in GateInput) GateInput {
	out := in
	out.Deployment.Sensors = append([]rulepackdomain.SensorRequirement(nil), in.Deployment.Sensors...)
	out.Deployment.AvailableFields = append([]detection.Field(nil), in.Deployment.AvailableFields...)
	out.Costs = append([]RuleCostObservation(nil), in.Costs...)
	out.Retro = append([]RetroEvidence(nil), in.Retro...)
	out.Purple = clonePurpleCoverage(in.Purple)
	out.Evaluation = cloneQualitySample(in.Evaluation)
	out.Canary = cloneQualitySamplePtr(in.Canary)
	out.Production = cloneQualitySamplePtr(in.Production)
	return out
}

func clonePurpleCoverage(in []purplecoverage.Coverage) []purplecoverage.Coverage {
	out := make([]purplecoverage.Coverage, len(in))
	for i, row := range in {
		out[i] = row
		out[i].Actual = append([]string(nil), row.Actual...)
	}
	return out
}

func cloneQualitySample(in QualitySample) QualitySample {
	out := in
	out.AvailableFields = append([]detection.Field(nil), in.AvailableFields...)
	return out
}

func cloneQualitySamplePtr(in *QualitySample) *QualitySample {
	if in == nil {
		return nil
	}
	out := cloneQualitySample(*in)
	return &out
}

func sortQualityFields(sample *QualitySample) {
	sort.Slice(sample.AvailableFields, func(i, j int) bool { return sample.AvailableFields[i] < sample.AvailableFields[j] })
}
