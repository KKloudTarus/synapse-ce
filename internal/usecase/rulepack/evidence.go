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
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/purplecoverage"
	rulepackdomain "github.com/KKloudTarus/synapse-ce/internal/domain/rulepack"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
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
	Deployment rulepackdomain.RulePackDeployment `json:"deployment"`
	Policy     GatePolicy                        `json:"policy"`
	Costs      []RuleCostObservation             `json:"costs"`
	RetroCases []RetroCase                       `json:"retro_cases"`
	Purple     PurpleRequest                     `json:"purple_request"`
	Evaluation QualitySample                     `json:"evaluation"`
	Canary     *QualitySample                    `json:"canary,omitempty"`
	Production *QualitySample                    `json:"production,omitempty"`
}

// RetroQueryProvenance records the exact bounded telemetry selector used to produce one rule's retro
// evidence. The gate attestation binds these selectors alongside the aggregate result so a later release
// review can identify and reproduce the exact host/class/time window that was evaluated.
type RetroQueryProvenance struct {
	RuleID  string          `json:"rule_id"`
	HostID  shared.ID       `json:"host_id"`
	AssetID shared.ID       `json:"asset_id,omitempty"`
	Class   detection.Class `json:"class"`
	Since   time.Time       `json:"since"`
	Until   time.Time       `json:"until"`
	Limit   int             `json:"limit"`
}

// SignedGateEvidence is the immutable release-evidence envelope consumed by synapse-cli rulepack gate.
// Its attestation covers the exact RulePack identity, the bounded retro-hunt selectors, and canonical
// GateInput; verification pins the evidence producer key externally, independently of the RulePack
// content-signing key.
type SignedGateEvidence struct {
	PackID       string                 `json:"pack_id"`
	PackVersion  int                    `json:"pack_version"`
	PackDigest   string                 `json:"pack_digest"`
	RetroQueries []RetroQueryProvenance `json:"retro_queries"`
	Input        GateInput              `json:"input"`
	Attestation  evidence.Attestation   `json:"attestation"`
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
	retroQueries := retroQueryProvenance(req.RetroCases)
	if err := validateRetroQueryProvenance(p, retro, retroQueries); err != nil {
		return SignedGateEvidence{}, fmt.Errorf("validate retro-hunt provenance: %w", err)
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
	head, err := gateEvidenceHead(p.ID, p.Version, p.Digest, input, retroQueries)
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
		RetroQueries: canonicalRetroQueryProvenance(retroQueries),
		Input:        cloneGateInput(input), Attestation: att,
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
	input := cloneGateInput(s.Input)
	if err := validateRetroQueryProvenance(p, input.Retro, s.RetroQueries); err != nil {
		return GateInput{}, fmt.Errorf("rulepack gate evidence has invalid retro-hunt provenance: %w", err)
	}
	head, err := gateEvidenceHead(s.PackID, s.PackVersion, s.PackDigest, input, s.RetroQueries)
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
	if _, err := Evaluate(p, input); err != nil {
		return GateInput{}, fmt.Errorf("validate attested rulepack gate evidence: %w", err)
	}
	return input, nil
}

func gateEvidenceHead(packID string, packVersion int, packDigest string, input GateInput, retroQuerySets ...[]RetroQueryProvenance) (string, error) {
	var retroQueries []RetroQueryProvenance
	if len(retroQuerySets) != 0 {
		retroQueries = canonicalRetroQueryProvenance(retroQuerySets[0])
	}
	payload := struct {
		PackID       string                 `json:"pack_id"`
		PackVersion  int                    `json:"pack_version"`
		PackDigest   string                 `json:"pack_digest"`
		RetroQueries []RetroQueryProvenance `json:"retro_queries,omitempty"`
		Input        GateInput              `json:"input"`
	}{packID, packVersion, packDigest, retroQueries, canonicalGateInput(input)}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("canonicalize rulepack gate evidence: %w", err)
	}
	sum := sha256.Sum256(b)
	return gateEvidenceDigestPrefix + hex.EncodeToString(sum[:]), nil
}

func retroQueryProvenance(cases []RetroCase) []RetroQueryProvenance {
	out := make([]RetroQueryProvenance, 0, len(cases))
	for _, candidate := range cases {
		q := candidate.Query
		out = append(out, RetroQueryProvenance{
			RuleID: candidate.RuleID, HostID: q.HostID, AssetID: q.AssetID, Class: q.Class,
			Since: q.Since.UTC(), Until: q.Until.UTC(), Limit: q.Limit,
		})
	}
	return canonicalRetroQueryProvenance(out)
}

func canonicalRetroQueryProvenance(in []RetroQueryProvenance) []RetroQueryProvenance {
	out := append([]RetroQueryProvenance(nil), in...)
	for i := range out {
		out[i].Since = out[i].Since.UTC()
		out[i].Until = out[i].Until.UTC()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

func validateRetroQueryProvenance(p rulepackdomain.RulePack, retro []RetroEvidence, queries []RetroQueryProvenance) error {
	if len(queries) != len(p.Rules) {
		return fmt.Errorf("expected exactly one retro query per rule (%d rules, %d queries)", len(p.Rules), len(queries))
	}
	rules := make(map[string]detection.Class, len(p.Rules))
	for _, rule := range p.Rules {
		rules[rule.ID] = rule.Class
	}
	retroRules := make(map[string]struct{}, len(retro))
	for _, item := range retro {
		retroRules[item.RuleID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(queries))
	for _, q := range queries {
		class, ok := rules[q.RuleID]
		if !ok {
			return fmt.Errorf("retro query names unknown rule %q", q.RuleID)
		}
		if _, duplicate := seen[q.RuleID]; duplicate {
			return fmt.Errorf("retro query for rule %q is duplicated", q.RuleID)
		}
		seen[q.RuleID] = struct{}{}
		if q.HostID == "" || !q.Class.Valid() || q.Class != class || q.Since.IsZero() || q.Until.IsZero() || q.Until.Before(q.Since) {
			return fmt.Errorf("retro query for rule %s needs a host, matching class, and bounded time window", q.RuleID)
		}
		if q.Limit < 1 || q.Limit > maxRetroHuntEvents {
			return fmt.Errorf("retro query for rule %s needs an event limit between 1 and %d", q.RuleID, maxRetroHuntEvents)
		}
		if _, ok := retroRules[q.RuleID]; !ok {
			return fmt.Errorf("retro query for rule %s has no corresponding result", q.RuleID)
		}
	}
	return nil
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
