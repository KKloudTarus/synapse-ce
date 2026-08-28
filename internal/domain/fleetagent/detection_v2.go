package fleetagent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	detectionBatchV2Context = "synapse-agent-detection-batch:v2"
	detectionBatchV3Context = "synapse-agent-detection-batch:v3"
)

// TelemetryReference identifies one durable transport event that causally supports a detection.
// It is deliberately transport-coordinate based: callers must not synthesize a reference from a
// host id, timestamp, or rendered evidence.
type TelemetryReference struct {
	StreamID shared.ID `json:"stream_id"`
	Epoch    uint64    `json:"epoch"`
	Sequence uint64    `json:"sequence"`
	EventID  shared.ID `json:"event_id"`
	Digest   string    `json:"digest"`
}

func (r TelemetryReference) Validate() error {
	if r.StreamID.IsZero() || r.EventID.IsZero() || r.Epoch == 0 || r.Sequence == 0 {
		return fmt.Errorf("%w: telemetry reference needs stream, epoch, sequence and event id", shared.ErrValidation)
	}
	if strings.TrimSpace(r.Digest) == "" {
		return fmt.Errorf("%w: telemetry reference %s has no digest", shared.ErrValidation, r.EventID)
	}
	return nil
}

func telemetryReferencesValid(refs []TelemetryReference) error {
	if len(refs) == 0 {
		return fmt.Errorf("%w: v2 detection needs at least one telemetry reference", shared.ErrValidation)
	}
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		if err := ref.Validate(); err != nil {
			return err
		}
		key := strings.Join([]string{ref.StreamID.String(), strconv.FormatUint(ref.Epoch, 10), strconv.FormatUint(ref.Sequence, 10), ref.EventID.String()}, "\x1f")
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%w: v2 detection repeats telemetry reference %s", shared.ErrValidation, ref.EventID)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// RulepackReference binds a detection to the exact rulepack artifact that supplied its rule.
type RulepackReference struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	Digest  string `json:"digest"`
}

func (r RulepackReference) Validate() error {
	if strings.TrimSpace(r.ID) == "" || r.Version < 1 || strings.TrimSpace(r.Digest) == "" {
		return fmt.Errorf("%w: rulepack reference needs id, version and digest", shared.ErrValidation)
	}
	return nil
}

// DetectionRefV2 is the immutable, signature-covered manifest entry for a v2 detection.
type DetectionRefV2 struct {
	ID                    shared.ID            `json:"id"`
	ContentSHA256         string               `json:"content_sha256"`
	AssetID               shared.ID            `json:"asset_id"`
	TelemetryRefs         []TelemetryReference `json:"telemetry_refs"`
	Rulepack              RulepackReference    `json:"rulepack"`
	RedactionPolicyDigest string               `json:"redaction_policy_digest"`
}

func (r DetectionRefV2) Validate() error {
	if r.ID.IsZero() || r.AssetID.IsZero() || strings.TrimSpace(r.ContentSHA256) == "" {
		return fmt.Errorf("%w: v2 detection reference needs id, asset and content digest", shared.ErrValidation)
	}
	if digest, err := hex.DecodeString(r.ContentSHA256); err != nil || len(digest) != sha256.Size {
		return fmt.Errorf("%w: v2 detection reference has an invalid content digest", shared.ErrValidation)
	}
	if err := telemetryReferencesValid(r.TelemetryRefs); err != nil {
		return err
	}
	if err := r.Rulepack.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(r.RedactionPolicyDigest) == "" {
		return fmt.Errorf("%w: v2 detection reference has no redaction policy digest", shared.ErrValidation)
	}
	return nil
}

// DetectionBatchItemV2 carries the full body corresponding to a v2 signed manifest entry.
type DetectionBatchItemV2 struct {
	ID                    shared.ID            `json:"id"`
	Detection             detection.Detection  `json:"detection"`
	AssetID               shared.ID            `json:"asset_id"`
	TelemetryRefs         []TelemetryReference `json:"telemetry_refs"`
	Rulepack              RulepackReference    `json:"rulepack"`
	RedactionPolicyDigest string               `json:"redaction_policy_digest"`
}

func (i DetectionBatchItemV2) Validate() error {
	if i.ID.IsZero() || i.AssetID.IsZero() {
		return fmt.Errorf("%w: v2 detection batch item needs id and asset", shared.ErrValidation)
	}
	if err := telemetryReferencesValid(i.TelemetryRefs); err != nil {
		return err
	}
	if err := i.Rulepack.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(i.RedactionPolicyDigest) == "" {
		return fmt.Errorf("%w: v2 detection batch item has no redaction policy digest", shared.ErrValidation)
	}
	ref := DetectionRefV2{ID: i.ID, AssetID: i.AssetID, ContentSHA256: strings.Repeat("0", sha256.Size*2), TelemetryRefs: i.TelemetryRefs, Rulepack: i.Rulepack, RedactionPolicyDigest: i.RedactionPolicyDigest}
	if err := ref.Validate(); err != nil {
		return err
	}
	if err := i.Detection.Validate(); err != nil {
		return fmt.Errorf("v2 detection batch item %s is malformed: %w", i.ID, err)
	}
	return nil
}

func (i DetectionBatchItemV2) Reference() (DetectionRefV2, error) {
	if err := i.Validate(); err != nil {
		return DetectionRefV2{}, err
	}
	payload, err := canonicalDetection(i.Detection)
	if err != nil {
		return DetectionRefV2{}, err
	}
	return DetectionRefV2{ID: i.ID, ContentSHA256: DetectionContentHash(payload, i.AssetID), AssetID: i.AssetID,
		TelemetryRefs: append([]TelemetryReference(nil), i.TelemetryRefs...), Rulepack: i.Rulepack, RedactionPolicyDigest: i.RedactionPolicyDigest}, nil
}

func canonicalDetection(value detection.Detection) ([]byte, error) {
	// Keep the existing detection content commitment byte-for-byte compatible with v1.
	return json.Marshal(value)
}

// AgentBatchV2 is a separate wire and signature contract. AgentBatch, BatchMessage, SignBatch, and
// VerifyBatch remain the v1 contract and must not be changed by v2 callers.
type AgentBatchV2 struct {
	Context      string           `json:"context"`
	Version      int              `json:"version"`
	AgentID      shared.ID        `json:"agent_id"`
	EngagementID shared.ID        `json:"engagement_id"`
	Sequence     uint64           `json:"sequence"`
	KeyID        string           `json:"key_id"`
	Signature    string           `json:"signature"`
	Detections   []DetectionRefV2 `json:"detections"`
}

func (b AgentBatchV2) Validate() error {
	if (b.Version != 2 || b.Context != detectionBatchV2Context) &&
		(b.Version != 3 || b.Context != detectionBatchV3Context) {
		return fmt.Errorf("%w: attributed detection batch has an invalid context or version", shared.ErrValidation)
	}
	if b.AgentID.IsZero() || b.EngagementID.IsZero() || b.Sequence == 0 || strings.TrimSpace(b.KeyID) == "" {
		return fmt.Errorf("%w: attributed detection batch needs agent, engagement, sequence and signing key", shared.ErrValidation)
	}
	if len(b.Detections) == 0 {
		return fmt.Errorf("%w: attributed detection batch carries no detections", shared.ErrValidation)
	}
	seen := make(map[shared.ID]struct{}, len(b.Detections))
	for _, ref := range b.Detections {
		if err := ref.Validate(); err != nil {
			return err
		}
		if _, exists := seen[ref.ID]; exists {
			return fmt.Errorf("%w: attributed batch repeats detection id %s", shared.ErrValidation, ref.ID)
		}
		seen[ref.ID] = struct{}{}
	}
	return nil
}

func BatchMessageV2(b AgentBatchV2) []byte {
	switch b.Version {
	case 2:
		return batchMessageV2Legacy(b)
	case 3:
		return batchMessageV3(b)
	default:
		return nil
	}
}

// batchMessageV2Legacy preserves the already-deployed v2 signature contract.
// V3 is the unambiguous length-prefixed replacement for newly emitted batches.
func batchMessageV2Legacy(b AgentBatchV2) []byte {
	refs := append([]DetectionRefV2(nil), b.Detections...)
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })

	h := sha256.New()
	write := func(value string) {
		_, _ = h.Write([]byte(value))
		_, _ = h.Write([]byte(batchSep))
	}
	write(detectionBatchV2Context)
	write(b.AgentID.String())
	write(b.EngagementID.String())
	write(strconv.FormatUint(b.Sequence, 10))
	write(b.KeyID)
	for _, ref := range refs {
		write(ref.ID.String())
		write(ref.ContentSHA256)
		write(ref.AssetID.String())
		write(ref.Rulepack.ID)
		write(strconv.Itoa(ref.Rulepack.Version))
		write(ref.Rulepack.Digest)
		write(ref.RedactionPolicyDigest)

		causal := append([]TelemetryReference(nil), ref.TelemetryRefs...)
		sort.Slice(causal, func(i, j int) bool {
			return telemetryReferenceLess(causal[i], causal[j])
		})
		for _, causalRef := range causal {
			write(causalRef.StreamID.String())
			write(strconv.FormatUint(causalRef.Epoch, 10))
			write(strconv.FormatUint(causalRef.Sequence, 10))
			write(causalRef.EventID.String())
			write(causalRef.Digest)
		}
	}
	return h.Sum(nil)
}

func batchMessageV3(b AgentBatchV2) []byte {
	refs := append([]DetectionRefV2(nil), b.Detections...)
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })

	h := sha256.New()
	write := func(value string) { writeTelemetryCommitField(h, value) }
	write(detectionBatchV3Context)
	write(b.AgentID.String())
	write(b.EngagementID.String())
	write(strconv.FormatUint(b.Sequence, 10))
	write(b.KeyID)
	write(strconv.Itoa(len(refs)))
	for _, ref := range refs {
		write(ref.ID.String())
		write(ref.ContentSHA256)
		write(ref.AssetID.String())
		write(ref.Rulepack.ID)
		write(strconv.Itoa(ref.Rulepack.Version))
		write(ref.Rulepack.Digest)
		write(ref.RedactionPolicyDigest)

		causal := append([]TelemetryReference(nil), ref.TelemetryRefs...)
		sort.Slice(causal, func(i, j int) bool {
			return telemetryReferenceLess(causal[i], causal[j])
		})
		write(strconv.Itoa(len(causal)))
		for _, causalRef := range causal {
			write(causalRef.StreamID.String())
			write(strconv.FormatUint(causalRef.Epoch, 10))
			write(strconv.FormatUint(causalRef.Sequence, 10))
			write(causalRef.EventID.String())
			write(causalRef.Digest)
		}
	}
	return h.Sum(nil)
}

func telemetryReferenceLess(left, right TelemetryReference) bool {
	if left.StreamID != right.StreamID {
		return left.StreamID < right.StreamID
	}
	if left.Epoch != right.Epoch {
		return left.Epoch < right.Epoch
	}
	if left.Sequence != right.Sequence {
		return left.Sequence < right.Sequence
	}
	return left.EventID < right.EventID
}

func SignBatchV2(priv ed25519.PrivateKey, b AgentBatchV2) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, BatchMessageV2(b)))
}

func VerifyBatchV2(pub ed25519.PublicKey, b AgentBatchV2) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad public key size", ErrBadBatchSignature)
	}
	if err := b.Validate(); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(b.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed signature", ErrBadBatchSignature)
	}
	if !ed25519.Verify(pub, BatchMessageV2(b), sig) {
		return ErrBadBatchSignature
	}
	return nil
}

// VerifyBatchV2WithKey applies the existing signing-key lifecycle checks to the v2 signature
// contract without altering the v1 VerifyBatchWithKey canonical bytes.
func VerifyBatchV2WithKey(k AgentSigningKey, wantPurpose SigningPurpose, now time.Time, b AgentBatchV2) error {
	if k.Purpose != wantPurpose {
		return fmt.Errorf("%w: signing key %s is for %q, not %q", shared.ErrForbidden, k.KeyID, k.Purpose, wantPurpose)
	}
	if k.AgentID != b.AgentID {
		return fmt.Errorf("%w: signing key %s is bound to agent %s, not %s", shared.ErrForbidden, k.KeyID, k.AgentID, b.AgentID)
	}
	if b.KeyID != k.KeyID {
		return fmt.Errorf("%w: batch names key %s but was verified against %s", ErrBadBatchSignature, b.KeyID, k.KeyID)
	}
	if err := k.UsableAt(now); err != nil {
		return err
	}
	return VerifyBatchV2(k.PublicKey, b)
}

// DetectionAttribution is the typed source-side seam for sources that possess real telemetry transport
// references. Existing DetectionSink.Emit stays a legacy v1 path because DetectionSensor does not expose
// such references; callers cannot populate this type by guessing from a detection's host or timestamp.
type DetectionAttribution struct {
	TelemetryRefs         []TelemetryReference
	Rulepack              RulepackReference
	RedactionPolicyDigest string
}

func (a DetectionAttribution) Validate() error {
	if err := telemetryReferencesValid(a.TelemetryRefs); err != nil {
		return err
	}
	if err := a.Rulepack.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(a.RedactionPolicyDigest) == "" {
		return fmt.Errorf("%w: v2 detection attribution has no redaction policy digest", shared.ErrValidation)
	}
	return nil
}

// DetectionSpoolPayload allows v2 attribution to survive the detection WAL. Version 1 remains a
// deliberately un-attributed legacy payload and is decoded by the shipper for compatibility.
type DetectionSpoolPayload struct {
	Version    int                  `json:"version"`
	Item       DetectionBatchItemV2 `json:"item"`
	ObservedAt time.Time            `json:"observed_at"`
}

// PendingDetectionV2 is the verified immutable input retained until custody completes.
type PendingDetectionV2 struct {
	Batch AgentBatchV2         `json:"batch"`
	Item  DetectionBatchItemV2 `json:"item"`
}

func (p PendingDetectionV2) Canonical() ([]byte, error) {
	if err := p.Batch.Validate(); err != nil {
		return nil, err
	}
	if err := p.Item.Validate(); err != nil {
		return nil, err
	}
	ref, err := p.Item.Reference()
	if err != nil {
		return nil, err
	}
	found := false
	for _, signed := range p.Batch.Detections {
		if signed.ID == ref.ID {
			left, leftErr := json.Marshal(signed)
			right, rightErr := json.Marshal(ref)
			found = leftErr == nil && rightErr == nil && string(left) == string(right)
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("%w: pending v2 detection is not exact signed batch membership", shared.ErrValidation)
	}
	return json.Marshal(p)
}

func DecodePendingDetectionV2(content []byte) (PendingDetectionV2, error) {
	var pending PendingDetectionV2
	if len(content) == 0 {
		return pending, fmt.Errorf("%w: empty pending v2 detection", shared.ErrValidation)
	}
	if err := json.Unmarshal(content, &pending); err != nil {
		return pending, fmt.Errorf("decode pending v2 detection: %w", err)
	}
	if _, err := pending.Canonical(); err != nil {
		return pending, err
	}
	return pending, nil
}

func (p DetectionSpoolPayload) Validate() error {
	if p.Version != 2 {
		return fmt.Errorf("%w: unsupported detection spool payload version", shared.ErrValidation)
	}
	if err := p.Item.Validate(); err != nil {
		return err
	}
	if p.ObservedAt.IsZero() {
		return fmt.Errorf("%w: v2 detection spool payload has no observation time", shared.ErrValidation)
	}
	return nil
}
