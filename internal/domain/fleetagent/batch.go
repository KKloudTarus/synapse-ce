package fleetagent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ErrBadBatchSignature is returned when an agent detection batch's signature does not verify.
var ErrBadBatchSignature = errors.New("detection batch signature invalid")

// batchContext is the domain-separation tag for a detection-batch signature, mirroring the evidence /
// audit attestation tags: the same agent key might sign other things, so the signed bytes are prefixed
// with a per-purpose tag and a version so a batch signature can never be replayed as anything else.
const batchContext = "synapse-detection-batch:v1"

const batchSep = "\x1e"

// DetectionRef binds a detection id to a digest of its content, so the batch signature covers WHAT each
// detection is, not merely its id. ContentSHA256 is the hex sha256 the agent computed over the exact
// bytes it is shipping (see DetectionContentHash); the control plane recomputes it and refuses a
// mismatch, so a transport that swaps a detection's body for a known id is rejected before sealing.
type DetectionRef struct {
	ID            shared.ID
	ContentSHA256 string
}

// DetectionBatchItem is one detection body covered by an AgentBatch ref. It lives beside the batch
// contract so the agent transport and control-plane ingest share the exact same wire shape without an
// infrastructure package importing a server-side use case. AssetID is explicit because the asset is
// part of DetectionContentHash and must therefore be verified under the batch signature.
type DetectionBatchItem struct {
	ID        shared.ID
	Detection detection.Detection
	AssetID   shared.ID
}

// Validate checks the item before it is signed or admitted by the control plane.
func (i DetectionBatchItem) Validate() error {
	if i.ID.IsZero() {
		return fmt.Errorf("%w: detection batch item has no id", shared.ErrValidation)
	}
	if i.AssetID.IsZero() {
		return fmt.Errorf("%w: detection batch item %s has no asset", shared.ErrValidation, i.ID)
	}
	if err := i.Detection.Validate(); err != nil {
		return fmt.Errorf("detection batch item %s is malformed: %w", i.ID, err)
	}
	return nil
}

// AgentBatch is a sequenced, signed set of detections an agent shipped to the control plane (#423). The
// sequence is monotonic PER AGENT, so a gap in the sequence is a detectable potential loss rather than a
// silently-missing batch. The signature is over the batch's canonical membership (id AND content digest)
// AND its sequence, so neither the membership, the ordinal, nor a detection's CONTENT can be altered
// without breaking it.
type AgentBatch struct {
	AgentID      shared.ID
	EngagementID shared.ID
	Sequence     uint64
	KeyID        string // the AgentSigningKey this batch is signed with; resolved + verified server-side
	Signature    string // base64 ed25519 over BatchMessage
	Detections   []DetectionRef
}

// DetectionContentHash is the shared digest both the agent and the control plane compute over a
// detection's shipped bytes plus the asset it was observed on, so the two sides agree on what the
// signature binds. Keeping it here (domain) means there is one definition, not two that can drift.
func DetectionContentHash(content []byte, assetID shared.ID) string {
	h := sha256.New()
	h.Write(content)
	h.Write([]byte(batchSep))
	h.Write([]byte(assetID.String()))
	return hex.EncodeToString(h.Sum(nil))
}

// Validate checks a batch is well-formed. An empty batch, or one missing its agent/engagement/sequence,
// or a ref missing its id or content digest, cannot be sequenced/attributed/tamper-checked and is refused.
func (b AgentBatch) Validate() error {
	if b.AgentID == "" {
		return fmt.Errorf("%w: batch has no agent id", shared.ErrValidation)
	}
	if b.EngagementID == "" {
		return fmt.Errorf("%w: batch has no engagement id", shared.ErrValidation)
	}
	if b.Sequence == 0 {
		return fmt.Errorf("%w: batch sequence must be >= 1 (0 is reserved for 'no batch yet')", shared.ErrValidation)
	}
	if b.KeyID == "" {
		return fmt.Errorf("%w: batch has no signing key id", shared.ErrValidation)
	}
	if len(b.Detections) == 0 {
		return fmt.Errorf("%w: batch carries no detections", shared.ErrValidation)
	}
	seen := make(map[shared.ID]struct{}, len(b.Detections))
	for i, ref := range b.Detections {
		if ref.ID == "" {
			return fmt.Errorf("%w: batch detection[%d] has no id", shared.ErrValidation, i)
		}
		if ref.ContentSHA256 == "" {
			return fmt.Errorf("%w: batch detection[%d] has no content digest", shared.ErrValidation, i)
		}
		if _, duplicate := seen[ref.ID]; duplicate {
			return fmt.Errorf("%w: batch repeats detection id %s", shared.ErrValidation, ref.ID)
		}
		seen[ref.ID] = struct{}{}
	}
	return nil
}

// IDs returns the detection ids in the batch, for callers that only need the membership.
func (b AgentBatch) IDs() []shared.ID {
	out := make([]shared.ID, len(b.Detections))
	for i, ref := range b.Detections {
		out[i] = ref.ID
	}
	return out
}

// BatchMessage is the canonical byte string a batch signature covers: the context tag, agent,
// engagement, sequence, signing-key id, and the SORTED (id, content-digest) refs — so membership is
// order-independent but complete, each detection's content is bound, and the named signing key cannot be
// swapped. It is a sha256 digest of those fields, separated so field boundaries cannot collide.
func BatchMessage(b AgentBatch) []byte {
	refs := append([]DetectionRef(nil), b.Detections...)
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
	h := sha256.New()
	write := func(s string) { h.Write([]byte(s)); h.Write([]byte(batchSep)) }
	write(batchContext)
	write(b.AgentID.String())
	write(b.EngagementID.String())
	write(strconv.FormatUint(b.Sequence, 10))
	write(b.KeyID) // bind the signing-key id into the signature: the envelope KeyID cannot be swapped
	for _, ref := range refs {
		write(ref.ID.String())
		write(ref.ContentSHA256)
	}
	return h.Sum(nil)
}

// SignBatch produces the base64 ed25519 signature for a batch. Agents sign with the private half of the
// key whose public half the control plane knows from enrolment (#408).
func SignBatch(priv ed25519.PrivateKey, b AgentBatch) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, BatchMessage(b)))
}

// VerifyBatch checks the batch signature against the agent's public key. A batch that does not verify is
// refused before any of its detections are sealed — an unsigned or forged batch must never enter the
// evidence chain.
func VerifyBatch(pub ed25519.PublicKey, b AgentBatch) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad public key size", ErrBadBatchSignature)
	}
	sig, err := base64.StdEncoding.DecodeString(b.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed signature", ErrBadBatchSignature)
	}
	if !ed25519.Verify(pub, BatchMessage(b), sig) {
		return ErrBadBatchSignature
	}
	return nil
}

// SequenceGap describes what an incoming batch sequence implies against the last one seen for an agent.
type SequenceGap struct {
	// Missing is how many batches are unaccounted for between the last seen and this one. > 0 means a
	// potential loss the caller must surface (a batch_gap coverage event), never silently accept.
	Missing uint64
	// Replay is true when the incoming sequence is not ahead of the last seen (duplicate or out-of-order),
	// which is also suspicious and must be reported rather than double-counted.
	Replay bool
}

// HasGap reports whether this sequence transition is anything other than the expected next-in-line.
func (g SequenceGap) HasGap() bool { return g.Missing > 0 || g.Replay }

// DetectSequenceGap compares an incoming batch sequence against the last sequence recorded for that
// agent (0 = none yet). The expected next sequence is lastSeen+1; anything higher leaves a gap, anything
// not higher is a replay/out-of-order.
//
// This is the single-counter predecessor of the delivery contract (#609): it cannot tell a legitimate
// reboot reset-to-1 apart from a replay. It is superseded by ClassifyDelivery (delivery.go), which is
// incarnation-aware; A3 adopts ClassifyDelivery once the wire envelope carries a StreamPosition.
func DetectSequenceGap(lastSeen, incoming uint64) SequenceGap {
	if incoming <= lastSeen {
		return SequenceGap{Replay: true}
	}
	return SequenceGap{Missing: incoming - lastSeen - 1}
}
