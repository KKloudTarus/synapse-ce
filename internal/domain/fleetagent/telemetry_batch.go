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
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ErrBadManifestSignature is returned when a telemetry batch manifest's signature does not verify.
var ErrBadManifestSignature = errors.New("telemetry batch manifest signature invalid")

// TelemetryProtocolVersion is the current agent→control-plane telemetry transport protocol. It is
// carried on every manifest so the wire envelope can evolve independently of the payload schema
// (A0.3) and of the agent version.
const TelemetryProtocolVersion = 1

// maxTelemetrySequence bounds epoch and sequence well below 2^63 so a malicious agent cannot drive an
// int64 truncation/overflow when the value is persisted (BIGINT), turning what would be a storage-tier 500
// into a clean 4xx at validation. Far above any real incarnation's sequence count.
const maxTelemetrySequence = uint64(1) << 62

// telemetryBatchContext is the domain-separation tag for a telemetry-batch signature. Like the
// detection-batch and evidence/audit tags, it prefixes the signed bytes so the same agent key signing
// a telemetry batch can never have that signature replayed as a detection batch or an attestation.
const telemetryBatchContext = "synapse-telemetry-batch:v1"

// EventRef binds one shipped telemetry event's id to a digest of its canonical bytes, so the manifest
// signature covers WHAT each event is, not merely its id — a transport that swaps an event body for a
// known id is rejected before ingest.
type EventRef struct {
	ID     shared.ID
	Digest string // hex sha256 over the event's canonical shipped bytes
}

// TelemetryBatchManifest is a sequenced, signed manifest for one shipped telemetry batch (A3, #624). It
// binds the batch to a stream position (incarnation-aware, so a reboot reset-to-1 is not a replay — the
// A0.4 delivery contract), carries the three DISTINCT loss counts (Sampled ≠ Truncated ≠ Dropped, per
// D2/A0.6), and commits to the batch payload. This is the TRANSPORT-integrity + ACK commitment only;
// the permanent evidence commitment (retention/proof/Merkle) is A5's, not computed here.
type TelemetryBatchManifest struct {
	ProtocolVersion int
	SchemaVersion   int
	BatchID         shared.ID
	AgentID         shared.ID
	AssetID         shared.ID
	StreamID        shared.ID
	// Position carries Priority, Epoch, Sequence, Session (== the AgentSessionID) and Boot — the
	// incarnation-aware stream coordinate ClassifyDelivery/AckLedger reason over.
	Position         StreamPosition
	PreviousSequence uint64
	EventTimeMin     time.Time
	EventTimeMax     time.Time
	// The three loss outcomes are separate buckets; per-event reason lives on the first-class
	// TelemetryLoss/TelemetryGap, not here.
	ObservedCount        int
	KeptCount            int
	SampledOutCount      int
	TruncatedCount       int
	DroppedCount         int
	SamplingPolicyDigest string // digest of {SamplingAlgorithm, SamplingPolicyID, Seed, Version}
	// Events are the KeptCount shipped events, each bound by id + content digest.
	Events []EventRef
	// PayloadDigest commits to the canonical uncompressed transport payload (the events' shipped bytes).
	PayloadDigest string
	KeyID         string // the AgentSigningKey (Purpose=telemetry-batch) this manifest is signed with
	Signature     string // base64 ed25519 over TelemetryManifestMessage
}

// AgentSessionID returns the incarnation's session id (the manifest's Position.Session).
func (m TelemetryBatchManifest) AgentSessionID() SessionID { return m.Position.Session }

// Validate checks the manifest is well-formed and internally consistent. A malformed manifest — missing
// identity, an inconsistent kept-vs-event count, or a bad loss arithmetic — is refused before any
// signature check or ingest.
func (m TelemetryBatchManifest) Validate() error {
	if m.ProtocolVersion < 1 {
		return fmt.Errorf("%w: telemetry manifest protocol version must be >= 1", shared.ErrValidation)
	}
	if m.SchemaVersion < 1 {
		return fmt.Errorf("%w: telemetry manifest schema version must be >= 1", shared.ErrValidation)
	}
	if m.BatchID.IsZero() || m.AgentID.IsZero() || m.AssetID.IsZero() || m.StreamID.IsZero() {
		return fmt.Errorf("%w: telemetry manifest needs batch, agent, asset and stream ids", shared.ErrValidation)
	}
	if err := m.Position.Validate(); err != nil {
		return fmt.Errorf("telemetry manifest position: %w", err)
	}
	if m.PreviousSequence >= m.Position.Sequence {
		return fmt.Errorf("%w: telemetry manifest previous sequence %d must be below current %d", shared.ErrValidation, m.PreviousSequence, m.Position.Sequence)
	}
	if m.Position.Epoch > maxTelemetrySequence || m.Position.Sequence > maxTelemetrySequence {
		return fmt.Errorf("%w: telemetry manifest epoch/sequence exceeds the maximum %d", shared.ErrValidation, maxTelemetrySequence)
	}
	if m.KeyID == "" {
		return fmt.Errorf("%w: telemetry manifest has no signing key id", shared.ErrValidation)
	}
	if m.PayloadDigest == "" {
		return fmt.Errorf("%w: telemetry manifest has no payload digest", shared.ErrValidation)
	}
	if m.EventTimeMax.Before(m.EventTimeMin) {
		return fmt.Errorf("%w: telemetry manifest event-time-max precedes event-time-min", shared.ErrValidation)
	}
	if m.ObservedCount < 0 || m.KeptCount < 0 || m.SampledOutCount < 0 || m.TruncatedCount < 0 || m.DroppedCount < 0 {
		return fmt.Errorf("%w: telemetry manifest has a negative count", shared.ErrValidation)
	}
	// Observed is what the agent saw; kept + the three loss buckets must not exceed it (they account for
	// where the observed events went; a shortfall is allowed — not every observed event is enumerated).
	if m.KeptCount+m.SampledOutCount+m.TruncatedCount+m.DroppedCount > m.ObservedCount {
		return fmt.Errorf("%w: telemetry manifest kept+lost exceeds observed", shared.ErrValidation)
	}
	if len(m.Events) != m.KeptCount {
		return fmt.Errorf("%w: telemetry manifest lists %d events but kept count is %d", shared.ErrValidation, len(m.Events), m.KeptCount)
	}
	for i, ref := range m.Events {
		if ref.ID.IsZero() {
			return fmt.Errorf("%w: telemetry manifest event[%d] has no id", shared.ErrValidation, i)
		}
		if ref.Digest == "" {
			return fmt.Errorf("%w: telemetry manifest event[%d] has no digest", shared.ErrValidation, i)
		}
	}
	return nil
}

// TelemetryEventDigest is the shared digest both the agent and the control plane compute over one
// telemetry event's shipped bytes plus the asset it was observed on, so the two sides agree on what the
// manifest's EventRef.Digest binds. One definition (domain) so the two sides cannot drift.
func TelemetryEventDigest(payload []byte, assetID shared.ID) string {
	h := sha256.New()
	h.Write(payload)
	h.Write([]byte(batchSep))
	h.Write([]byte(assetID.String()))
	return hex.EncodeToString(h.Sum(nil))
}

// TelemetryPayloadDigest is the batch-level commitment the manifest's PayloadDigest carries: a sha256 over
// the SORTED (event id, digest) refs. The control plane recomputes it from the manifest's event refs and
// checks it equals the signed PayloadDigest, so that signed field cannot be a stray value. One definition
// (domain) so the agent and control plane cannot drift.
func TelemetryPayloadDigest(events []EventRef) string {
	refs := append([]EventRef(nil), events...)
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].ID != refs[j].ID {
			return refs[i].ID < refs[j].ID
		}
		return refs[i].Digest < refs[j].Digest
	})
	h := sha256.New()
	for _, ref := range refs {
		h.Write([]byte(ref.ID.String()))
		h.Write([]byte(batchSep))
		h.Write([]byte(ref.Digest))
		h.Write([]byte(batchSep))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TelemetryManifestMessage is the canonical byte string a manifest signature covers: the context tag,
// protocol/schema versions, identity, the full stream position, the loss accounting, the SORTED
// (event id, digest) pairs, and the payload digest — so the batch's membership, ordinal, incarnation,
// loss claims and payload are all bound and the named signing key cannot be swapped. It is a sha256
// digest with delimiter-separated fields so field boundaries cannot collide.
func TelemetryManifestMessage(m TelemetryBatchManifest) []byte {
	refs := append([]EventRef(nil), m.Events...)
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].ID != refs[j].ID {
			return refs[i].ID < refs[j].ID
		}
		return refs[i].Digest < refs[j].Digest
	})
	h := sha256.New()
	write := func(s string) { h.Write([]byte(s)); h.Write([]byte(batchSep)) }
	writeU := func(u uint64) { write(strconv.FormatUint(u, 10)) }
	writeI := func(i int) { write(strconv.Itoa(i)) }
	write(telemetryBatchContext)
	writeI(m.ProtocolVersion)
	writeI(m.SchemaVersion)
	write(m.BatchID.String())
	write(m.AgentID.String())
	write(m.AssetID.String())
	write(m.StreamID.String())
	writeU(uint64(m.Position.Priority))
	writeU(m.Position.Epoch)
	writeU(m.Position.Sequence)
	writeU(m.PreviousSequence)
	write(string(m.Position.Session))
	write(string(m.Position.Boot))
	writeU(uint64(m.EventTimeMin.UTC().UnixNano()))
	writeU(uint64(m.EventTimeMax.UTC().UnixNano()))
	writeI(m.ObservedCount)
	writeI(m.KeptCount)
	writeI(m.SampledOutCount)
	writeI(m.TruncatedCount)
	writeI(m.DroppedCount)
	write(m.SamplingPolicyDigest)
	write(m.PayloadDigest)
	write(m.KeyID) // bind the signing-key id: the envelope KeyID cannot be swapped
	for _, ref := range refs {
		write(ref.ID.String())
		write(ref.Digest)
	}
	return h.Sum(nil)
}

// SignTelemetryManifest produces the base64 ed25519 signature for a manifest.
func SignTelemetryManifest(priv ed25519.PrivateKey, m TelemetryBatchManifest) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, TelemetryManifestMessage(m)))
}

// VerifyTelemetryManifest checks the manifest signature against a public key. Fail-closed: a bad key
// size, malformed signature, or a signature that does not verify all return ErrBadManifestSignature.
func VerifyTelemetryManifest(pub ed25519.PublicKey, m TelemetryBatchManifest) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad public key size", ErrBadManifestSignature)
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed signature", ErrBadManifestSignature)
	}
	if !ed25519.Verify(pub, TelemetryManifestMessage(m), sig) {
		return ErrBadManifestSignature
	}
	return nil
}

// VerifyTelemetryManifestWithKey is the fail-closed server-side gate: the resolved key must be a
// telemetry-batch key, bound to the manifest's agent, named by the manifest's KeyID, usable now, and
// its public half must verify the signature. It mirrors VerifyBatchWithKey for the telemetry path.
func VerifyTelemetryManifestWithKey(k AgentSigningKey, now time.Time, m TelemetryBatchManifest) error {
	if k.Purpose != PurposeTelemetryBatch {
		return fmt.Errorf("%w: signing key %s is for %q, not %q", shared.ErrForbidden, k.KeyID, k.Purpose, PurposeTelemetryBatch)
	}
	if k.AgentID != m.AgentID {
		return fmt.Errorf("%w: signing key %s is bound to agent %s, not %s", shared.ErrForbidden, k.KeyID, k.AgentID, m.AgentID)
	}
	if m.KeyID != k.KeyID {
		return fmt.Errorf("%w: manifest names key %s but was verified against %s", ErrBadManifestSignature, m.KeyID, k.KeyID)
	}
	if err := k.UsableAt(now); err != nil {
		return err
	}
	return VerifyTelemetryManifest(k.PublicKey, m)
}
