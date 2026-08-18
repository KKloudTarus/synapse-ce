package fleetagent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// A content-signing key is separate from the agent's TLS/enrolment cert key: it signs the CONTENT an
// agent ships (telemetry / detection / response), so a payload is attributable to a canonical agent
// identity over the key's lifetime even as the transport cert rotates independently (#607, A0.2).
//
// Three invariants make a signing key trustworthy:
//   - the KeyID is the fingerprint of the public key, so a KeyID cannot name a different key than the one
//     it was minted from (see NewSigningKey / evidence.KeyFingerprint);
//   - the key is bound to a canonical AgentID (#606, A0.1) and to ONE purpose, so a detection-batch key
//     can never verify a telemetry batch (domain separation);
//   - it carries a validity window plus revocation, so a rotated-out or compromised key fails closed.

// SigningPurpose is the single content stream a key may sign. A key is minted for exactly one purpose so
// a signature over one stream can never be replayed as another (domain separation).
type SigningPurpose string

const (
	PurposeTelemetryBatch SigningPurpose = "telemetry-batch"
	PurposeDetectionBatch SigningPurpose = "detection-batch"
	PurposeResponseResult SigningPurpose = "response-result"
)

// Valid reports whether p is one of the known purposes.
func (p SigningPurpose) Valid() bool {
	switch p {
	case PurposeTelemetryBatch, PurposeDetectionBatch, PurposeResponseResult:
		return true
	default:
		return false
	}
}

// SigningAlgorithm is the only content-signing algorithm A0.2 supports. It is a named constant (not a
// free string) so an unknown algorithm is rejected at construction rather than silently trusted.
const SigningAlgorithm = "ed25519"

// keyBindingContext domain-separates the proof-of-possession signature an agent produces when it
// registers a key, so that proof can never be replayed as a batch signature or an attestation.
const keyBindingContext = "synapse-agent-key-binding:v1"

// KeyStatus is a signing key's lifecycle state AT A GIVEN TIME. It is derived (never stored) from the
// window + revocation, so the same stored key reads Pending, Active, Expired, or Revoked as time moves.
type KeyStatus string

const (
	KeyPending KeyStatus = "pending" // now < NotBefore
	KeyActive  KeyStatus = "active"  // usable
	KeyExpired KeyStatus = "expired" // now >= NotAfter
	KeyRevoked KeyStatus = "revoked" // now >= RevokedAt
)

// AgentSigningKey is a first-class content-signing key with a lifecycle. It is minted by NewSigningKey so
// the KeyID↔PublicKey invariant always holds; a zero-value struct is not a valid key.
type AgentSigningKey struct {
	KeyID      string            // evidence.KeyFingerprint(PublicKey); a key names itself, tamper-evident
	AgentID    shared.ID         // the canonical enrolled agent this key is bound to (#606)
	Algorithm  string            // SigningAlgorithm
	Purpose    SigningPurpose    // the one content stream this key may sign
	PublicKey  ed25519.PublicKey // raw 32-byte ed25519 public key
	NotBefore  time.Time         // key is not usable before this instant
	NotAfter   time.Time         // key is not usable at/after this instant (bounded — supports rotation)
	RevokedAt  time.Time         // zero = not revoked; a set value fails the key closed from that instant
	ReplacedBy string            // KeyID of the successor minted to rotate this key out; "" if none
}

// NewSigningKey mints a signing key from a public key and a validity window, deriving the KeyID from the
// key itself so KeyID and PublicKey can never disagree. It validates the algorithm, purpose, key size,
// and that the window is a real bounded interval (NotBefore < NotAfter) — an unbounded key defeats
// rotation and anti-rollback. Revocation and ReplacedBy are set later, through the lifecycle, not here.
func NewSigningKey(agentID shared.ID, purpose SigningPurpose, pub ed25519.PublicKey, notBefore, notAfter time.Time) (AgentSigningKey, error) {
	if agentID == "" {
		return AgentSigningKey{}, fmt.Errorf("%w: signing key must be bound to a canonical agent id", shared.ErrValidation)
	}
	if !purpose.Valid() {
		return AgentSigningKey{}, fmt.Errorf("%w: unknown signing purpose %q", shared.ErrValidation, purpose)
	}
	if len(pub) != ed25519.PublicKeySize {
		return AgentSigningKey{}, fmt.Errorf("%w: signing public key must be %d bytes, got %d", shared.ErrValidation, ed25519.PublicKeySize, len(pub))
	}
	if notBefore.IsZero() || notAfter.IsZero() {
		return AgentSigningKey{}, fmt.Errorf("%w: signing key must carry a validity window", shared.ErrValidation)
	}
	if !notBefore.Before(notAfter) {
		return AgentSigningKey{}, fmt.Errorf("%w: signing key NotBefore must precede NotAfter", shared.ErrValidation)
	}
	cp := append(ed25519.PublicKey(nil), pub...) // defensive copy: caller's slice can't mutate the key
	return AgentSigningKey{
		KeyID:     evidence.KeyFingerprint(cp),
		AgentID:   agentID,
		Algorithm: SigningAlgorithm,
		Purpose:   purpose,
		PublicKey: cp,
		NotBefore: notBefore.UTC(),
		NotAfter:  notAfter.UTC(),
	}, nil
}

// Validate checks a stored key is internally consistent — the same invariants NewSigningKey enforces,
// re-asserted after a round-trip through storage so a corrupted or hand-built row is rejected, plus the
// KeyID↔PublicKey binding (a row whose KeyID does not fingerprint its stored key is refused).
func (k AgentSigningKey) Validate() error {
	if k.AgentID == "" {
		return fmt.Errorf("%w: signing key has no agent id", shared.ErrValidation)
	}
	if k.Algorithm != SigningAlgorithm {
		return fmt.Errorf("%w: unsupported signing algorithm %q", shared.ErrValidation, k.Algorithm)
	}
	if !k.Purpose.Valid() {
		return fmt.Errorf("%w: unknown signing purpose %q", shared.ErrValidation, k.Purpose)
	}
	if len(k.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: signing public key must be %d bytes", shared.ErrValidation, ed25519.PublicKeySize)
	}
	if k.KeyID == "" || k.KeyID != evidence.KeyFingerprint(k.PublicKey) {
		return fmt.Errorf("%w: signing key id does not match its public key", shared.ErrValidation)
	}
	if k.NotBefore.IsZero() || k.NotAfter.IsZero() || !k.NotBefore.Before(k.NotAfter) {
		return fmt.Errorf("%w: signing key has an invalid validity window", shared.ErrValidation)
	}
	if !k.RevokedAt.IsZero() && k.RevokedAt.Before(k.NotBefore) {
		return fmt.Errorf("%w: signing key cannot be revoked before it is valid", shared.ErrValidation)
	}
	return nil
}

// SameIdentity reports whether o is the same registration as k by its IMMUTABLE fields only — key id,
// agent, purpose, algorithm, public key, and window — NOT its lifecycle state (RevokedAt/ReplacedBy). A
// store uses it to make Register idempotent (a duplicate is a no-op) while refusing an attempt to
// re-point an existing KeyID at different attributes (anti-rollback → conflict).
func (k AgentSigningKey) SameIdentity(o AgentSigningKey) bool {
	return k.KeyID == o.KeyID &&
		k.AgentID == o.AgentID &&
		k.Purpose == o.Purpose &&
		k.Algorithm == o.Algorithm &&
		k.NotBefore.Equal(o.NotBefore) &&
		k.NotAfter.Equal(o.NotAfter) &&
		bytes.Equal(k.PublicKey, o.PublicKey)
}

// StatusAt derives the lifecycle state at now. Revocation takes precedence over the window: a key revoked
// while still inside its window is Revoked, not Active, from RevokedAt onward.
func (k AgentSigningKey) StatusAt(now time.Time) KeyStatus {
	if !k.RevokedAt.IsZero() && !now.Before(k.RevokedAt) {
		return KeyRevoked
	}
	if now.Before(k.NotBefore) {
		return KeyPending
	}
	if !now.Before(k.NotAfter) {
		return KeyExpired
	}
	return KeyActive
}

// UsableAt fails closed: it returns nil ONLY when the key is Active at now, and otherwise a validation
// error naming why (pending / expired / revoked). Verification paths gate on this before trusting a
// signature, so a rotated-out or revoked key can never admit a payload.
func (k AgentSigningKey) UsableAt(now time.Time) error {
	switch k.StatusAt(now) {
	case KeyActive:
		return nil
	case KeyPending:
		return fmt.Errorf("%w: signing key %s is not yet valid", shared.ErrForbidden, k.KeyID)
	case KeyExpired:
		return fmt.Errorf("%w: signing key %s has expired", shared.ErrForbidden, k.KeyID)
	case KeyRevoked:
		return fmt.Errorf("%w: signing key %s is revoked", shared.ErrForbidden, k.KeyID)
	default:
		return fmt.Errorf("%w: signing key %s is not usable", shared.ErrForbidden, k.KeyID)
	}
}

// KeyBindingMessage is the canonical proof-of-possession challenge an agent signs when it registers a
// key: the context tag plus every field that binds the key to its identity — agent, key id, purpose,
// algorithm, and window. Signing it with the key's private half proves possession AND commits to the
// binding, so the server cannot be tricked into registering a public key its holder did not intend for
// this agent/purpose. Field boundaries are separated so they cannot collide.
func KeyBindingMessage(k AgentSigningKey) []byte {
	fields := []string{
		keyBindingContext,
		k.AgentID.String(),
		k.KeyID,
		string(k.Purpose),
		k.Algorithm,
		strconvUnix(k.NotBefore),
		strconvUnix(k.NotAfter),
	}
	return hashFields(fields)
}

// ProveKeyPossession produces the base64 proof an agent presents at registration: an ed25519 signature
// over KeyBindingMessage with the key's PRIVATE half. The public half is what gets registered.
func ProveKeyPossession(priv ed25519.PrivateKey, k AgentSigningKey) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, KeyBindingMessage(k)))
}

// VerifyKeyPossession checks a registration proof fail-closed: the key must be internally valid (which
// re-asserts KeyID == fingerprint(PublicKey)), and the proof must be a well-formed ed25519 signature over
// the binding message BY THE KEY'S OWN PUBLIC HALF. A holder who does not possess the private key, or who
// signed a different binding, cannot register the key.
func VerifyKeyPossession(k AgentSigningKey, proofB64 string) error {
	if err := k.Validate(); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(proofB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed key-possession proof", shared.ErrValidation)
	}
	if !ed25519.Verify(k.PublicKey, KeyBindingMessage(k), sig) {
		return fmt.Errorf("%w: key-possession proof does not verify for this key", shared.ErrValidation)
	}
	return nil
}

// VerifyBatchWithKey is the server-side gate that admits a signed batch under the keyed lifecycle. It
// fails closed on every mismatch, in order: wrong purpose (a key for another stream), a key not bound to
// the batch's agent, an envelope naming a different KeyID than the resolved key, a key that is not usable
// at now (pending/expired/revoked), and finally a bad signature. Only a key that passes all of these
// verifies the batch, so no rotated-out, cross-purpose, or misattributed key can admit a detection.
func VerifyBatchWithKey(k AgentSigningKey, wantPurpose SigningPurpose, now time.Time, b AgentBatch) error {
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
	return VerifyBatch(k.PublicKey, b)
}

// ActiveKeyFor selects the key to sign with at now among a ring for one purpose: the Active key with the
// latest NotBefore (so during a rotation OVERLAP the newest usable key is chosen while the older one
// still verifies inbound traffic). It returns false if no key is currently usable for that purpose.
func ActiveKeyFor(ring []AgentSigningKey, purpose SigningPurpose, now time.Time) (AgentSigningKey, bool) {
	usable := make([]AgentSigningKey, 0, len(ring))
	for _, k := range ring {
		if k.Purpose == purpose && k.UsableAt(now) == nil {
			usable = append(usable, k)
		}
	}
	if len(usable) == 0 {
		return AgentSigningKey{}, false
	}
	sort.Slice(usable, func(i, j int) bool { return usable[i].NotBefore.After(usable[j].NotBefore) })
	return usable[0], true
}

// strconvUnix renders an instant as whole-second Unix time. Whole seconds (not nanos) keep the binding
// message reproducible across a Postgres round-trip, whose timestamptz truncates below microseconds.
func strconvUnix(t time.Time) string { return strconv.FormatInt(t.UTC().Unix(), 10) }

// hashFields digests a canonical, separator-delimited field list, so distinct field layouts cannot
// collide into the same message. It mirrors BatchMessage's construction (same separator).
func hashFields(fields []string) []byte {
	h := sha256.New()
	for _, f := range fields {
		h.Write([]byte(f))
		h.Write([]byte(batchSep))
	}
	return h.Sum(nil)
}
