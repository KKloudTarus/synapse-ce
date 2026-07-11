// Package evidence models tamper-evident, hash-chained records of what an
// engagement produced (scans, findings, reports). Each item's Hash covers its
// content AND the previous item's Hash, so any later edit, insertion, or removal
// breaks the chain – and the report path must refuse to proceed on a mismatch
// . This is the domain groundwork; persistence + wiring land
// with the evidence vault.
package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ErrChainBroken is returned when an evidence chain fails verification.
var ErrChainBroken = errors.New("evidence chain broken")

// ErrBadAttestation is returned when a chain-head signature fails verification.
var ErrBadAttestation = errors.New("evidence attestation invalid")

// Attestation context tags provide DOMAIN SEPARATION for the signed message: one
// ed25519 key signs both evidence and audit chain heads, so the signed bytes are
// prefixed with a per-chain tag. This makes an attestation self-describing about
// WHICH custody chain it covers and means an evidence-head signature can never be
// presented as an audit-head signature (and vice versa) even though both heads are
// 64-char hex sha256 strings. The `:v1` suffix lets the format evolve.
const (
	AttestationContextEvidence = "synapse-evidence-head:v1"
	AttestationContextAudit    = "synapse-audit-head:v1"
)

// attestSep separates the context tag from the head in the signed message; the unit
// separator cannot appear in a hex head or the ASCII context tag, so the encoding is
// unambiguous.
const attestSep = "\x1f"

// Attestation is a detached signature over a chain head: it proves WHICH key
// attested to that head (origin / non-repudiation) and, via Context, WHICH chain it
// covers, on top of the chain's integrity. ed25519 signatures are
// deterministic (RFC 8032), and only the (context-tagged) head is signed – so
// re-signing the same chain yields identical bytes, keeping the report
// byte-reproducible. Verification needs only the public key, so it is
// a pure function here; only signing needs the private key (a port).
type Attestation struct {
	Algorithm string `json:"algorithm"`         // "ed25519"
	KeyID     string `json:"key_id"`            // short fingerprint of the public key (sha256 prefix)
	PublicKey string `json:"public_key"`        // base64-std of the 32-byte ed25519 public key
	Context   string `json:"context,omitempty"` // domain-separation tag (e.g. AttestationContextAudit); empty = legacy bare-head
	Head      string `json:"head"`              // the chain head hash that was signed
	Signature string `json:"signature"`         // base64-std of the 64-byte signature
}

// AttestationMessage builds the exact bytes that are signed/verified for a chain
// head under a context. An empty context reproduces the legacy bare-head message so
// attestations minted before domain separation still verify; a non-empty context
// binds the signature to that chain kind. Sign and VerifyAttestation MUST agree by
// going through this one function.
func AttestationMessage(context, head string) []byte {
	if context == "" {
		return []byte(head)
	}
	return []byte(context + attestSep + head)
}

// KeyFingerprint returns a short, stable id for an ed25519 public key (first 16 hex
// chars of its sha256) – used as the attestation KeyID and to pin a signer.
func KeyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// VerifyAttestation checks that att is a well-formed ed25519 signature over its
// context-tagged head by att.PublicKey, and that the embedded KeyID matches that key.
// It does NOT decide whether the key is trusted, nor whether the Context is the one
// the caller expected – those are the verifier's policy (pin a known key; assert the
// context for your chain). Returns ErrBadAttestation on any failure.
func VerifyAttestation(att Attestation) error {
	if att.Algorithm != "ed25519" {
		return fmt.Errorf("%w: unsupported algorithm %q", ErrBadAttestation, att.Algorithm)
	}
	pub, err := base64.StdEncoding.DecodeString(att.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: malformed public key", ErrBadAttestation)
	}
	sig, err := base64.StdEncoding.DecodeString(att.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed signature", ErrBadAttestation)
	}
	if KeyFingerprint(pub) != att.KeyID {
		return fmt.Errorf("%w: key_id does not match the public key", ErrBadAttestation)
	}
	if !ed25519.Verify(pub, AttestationMessage(att.Context, att.Head), sig) {
		return fmt.Errorf("%w: signature does not verify for this head", ErrBadAttestation)
	}
	return nil
}

// Evidence is one link in an engagement's append-only hash chain.
type Evidence struct {
	ID           shared.ID
	EngagementID shared.ID
	FindingID    shared.ID // optional link to the finding this evidence supports
	Kind         string    // e.g. "scan", "finding", "report"
	Content      []byte    // the sealed payload (or a digest of it)
	StorageRef   string    // optional content-addressed blob key (sha256) for an out-of-line artifact; the same hash is also inside Content, so the blob is chain-protected
	Hash         string    // hex sha256 binding previous_hash + attribution + metadata + content
	PreviousHash string    // the prior item's Hash; empty for the first link
	CreatedBy    string    // human/agent id that produced this evidence (attribution)
	CreatedAt    time.Time
}

// evSep separates fields in the hash preimage so distinct field boundaries can't collide.
const evSep = "\x1e"

// ComputeHash returns the chain hash binding an evidence link to its predecessor. It binds
// not just previous_hash + content but ALSO the attribution + metadata (kind, finding_id,
// storage_ref, created_by, created_at) – so a rewrite of WHO produced the evidence or WHEN
// is detected by VerifyChain, not just a content edit. The timestamp is
// truncated to µs (matching Postgres timestamptz) so the hash is stable across a DB
// round-trip. Including previous_hash links the chain: any earlier change cascades.
func ComputeHash(e Evidence) string {
	h := sha256.New()
	write := func(s string) { h.Write([]byte(s)); h.Write([]byte(evSep)) }
	write(e.PreviousHash)
	write(e.Kind)
	write(e.FindingID.String())
	write(e.StorageRef)
	write(e.CreatedBy)
	write(e.CreatedAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano))
	h.Write(e.Content)
	return hex.EncodeToString(h.Sum(nil))
}

// Seal returns a copy of e with Hash computed from its chained fields.
func (e Evidence) Seal() Evidence {
	e.Hash = ComputeHash(e)
	return e
}

// VerifyChain checks that items form an unbroken hash chain in order: each item's
// PreviousHash equals the prior item's Hash, and each Hash recomputes from its
// own content + previous hash. It returns ErrChainBroken at the first break.
func VerifyChain(items []Evidence) error {
	prev := ""
	for i, e := range items {
		if e.PreviousHash != prev {
			return fmt.Errorf("%w: item %d previous_hash does not match the prior item", ErrChainBroken, i)
		}
		if e.Hash != ComputeHash(e) {
			return fmt.Errorf("%w: item %d hash does not match its content/attribution (tampered)", ErrChainBroken, i)
		}
		prev = e.Hash
	}
	return nil
}
