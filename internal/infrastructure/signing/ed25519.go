// Package signing implements ports.ChainSigner with ed25519: it attests to an
// evidence chain head so a custody chain proves origin (non-repudiation), not just
// integrity. ed25519 signatures are deterministic
// (RFC 8032), so signing the same head with the same key is byte-reproducible –
// the report path stays reproducible. Verification lives in the
// domain (evidence.VerifyAttestation); only signing needs the private key.
package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Ed25519Signer signs chain heads with a fixed ed25519 key under a domain-separation
// context (so one key can safely attest both evidence and audit heads).
type Ed25519Signer struct {
	priv      ed25519.PrivateKey
	publicB64 string
	keyID     string
	ephemeral bool
	context   string // domain-separation tag baked into every signed message
}

var _ ports.ChainSigner = (*Ed25519Signer)(nil)

// WithContext returns a sibling signer that shares this key but signs under a
// different domain-separation context (e.g. evidence vs audit heads). The private key
// is shared by value; the copy is otherwise independent.
func (s *Ed25519Signer) WithContext(context string) *Ed25519Signer {
	c := *s
	c.context = context
	return &c
}

// NewEd25519Signer builds a signer from a 32-byte seed (a stable key, so the same
// instance always attests under the same key id). If seed is empty, a random key is
// generated and the signer is marked Ephemeral – attestations still self-verify (the
// public key travels with them), but the key id is not stable across restarts; the
// caller should log a warning and an operator should configure a seed in production.
func NewEd25519Signer(seed []byte) (*Ed25519Signer, error) {
	var priv ed25519.PrivateKey
	ephemeral := false
	switch len(seed) {
	case 0:
		_, p, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate signing key: %w", err)
		}
		priv = p
		ephemeral = true
	case ed25519.SeedSize:
		priv = ed25519.NewKeyFromSeed(seed)
	default:
		return nil, fmt.Errorf("%w: signing seed must be %d bytes, got %d", shared.ErrValidation, ed25519.SeedSize, len(seed))
	}
	pub := priv.Public().(ed25519.PublicKey)
	return &Ed25519Signer{
		priv:      priv,
		publicB64: base64.StdEncoding.EncodeToString(pub),
		keyID:     evidence.KeyFingerprint(pub),
		ephemeral: ephemeral,
	}, nil
}

// Sign returns a deterministic ed25519 attestation over the context-tagged head.
func (s *Ed25519Signer) Sign(_ context.Context, head string) (evidence.Attestation, error) {
	if head == "" {
		return evidence.Attestation{}, fmt.Errorf("%w: cannot attest an empty chain head", shared.ErrValidation)
	}
	sig := ed25519.Sign(s.priv, evidence.AttestationMessage(s.context, head))
	return evidence.Attestation{
		Algorithm: "ed25519",
		KeyID:     s.keyID,
		PublicKey: s.publicB64,
		Context:   s.context,
		Head:      head,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// PublicKey is the base64-std raw ed25519 public key.
func (s *Ed25519Signer) PublicKey() string { return s.publicB64 }

// KeyID is the short fingerprint of the public key.
func (s *Ed25519Signer) KeyID() string { return s.keyID }

// Ephemeral reports whether this signer uses a generated (non-persisted) key.
func (s *Ed25519Signer) Ephemeral() bool { return s.ephemeral }

// DecodeSeed parses a signing seed from operator config, accepting either 64 hex
// chars or base64-std (both decoding to 32 bytes). An empty string yields a nil
// seed (an ephemeral key). It never logs the seed.
func DecodeSeed(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if len(s) == ed25519.SeedSize*2 {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: signing seed must be 64 hex chars or base64 of 32 bytes", shared.ErrValidation)
	}
	return b, nil
}
