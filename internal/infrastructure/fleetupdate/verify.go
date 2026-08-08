package fleetupdate

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Ed25519Verifier verifies a detached ed25519 signature over the artifact bytes using the project's
// published release public key. It is a real, dependency-free Verifier; the GPG/Authenticode
// pipeline-signing side (packaging) is separate — this is what the AGENT uses to gate a self-update.
type Ed25519Verifier struct {
	pub ed25519.PublicKey
}

var _ Verifier = (*Ed25519Verifier)(nil)

// NewEd25519Verifier builds a verifier from a hex-encoded 32-byte public key.
func NewEd25519Verifier(pubHex string) (*Ed25519Verifier, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(pubHex))
	if err != nil {
		return nil, fmt.Errorf("fleetupdate: decode release public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("fleetupdate: release public key must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return &Ed25519Verifier{pub: ed25519.PublicKey(raw)}, nil
}

// Verify reports nil when signature is a valid ed25519 signature over artifact under the release key.
func (v *Ed25519Verifier) Verify(artifact, signature []byte) error {
	if len(v.pub) != ed25519.PublicKeySize {
		return errors.New("fleetupdate: verifier has no valid release public key")
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("fleetupdate: signature must be %d bytes, got %d", ed25519.SignatureSize, len(signature))
	}
	if !ed25519.Verify(v.pub, artifact, signature) {
		return errors.New("fleetupdate: signature does not verify under the release key")
	}
	return nil
}
