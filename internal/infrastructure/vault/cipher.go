// Package vault is the credential store: per-engagement
// secrets encrypted at rest with AES-256-GCM under a master key that never touches the
// database, logs, or the LLM transcript. The plaintext is returned ONLY via Resolve at
// tool-execution time (the SandboxRunner substitutes it into the child's environment
// after the redacted spec has been audited + sealed). Everything else – listing, the
// API, logs – sees names only.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Cipher is an AES-256-GCM AEAD over the vault master key. The ciphertext is bound to
// the credential's identity via AAD (engagement+name), so a stored blob cannot be
// replayed under a different name/engagement even by someone with DB write access.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher builds the AEAD from a 32-byte master key (AES-256). The key is held only
// in memory and never logged.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: vault master key must be 32 bytes (AES-256)", shared.ErrValidation)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("vault cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault gcm: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// DecodeKey parses the master key from 64 hex chars or base64 of 32 bytes (the same
// shape as the evidence signing seed). Returns ErrValidation otherwise. Never log s.
func DecodeKey(s string) ([]byte, error) {
	if len(s) == 64 {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, fmt.Errorf("%w: vault master key must be 64 hex chars or base64 of 32 bytes", shared.ErrValidation)
}

// Seal encrypts plaintext, prepending a random nonce, and returns base64(nonce|ct). aad
// (associated data, e.g. engagement+name) is authenticated but not encrypted.
func (c *Cipher) Seal(plaintext, aad []byte) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("vault nonce: %w", err)
	}
	sealed := c.aead.Seal(nonce, nonce, plaintext, aad)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open reverses Seal. A wrong key, tampered ciphertext, or mismatched aad fails the GCM
// tag check and returns ErrValidation (never the plaintext).
func (c *Cipher) Open(encoded string, aad []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: vault ciphertext not base64", shared.ErrValidation)
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return nil, fmt.Errorf("%w: vault ciphertext too short", shared.ErrValidation)
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := c.aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: vault decrypt failed (key/aad/tamper)", shared.ErrValidation)
	}
	return pt, nil
}

// aad binds a ciphertext to its (engagement, name) identity.
func aad(engagementID shared.ID, name string) []byte {
	return []byte("synapse:cred:" + engagementID.String() + ":" + name)
}
