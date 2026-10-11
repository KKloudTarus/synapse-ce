// Package seal adapts the vault cipher to SIEM payload and credential sealing.
package seal

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
)

// Vault seals with AES-256-GCM. The associated data binds the ciphertext to
// a tenant, sink, provider, and version so it cannot be replayed onto another sink.
type Vault struct{ Cipher *vault.Cipher }

// Seal encrypts plaintext.
func (v Vault) Seal(ctx context.Context, plaintext, aad []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return v.Cipher.Seal(plaintext, aad)
}

// Open decrypts ciphertext. A mismatched associated data fails closed.
func (v Vault) Open(ctx context.Context, ciphertext string, aad []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return v.Cipher.Open(ciphertext, aad)
}
