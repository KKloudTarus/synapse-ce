package oidc

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
)

// SecretProtector adapts the authenticated vault cipher for short-lived PKCE verifier storage.
type SecretProtector struct{ cipher *vault.Cipher }

func NewSecretProtector(cipher *vault.Cipher) *SecretProtector {
	return &SecretProtector{cipher: cipher}
}

func (p *SecretProtector) Seal(ctx context.Context, plaintext, aad []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return p.cipher.Seal(plaintext, aad)
}

func (p *SecretProtector) Open(ctx context.Context, ciphertext string, aad []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return p.cipher.Open(ciphertext, aad)
}
