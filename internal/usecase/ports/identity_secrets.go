package ports

import "context"

// IdentitySecretProtector encrypts short-lived PKCE verifiers before persistence. Implementations
// must authenticate ciphertext to the supplied associated data; plaintext never reaches a store.
type IdentitySecretProtector interface {
	Seal(ctx context.Context, plaintext, associatedData []byte) (string, error)
	Open(ctx context.Context, ciphertext string, associatedData []byte) ([]byte, error)
}
