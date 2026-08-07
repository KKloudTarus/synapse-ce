// Package worksign is the platform adapter that signs and verifies fleet work order payloads with
// an HMAC-SHA256 keyed MAC. It holds the key so the key material never reaches the domain or the
// use case, which depend only on the ports.WorkOrderSigner interface.
package worksign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// Signer is an HMAC-SHA256 work order signer.
type Signer struct {
	key []byte
}

// New returns a Signer keyed with key. The caller supplies the key from the credential vault or
// configuration; it is never logged.
func New(key []byte) *Signer {
	// Copy so the caller cannot mutate the key after construction.
	k := make([]byte, len(key))
	copy(k, key)
	return &Signer{key: k}
}

// Sign returns the base64 HMAC-SHA256 of payload.
func (s *Signer) Sign(payload string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(payload))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// Verify reports whether signature is a valid MAC for payload, in constant time.
func (s *Signer) Verify(payload, signature string) bool {
	expected := s.Sign(payload)
	return hmac.Equal([]byte(signature), []byte(expected))
}
