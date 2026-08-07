// Package agenttoken mints and parses fleet agent credentials. A credential is opaque to the agent
// but carries a routable, non-secret prefix so the server can resolve the tenant (and agent) before
// a Row-Level-Security lookup, then verify the secret by a constant-time hash comparison. Only the
// hash of the secret is ever stored; the plaintext is shown once at creation.
//
// Format: "<kind>.<b64url(tenantID)>.<b64url(id)>.<b64url(secret)>". For an enrolment token id is
// empty. The tenant/id parts are NOT secret (they just route the lookup); forging them fails the
// hash comparison because the attacker cannot produce the matching secret.
package agenttoken

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Kinds of credential.
const (
	KindEnrol = "et" // single-use enrolment token
	KindAgent = "fa" // long-lived agent bearer credential
)

const secretBytes = 32

var enc = base64.RawURLEncoding

// Mint generates a credential of the given kind for (tenantID, id) and returns the full plaintext
// token plus the hash of its secret to store. id may be empty (enrolment tokens).
func Mint(kind, tenantID, id string) (token, secretHash string, err error) {
	if kind != KindEnrol && kind != KindAgent {
		return "", "", fmt.Errorf("agenttoken: unknown kind %q", kind)
	}
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("agenttoken: generate secret: %w", err)
	}
	secret := enc.EncodeToString(b)
	token = strings.Join([]string{kind, enc.EncodeToString([]byte(tenantID)), enc.EncodeToString([]byte(id)), secret}, ".")
	return token, Hash(secret), nil
}

// Parse decodes a token into its parts. ok is false for any malformed token.
func Parse(token string) (kind, tenantID, id, secret string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return "", "", "", "", false
	}
	if parts[0] != KindEnrol && parts[0] != KindAgent {
		return "", "", "", "", false
	}
	tb, err1 := enc.DecodeString(parts[1])
	ib, err2 := enc.DecodeString(parts[2])
	if err1 != nil || err2 != nil || parts[3] == "" {
		return "", "", "", "", false
	}
	return parts[0], string(tb), string(ib), parts[3], true
}

// B64 encodes a routable (non-secret) token part with the same alphabet Mint uses. Exposed so
// callers and tests can construct or inspect the tenant/id parts of a token.
func B64(s string) string { return enc.EncodeToString([]byte(s)) }

// Hash returns the hex SHA-256 of a secret. The stored hash is compared against this.
func Hash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// Equal reports whether secret hashes to storedHash, in constant time.
func Equal(secret, storedHash string) bool {
	return subtle.ConstantTimeCompare([]byte(Hash(secret)), []byte(storedHash)) == 1
}
