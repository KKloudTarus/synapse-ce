package identity

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestAuthorizationTransactionUsable(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	transaction, err := NewAuthorizationTransaction("tx", "tenant", "state-hash", "nonce-hash", "encrypted-verifier", now.Add(time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	if !transaction.Usable(now) {
		t.Fatal("fresh authorization transaction must be usable")
	}
	transaction.ConsumedAt = &now
	if transaction.Usable(now) {
		t.Fatal("consumed authorization transaction must not be usable")
	}
	if _, err := NewAuthorizationTransaction("tx", "tenant", "state", "nonce", "ciphertext", now, now); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expiry at creation must be invalid, got %v", err)
	}
}

func TestSessionLifecycleAndMetadata(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	session, err := NewSession("session", "tenant", "user", "token-hash", "csrf-hash", map[string]string{"ip": "127.0.0.1"}, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if !session.Active(now) {
		t.Fatal("new session must be active")
	}
	session.Revoke(now.Add(time.Second))
	if session.Active(now.Add(time.Second)) || session.RevokedAt == nil {
		t.Fatalf("revoked session must be inactive: %+v", session)
	}
	copy := CopySession(session)
	copy.Metadata["ip"] = "changed"
	if session.Metadata["ip"] != "127.0.0.1" {
		t.Fatal("copy must not share mutable metadata")
	}
}

func TestExternalIdentityRequiresTenantScopedUser(t *testing.T) {
	_, err := NewExternalIdentity("identity", "", "user", "https://issuer", "subject", time.Now())
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty tenant must be rejected, got %v", err)
	}
}
