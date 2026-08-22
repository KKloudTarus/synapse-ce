// Package keyregistry is the control-plane side of the agent signing-key lifecycle (#607, A0.2): an
// enrolled agent registers its Ed25519 signing public key together with a proof-of-possession bound to
// its canonical AgentID; operators list and revoke keys. It is the wire front for
// ports.AgentSigningKeyStore — the store enforces idempotency, anti-rollback, and monotonic revoke; this
// service enforces that a key is only registered after its possession is proven (the port doc mandates
// the caller verify PoP; this is that caller) and that every mutation is audited.
package keyregistry

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// MaxSigningKeyValidity caps the validity window an agent may self-register for a signing key. Without a
// ceiling an agent could mint a key valid for decades, defeating rotation: a later private-key compromise
// would then rely solely on a manual operator revoke to close. One year is a safe upper bound that still
// leaves normal rotation comfortable; operators tighten it out-of-band. Rejecting a longer window is
// fail-closed (a shorter one is always allowed).
const MaxSigningKeyValidity = 365 * 24 * time.Hour

// Service registers, lists, and revokes agent signing keys.
type Service struct {
	keys  ports.AgentSigningKeyStore
	audit ports.AuditLogger
	clock ports.Clock
}

// NewService validates and constructs the key-registry service.
func NewService(keys ports.AgentSigningKeyStore, audit ports.AuditLogger, clock ports.Clock) (*Service, error) {
	if keys == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: key registry needs a key store, audit log and clock", shared.ErrValidation)
	}
	return &Service{keys: keys, audit: audit, clock: clock}, nil
}

// RegisterRequest is an agent's signing-key enrolment: its Ed25519 public key (base64), the purpose the
// key is for, its validity window, and a base64 proof-of-possession (an Ed25519 signature over the key's
// binding message, produced with the matching private key).
type RegisterRequest struct {
	PublicKeyB64 string
	Purpose      string
	NotBefore    time.Time
	NotAfter     time.Time
	Proof        string
}

// Register verifies proof-of-possession and registers the key bound to the AUTHENTICATED agent. authAgentID
// comes from the agent-plane credential, never the wire: the key's binding message (and thus the PoP and
// the derived KeyID) is computed against authAgentID, so an agent can only ever register a key for itself —
// a proof made for another agent id will not verify. Registration is idempotent on identity; re-pointing an
// existing KeyID to a different key returns ErrConflict from the store (anti-rollback).
func (s *Service) Register(ctx context.Context, authAgentID shared.ID, req RegisterRequest) (fleetagent.AgentSigningKey, error) {
	if authAgentID.IsZero() {
		return fleetagent.AgentSigningKey{}, fmt.Errorf("%w: key registration requires an authenticated agent", shared.ErrForbidden)
	}
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.PublicKeyB64))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fleetagent.AgentSigningKey{}, fmt.Errorf("%w: signing public key must be base64 Ed25519 (%d bytes)", shared.ErrValidation, ed25519.PublicKeySize)
	}
	purpose := fleetagent.SigningPurpose(req.Purpose)
	if !purpose.Valid() {
		return fleetagent.AgentSigningKey{}, fmt.Errorf("%w: unknown signing-key purpose %q", shared.ErrValidation, req.Purpose)
	}
	key, err := fleetagent.NewSigningKey(authAgentID, purpose, ed25519.PublicKey(pub), req.NotBefore.UTC(), req.NotAfter.UTC())
	if err != nil {
		return fleetagent.AgentSigningKey{}, err
	}
	// Rotation hygiene: refuse an over-long validity window so a compromised key cannot linger for years.
	if key.NotAfter.Sub(key.NotBefore) > MaxSigningKeyValidity {
		s.record(ctx, authAgentID.String(), key.KeyID, "fleet.key.rejected", map[string]string{"reason": "validity_too_long", "purpose": string(purpose)})
		return fleetagent.AgentSigningKey{}, fmt.Errorf("%w: signing-key validity window exceeds the maximum of %s", shared.ErrValidation, MaxSigningKeyValidity)
	}
	// Proof-of-possession BEFORE Register (the store deliberately does not check it): the agent must hold
	// the private key for the public key it posts, bound to its own AgentID/purpose/window. Fail closed.
	if err := fleetagent.VerifyKeyPossession(key, req.Proof); err != nil {
		s.record(ctx, authAgentID.String(), key.KeyID, "fleet.key.rejected", map[string]string{"reason": "proof_invalid", "purpose": string(purpose)})
		return fleetagent.AgentSigningKey{}, fmt.Errorf("%w: signing-key possession proof did not verify: %v", shared.ErrForbidden, err)
	}
	if err := s.keys.Register(ctx, key); err != nil {
		return fleetagent.AgentSigningKey{}, fmt.Errorf("register signing key: %w", err)
	}
	s.record(ctx, authAgentID.String(), key.KeyID, "fleet.key.registered", map[string]string{
		"purpose": string(purpose), "not_before": key.NotBefore.Format(time.RFC3339), "not_after": key.NotAfter.Format(time.RFC3339),
	})
	return key, nil
}

// List returns the signing keys registered for an agent (operator read), tenant-scoped by the store.
func (s *Service) List(ctx context.Context, agentID shared.ID) ([]fleetagent.AgentSigningKey, error) {
	if agentID.IsZero() {
		return nil, fmt.Errorf("%w: list keys needs an agent id", shared.ErrValidation)
	}
	return s.keys.ListByAgent(ctx, agentID)
}

// Revoke marks a key revoked as of now (operator action, monotonic in the store). actor names the human
// operator for the audit trail; revoke without an attributable actor is refused.
func (s *Service) Revoke(ctx context.Context, agentID shared.ID, keyID, actor string) error {
	if agentID.IsZero() || strings.TrimSpace(keyID) == "" {
		return fmt.Errorf("%w: revoke needs an agent id and key id", shared.ErrValidation)
	}
	if strings.TrimSpace(actor) == "" {
		return fmt.Errorf("%w: revoke must name the operator", shared.ErrValidation)
	}
	if err := s.keys.Revoke(ctx, agentID, keyID, s.clock.Now().UTC()); err != nil {
		return fmt.Errorf("revoke signing key: %w", err)
	}
	s.record(ctx, actor, keyID, "fleet.key.revoked", map[string]string{"agent_id": agentID.String()})
	return nil
}

func (s *Service) record(ctx context.Context, actor, keyID, action string, meta map[string]string) {
	if meta == nil {
		meta = map[string]string{}
	}
	meta["key_id"] = keyID
	_ = s.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: action, Target: keyID, At: s.clock.Now().UTC(), Metadata: meta})
}
