package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// AgentSigningKeyStore persists the agent content-signing key lifecycle (#607, A0.2): the public halves
// of the keys an agent uses to sign telemetry/detection/response payloads, with their validity windows
// and revocation. Tenant scoping is enforced in the implementation from the context tenant (the same
// chokepoint the other fleet stores use), never by the caller.
//
// The store is the durable backing for the verify path: given the KeyID an incoming envelope names, the
// control plane resolves the bound public key and decides — fail-closed — whether it may admit the
// payload. Registration and revocation are append-only in spirit: a key's public half and window are
// immutable once written (provenance), and revocation is monotonic (anti-rollback).
type AgentSigningKeyStore interface {
	// Register stores a newly registered signing key under the context tenant. It is idempotent on the
	// KeyID: re-registering the identical key (same agent, purpose, public key, window) is a no-op, so an
	// at-least-once registration transport cannot create duplicates. A KeyID that already exists bound to
	// a DIFFERENT key/agent/purpose/window is refused with shared.ErrConflict — a KeyID (a public-key
	// fingerprint) can never be re-pointed at another key (anti-rollback).
	//
	// CONTRACT: Register only checks the key is internally valid; it does NOT verify proof-of-possession.
	// The caller (the A4 agent-plane registration handler) MUST first call
	// fleetagent.VerifyKeyPossession(key, proof) so an agent cannot register a public key whose private
	// half it does not hold, or bind a key to an agent/purpose it did not commit to. Persisting a key
	// without that check would let an unverified public key later admit signed payloads — fail open.
	Register(ctx context.Context, key fleetagent.AgentSigningKey) error
	// ResolveSigningKey returns the key with keyID that is bound to agentID, under the context tenant. It
	// returns shared.ErrNotFound when no such key exists — the verify path treats that as fail-closed (an
	// unknown key admits nothing). The name matches the detectledger consumer interface so a store value
	// satisfies it directly.
	ResolveSigningKey(ctx context.Context, agentID shared.ID, keyID string) (fleetagent.AgentSigningKey, error)
	// ListByAgent returns every signing key (any lifecycle state) for an agent, newest NotBefore first,
	// under the context tenant — for rotation/audit views and for selecting the active signer.
	ListByAgent(ctx context.Context, agentID shared.ID) ([]fleetagent.AgentSigningKey, error)
	// Revoke marks the (agentID, keyID) key revoked as of `at`, under the context tenant. It is monotonic:
	// once revoked, a later call never moves RevokedAt (a revocation cannot be walked back or forward —
	// anti-rollback). It returns shared.ErrNotFound when the key is unknown.
	Revoke(ctx context.Context, agentID shared.ID, keyID string, at time.Time) error
}
