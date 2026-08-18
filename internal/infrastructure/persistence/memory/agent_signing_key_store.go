package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// skKey identifies a signing key by (agent, key id) within a tenant bucket — a KeyID is unique per agent
// (it fingerprints the agent's public key), and the pair is what the verify path resolves by.
type skKey struct {
	agent shared.ID
	keyID string
}

// AgentSigningKeyStore is the in-memory agent-signing-key registry used inline/in dev. Keys are bucketed
// per tenant, so a read under one tenant can never observe another's — the same isolation the Postgres
// store gets from RLS. It keeps deep copies so a caller mutating a returned key cannot corrupt stored
// state, and enforces the same immutability + monotonic-revocation invariants as the Postgres store.
type AgentSigningKeyStore struct {
	mu       sync.Mutex
	byTenant map[shared.ID]map[skKey]fleetagent.AgentSigningKey
}

var _ ports.AgentSigningKeyStore = (*AgentSigningKeyStore)(nil)

// NewAgentSigningKeyStore constructs the store.
func NewAgentSigningKeyStore() *AgentSigningKeyStore {
	return &AgentSigningKeyStore{byTenant: map[shared.ID]map[skKey]fleetagent.AgentSigningKey{}}
}

// Register stores a signing key, idempotent on its identity and anti-rollback on its KeyID. Like the
// Postgres store it does NOT verify proof-of-possession — see the port contract; the caller must have
// called fleetagent.VerifyKeyPossession first.
func (s *AgentSigningKeyStore) Register(ctx context.Context, key fleetagent.AgentSigningKey) error {
	if err := key.Validate(); err != nil {
		return err
	}
	// Fail closed on a missing tenant, matching the authoritative Postgres store (a security registry
	// must never silently bucket a key under a default tenant).
	tenant, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("%w: signing-key registration requires a tenant in context", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byTenant[tenant] == nil {
		s.byTenant[tenant] = map[skKey]fleetagent.AgentSigningKey{}
	}
	k := skKey{agent: key.AgentID, keyID: key.KeyID}
	if existing, ok := s.byTenant[tenant][k]; ok {
		// A KeyID (a public-key fingerprint) can never be re-pointed at a different key/agent/purpose/
		// window. An identical re-registration is a no-op (at-least-once safe); anything else conflicts.
		if !existing.SameIdentity(key) {
			return fmt.Errorf("%w: signing key %s already registered with different attributes", shared.ErrConflict, key.KeyID)
		}
		return nil
	}
	s.byTenant[tenant][k] = cloneSigningKey(key)
	return nil
}

// ResolveSigningKey returns the (agent, keyID) key under the ctx tenant, or ErrNotFound.
func (s *AgentSigningKeyStore) ResolveSigningKey(ctx context.Context, agentID shared.ID, keyID string) (fleetagent.AgentSigningKey, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok {
		return fleetagent.AgentSigningKey{}, fmt.Errorf("%w: signing-key resolution requires a tenant in context", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key, found := s.byTenant[tenant][skKey{agent: agentID, keyID: keyID}]
	if !found {
		return fleetagent.AgentSigningKey{}, fmt.Errorf("%w: signing key %s for agent %s", shared.ErrNotFound, keyID, agentID)
	}
	return cloneSigningKey(key), nil
}

// ListByAgent returns every key for an agent under the ctx tenant, newest NotBefore first.
func (s *AgentSigningKeyStore) ListByAgent(ctx context.Context, agentID shared.ID) ([]fleetagent.AgentSigningKey, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok {
		return nil, fmt.Errorf("%w: listing signing keys requires a tenant in context", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []fleetagent.AgentSigningKey
	for k, key := range s.byTenant[tenant] {
		if k.agent == agentID {
			out = append(out, cloneSigningKey(key))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NotBefore.Equal(out[j].NotBefore) {
			return out[i].KeyID < out[j].KeyID
		}
		return out[i].NotBefore.After(out[j].NotBefore)
	})
	return out, nil
}

// Revoke marks a key revoked at `at`, monotonic: an already-revoked key keeps its first RevokedAt.
func (s *AgentSigningKeyStore) Revoke(ctx context.Context, agentID shared.ID, keyID string, at time.Time) error {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("%w: revoking a signing key requires a tenant in context", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := skKey{agent: agentID, keyID: keyID}
	key, found := s.byTenant[tenant][k]
	if !found {
		return fmt.Errorf("%w: signing key %s for agent %s", shared.ErrNotFound, keyID, agentID)
	}
	if !key.RevokedAt.IsZero() {
		return nil // already revoked — revocation is monotonic, never moved
	}
	key.RevokedAt = at.UTC()
	s.byTenant[tenant][k] = key
	return nil
}

func cloneSigningKey(k fleetagent.AgentSigningKey) fleetagent.AgentSigningKey {
	cp := k
	cp.PublicKey = append([]byte(nil), k.PublicKey...)
	return cp
}
