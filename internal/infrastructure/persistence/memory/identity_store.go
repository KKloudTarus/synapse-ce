package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// IdentityStore is a race-safe in-memory ports.IdentityStore for development and tests.
type IdentityStore struct {
	mu               sync.RWMutex
	users            ports.UserRepository
	identitiesByKey  map[string]identity.ExternalIdentity
	transactions     map[string]identity.AuthorizationTransaction
	sessionsByID     map[shared.ID]identity.Session
	sessionIDsByHash map[string]shared.ID
}

// NewIdentityStore returns an empty store linked to the supplied user repository.
func NewIdentityStore(users ports.UserRepository) (*IdentityStore, error) {
	if users == nil {
		return nil, fmt.Errorf("%w: identity store requires user repository", shared.ErrValidation)
	}
	return &IdentityStore{
		users: users, identitiesByKey: make(map[string]identity.ExternalIdentity),
		transactions: make(map[string]identity.AuthorizationTransaction), sessionsByID: make(map[shared.ID]identity.Session), sessionIDsByHash: make(map[string]shared.ID),
	}, nil
}

var _ ports.IdentityStore = (*IdentityStore)(nil)

func (s *IdentityStore) CreateExternalIdentity(ctx context.Context, external identity.ExternalIdentity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	u, err := s.users.GetByID(ctx, external.UserID)
	if err != nil {
		return fmt.Errorf("identity user %s: %w", external.UserID, err)
	}
	if shared.TenantOrDefault(shared.ID(u.TenantID)) != external.TenantID {
		return fmt.Errorf("identity user %s tenant: %w", external.UserID, shared.ErrForbidden)
	}
	key := external.Issuer + "\x00" + external.Subject
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.identitiesByKey[key]; exists {
		return fmt.Errorf("identity issuer/subject already exists: %w", shared.ErrConflict)
	}
	s.identitiesByKey[key] = external
	return nil
}

func (s *IdentityStore) GetExternalIdentity(ctx context.Context, issuer, subject string) (identity.ExternalIdentity, error) {
	if err := ctx.Err(); err != nil {
		return identity.ExternalIdentity{}, err
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return identity.ExternalIdentity{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	external, ok := s.identitiesByKey[issuer+"\x00"+subject]
	if !ok || external.TenantID != tenantID {
		return identity.ExternalIdentity{}, shared.ErrNotFound
	}
	return external, nil
}

func (s *IdentityStore) CreateAuthorizationTransaction(ctx context.Context, transaction identity.AuthorizationTransaction) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.transactions[transaction.StateHash]; exists {
		return fmt.Errorf("authorization state already exists: %w", shared.ErrConflict)
	}
	s.transactions[transaction.StateHash] = transaction
	return nil
}

func (s *IdentityStore) ConsumeAuthorizationTransaction(ctx context.Context, tenantID shared.ID, stateHash string, now time.Time) (identity.AuthorizationTransaction, error) {
	if err := ctx.Err(); err != nil {
		return identity.AuthorizationTransaction{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	transaction, ok := s.transactions[stateHash]
	if !ok || transaction.TenantID != tenantID {
		return identity.AuthorizationTransaction{}, shared.ErrNotFound
	}
	if !transaction.Usable(now) {
		delete(s.transactions, stateHash) // expired records contain short-lived encrypted secret material.
		return identity.AuthorizationTransaction{}, shared.ErrNotFound
	}
	delete(s.transactions, stateHash) // deletion makes consumption one-time and does not retain short-lived secrets.
	return transaction, nil
}

func (s *IdentityStore) CreateSession(ctx context.Context, session identity.Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	u, err := s.users.GetByID(ctx, session.UserID)
	if err != nil {
		return fmt.Errorf("session user %s: %w", session.UserID, err)
	}
	if shared.TenantOrDefault(shared.ID(u.TenantID)) != session.TenantID {
		return fmt.Errorf("session user %s tenant: %w", session.UserID, shared.ErrForbidden)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sessionsByID[session.ID]; exists {
		return fmt.Errorf("session id already exists: %w", shared.ErrConflict)
	}
	if _, exists := s.sessionIDsByHash[session.TokenHash]; exists {
		return fmt.Errorf("session token already exists: %w", shared.ErrConflict)
	}
	s.sessionsByID[session.ID] = identity.CopySession(session)
	s.sessionIDsByHash[session.TokenHash] = session.ID
	return nil
}

// RotateSession creates replacement and revokes previous under one lock.
func (s *IdentityStore) RotateSession(ctx context.Context, previousSessionID shared.ID, replacement identity.Session, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	u, err := s.users.GetByID(ctx, replacement.UserID)
	if err != nil {
		return fmt.Errorf("replacement session user %s: %w", replacement.UserID, err)
	}
	if shared.TenantOrDefault(shared.ID(u.TenantID)) != replacement.TenantID {
		return fmt.Errorf("replacement session user %s tenant: %w", replacement.UserID, shared.ErrForbidden)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, ok := s.sessionsByID[previousSessionID]
	if !ok || previous.TenantID != replacement.TenantID || previous.UserID != replacement.UserID || !previous.Active(now) {
		return fmt.Errorf("previous session is not active: %w", shared.ErrConflict)
	}
	if _, exists := s.sessionsByID[replacement.ID]; exists {
		return fmt.Errorf("replacement session id already exists: %w", shared.ErrConflict)
	}
	if _, exists := s.sessionIDsByHash[replacement.TokenHash]; exists {
		return fmt.Errorf("replacement session token already exists: %w", shared.ErrConflict)
	}
	previous.Revoke(now)
	s.sessionsByID[previousSessionID] = previous
	s.sessionsByID[replacement.ID] = identity.CopySession(replacement)
	s.sessionIDsByHash[replacement.TokenHash] = replacement.ID
	return nil
}

func (s *IdentityStore) GetSessionByTokenHash(ctx context.Context, tokenHash string) (identity.Session, error) {
	if err := ctx.Err(); err != nil {
		return identity.Session{}, err
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return identity.Session{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.sessionIDsByHash[tokenHash]
	if !ok || s.sessionsByID[id].TenantID != tenantID {
		return identity.Session{}, shared.ErrNotFound
	}
	return identity.CopySession(s.sessionsByID[id]), nil
}

func (s *IdentityStore) RevokeSession(ctx context.Context, tenantID, sessionID shared.ID, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessionsByID[sessionID]
	if !ok || session.TenantID != tenantID {
		return shared.ErrNotFound
	}
	if session.RevokedAt != nil {
		return fmt.Errorf("session already revoked: %w", shared.ErrConflict)
	}
	session.Revoke(now)
	s.sessionsByID[sessionID] = session
	return nil
}
