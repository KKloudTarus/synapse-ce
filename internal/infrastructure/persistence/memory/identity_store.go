package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// IdentityStore is a race-safe in-memory ports.IdentityStore for development and tests.
type IdentityStore struct {
	mu                    sync.RWMutex
	authorizationMu       sync.Mutex
	authorizationCapacity int
	users                 ports.UserRepository
	identitiesByKey       map[string]identity.ExternalIdentity
	transactions          map[string]identity.AuthorizationTransaction
	sessionsByID          map[shared.ID]identity.Session
	sessionIDsByHash      map[string]shared.ID
}

// NewIdentityStore returns an empty store linked to the supplied user repository.
func NewIdentityStore(users ports.UserRepository) (*IdentityStore, error) {
	if users == nil {
		return nil, fmt.Errorf("%w: identity store requires user repository", shared.ErrValidation)
	}
	return &IdentityStore{
		users: users, authorizationCapacity: 256, identitiesByKey: make(map[string]identity.ExternalIdentity),
		transactions: make(map[string]identity.AuthorizationTransaction), sessionsByID: make(map[shared.ID]identity.Session), sessionIDsByHash: make(map[string]shared.ID),
	}, nil
}

var (
	_ ports.IdentityStore                 = (*IdentityStore)(nil)
	_ ports.ExternalIdentitySessionIssuer = (*IdentityStore)(nil)
)

func (s *IdentityStore) CreateExternalIdentity(ctx context.Context, external identity.ExternalIdentity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// The user lookup is tenant-scoped, so a user that does not exist and a user that belongs to
	// another tenant are one case here – which is exactly how PostgreSQL answers, where both violate
	// the (user_id, tenant_id) foreign key and surface as forbidden.
	u, err := s.users.GetByID(ctx, external.TenantID, external.UserID)
	if err != nil {
		return fmt.Errorf("identity user %s tenant link is invalid: %w", external.UserID, shared.ErrForbidden)
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
	// Inside a tenant transaction the link is undone if the enclosing unit (its audit record
	// included) fails, matching the PostgreSQL store.
	registerTenantRollback(ctx, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.identitiesByKey, key)
	})
	return nil
}

// DeleteExternalIdentity removes one approved link of a user. Inside a tenant transaction the link
// is restored if the enclosing unit fails, matching the PostgreSQL store.
func (s *IdentityStore) DeleteExternalIdentity(ctx context.Context, tenantID, userID, linkID shared.ID) (identity.ExternalIdentity, error) {
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return identity.ExternalIdentity{}, err
	}
	if tenantID.IsZero() || userID.IsZero() || linkID.IsZero() {
		return identity.ExternalIdentity{}, fmt.Errorf("%w: identity link tenant, user and id are required", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, external := range s.identitiesByKey {
		if external.ID != linkID || external.TenantID != tenantID || external.UserID != userID {
			continue
		}
		delete(s.identitiesByKey, key)
		registerTenantRollback(ctx, func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.identitiesByKey[key] = external
		})
		return external, nil
	}
	return identity.ExternalIdentity{}, fmt.Errorf("identity link %s: %w", linkID, shared.ErrNotFound)
}

// ListExternalIdentities returns one user's approved issuer/subject links, oldest first.
func (s *IdentityStore) ListExternalIdentities(ctx context.Context, tenantID, userID shared.ID) ([]identity.ExternalIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenantID.IsZero() || userID.IsZero() {
		return nil, fmt.Errorf("%w: identity link tenant and user are required", shared.ErrValidation)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []identity.ExternalIdentity
	for _, external := range s.identitiesByKey {
		if external.TenantID == tenantID && external.UserID == userID {
			out = append(out, external)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// RevokeUserSessions terminally revokes every unrevoked session of one user.
func (s *IdentityStore) RevokeUserSessions(ctx context.Context, tenantID, userID shared.ID, now time.Time) (int, error) {
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if tenantID.IsZero() || userID.IsZero() {
		return 0, fmt.Errorf("%w: session revocation tenant and user are required", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var previous []identity.Session
	for id, session := range s.sessionsByID {
		if session.TenantID != tenantID || session.UserID != userID || session.RevokedAt != nil {
			continue
		}
		previous = append(previous, session)
		session.Revoke(now)
		s.sessionsByID[id] = session
	}
	if len(previous) > 0 {
		registerTenantRollback(ctx, func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			for _, session := range previous {
				s.sessionsByID[session.ID] = session
			}
		})
	}
	return len(previous), nil
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
	for stateHash, existing := range s.transactions {
		if !existing.Usable(transaction.CreatedAt) {
			delete(s.transactions, stateHash)
		}
	}
	if s.authorizationCapacity <= 0 {
		return shared.ErrSaturated
	}
	for len(s.transactions) >= s.authorizationCapacity {
		var oldestStateHash string
		var oldest identity.AuthorizationTransaction
		for stateHash, existing := range s.transactions {
			if oldestStateHash == "" || existing.CreatedAt.Before(oldest.CreatedAt) || (existing.CreatedAt.Equal(oldest.CreatedAt) && stateHash < oldestStateHash) {
				oldestStateHash, oldest = stateHash, existing
			}
		}
		delete(s.transactions, oldestStateHash)
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
	u, err := s.users.GetByID(ctx, session.TenantID, session.UserID)
	if err != nil {
		return fmt.Errorf("session user %s tenant link is invalid: %w", session.UserID, shared.ErrForbidden)
	}
	if shared.TenantOrDefault(shared.ID(u.TenantID)) != session.TenantID {
		return fmt.Errorf("session user %s tenant: %w", session.UserID, shared.ErrForbidden)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createSessionLocked(session)
}

func (s *IdentityStore) CreateSessionForExternalIdentity(ctx context.Context, issuer, subject string, approvedUserUpdatedAt time.Time, session identity.Session) error {
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if session.TenantID.IsZero() || session.UserID.IsZero() || issuer == "" || subject == "" || approvedUserUpdatedAt.IsZero() {
		return fmt.Errorf("%w: OIDC session tenant, user, issuer, subject and approval version are required", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	external, ok := s.identitiesByKey[issuer+"\x00"+subject]
	if !ok || external.TenantID != session.TenantID || external.UserID != session.UserID {
		return shared.ErrNotFound
	}
	u, err := s.users.GetByID(ctx, session.TenantID, session.UserID)
	if err != nil || u.Disabled || !u.Role.Valid() || u.ID.String() == "operator" || !u.Audit.UpdatedAt.Equal(approvedUserUpdatedAt) {
		return shared.ErrNotFound
	}
	return s.createSessionLocked(session)
}

func (s *IdentityStore) createSessionLocked(session identity.Session) error {
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
	u, err := s.users.GetByID(ctx, replacement.TenantID, replacement.UserID)
	if err != nil {
		return fmt.Errorf("replacement session user %s tenant link is invalid: %w", replacement.UserID, shared.ErrForbidden)
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
