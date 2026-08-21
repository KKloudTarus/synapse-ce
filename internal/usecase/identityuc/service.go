// Package identityuc manages secure persistence primitives for OIDC login and opaque sessions.
package identityuc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service owns secret generation and ensures stores receive only one-way hashes or authenticated
// ciphertext. It does not process provider access, refresh, or ID tokens.
type Service struct {
	store     ports.IdentityStore
	protector ports.IdentitySecretProtector
	clock     ports.Clock
	ids       ports.IDGenerator
}

// NewService validates OIDC persistence dependencies.
func NewService(store ports.IdentityStore, protector ports.IdentitySecretProtector, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if store == nil || protector == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: identity service is missing a dependency", shared.ErrValidation)
	}
	return &Service{store: store, protector: protector, clock: clock, ids: ids}, nil
}

// AuthorizationStart is returned once to the browser-bound authorization redirect flow. State and
// nonce are raw only at this boundary; their hashes are persisted.
type AuthorizationStart struct {
	State string
	Nonce string
}

// BeginAuthorization creates a one-time transaction for the supplied PKCE verifier. ttl must be
// short-lived and is constrained by the caller's policy; a non-positive ttl is rejected.
func (s *Service) BeginAuthorization(ctx context.Context, tenantID shared.ID, pkceVerifier string, ttl time.Duration) (AuthorizationStart, error) {
	if tenantID.IsZero() || strings.TrimSpace(pkceVerifier) == "" || ttl <= 0 {
		return AuthorizationStart{}, fmt.Errorf("%w: tenant, PKCE verifier, and positive transaction lifetime are required", shared.ErrValidation)
	}
	state, err := randomValue()
	if err != nil {
		return AuthorizationStart{}, err
	}
	nonce, err := randomValue()
	if err != nil {
		return AuthorizationStart{}, err
	}
	ciphertext, err := s.protector.Seal(ctx, []byte(pkceVerifier), transactionAAD(tenantID, stateHash(state)))
	if err != nil {
		return AuthorizationStart{}, fmt.Errorf("seal PKCE verifier: %w", err)
	}
	now := s.clock.Now().UTC()
	transaction, err := identity.NewAuthorizationTransaction(s.ids.NewID(), tenantID, stateHash(state), stateHash(nonce), ciphertext, now.Add(ttl), now)
	if err != nil {
		return AuthorizationStart{}, err
	}
	if err := s.store.CreateAuthorizationTransaction(ctx, transaction); err != nil {
		return AuthorizationStart{}, fmt.Errorf("create authorization transaction: %w", err)
	}
	return AuthorizationStart{State: state, Nonce: nonce}, nil
}

// ConsumedAuthorization contains the PKCE verifier and nonce hash required to validate one
// callback. The ID-token nonce claim must be hashed before comparison with NonceHash.
type ConsumedAuthorization struct {
	NonceHash    string
	PKCEVerifier string
	TenantID     shared.ID
}

// ConsumeAuthorization atomically burns a tenant-bound state value then decrypts its PKCE verifier.
// A failed decrypt leaves the state burned, which is intentional fail-closed replay protection.
func (s *Service) ConsumeAuthorization(ctx context.Context, tenantID shared.ID, state string) (ConsumedAuthorization, error) {
	if tenantID.IsZero() || strings.TrimSpace(state) == "" {
		return ConsumedAuthorization{}, fmt.Errorf("%w: authorization tenant and state are required", shared.ErrValidation)
	}
	transaction, err := s.store.ConsumeAuthorizationTransaction(ctx, tenantID, stateHash(state), s.clock.Now().UTC())
	if err != nil {
		return ConsumedAuthorization{}, fmt.Errorf("consume authorization transaction: %w", err)
	}
	verifier, err := s.protector.Open(ctx, transaction.PKCEVerifierCiphertext, transactionAAD(transaction.TenantID, transaction.StateHash))
	if err != nil {
		return ConsumedAuthorization{}, fmt.Errorf("open PKCE verifier: %w", err)
	}
	return ConsumedAuthorization{NonceHash: transaction.NonceHash, PKCEVerifier: string(verifier), TenantID: transaction.TenantID}, nil
}

// LinkExternalIdentity creates the exact issuer/subject-to-user relationship after a provider ID
// token has been validated by a higher-level OIDC protocol adapter.
func (s *Service) LinkExternalIdentity(ctx context.Context, tenantID, userID shared.ID, issuer, subject string) (identity.ExternalIdentity, error) {
	external, err := identity.NewExternalIdentity(s.ids.NewID(), tenantID, userID, issuer, subject, s.clock.Now().UTC())
	if err != nil {
		return identity.ExternalIdentity{}, err
	}
	if err := s.store.CreateExternalIdentity(ctx, external); err != nil {
		return identity.ExternalIdentity{}, fmt.Errorf("link OIDC external identity: %w", err)
	}
	return external, nil
}

// CreatedSession returns opaque tokens exactly once. Their hashes, not these values, are persisted.
type CreatedSession struct {
	Session   identity.Session
	Token     string
	CSRFToken string
}

// CreateSession mints an opaque browser session linked to an existing tenant-scoped user.
func (s *Service) CreateSession(ctx context.Context, tenantID, userID shared.ID, metadata map[string]string, ttl time.Duration) (CreatedSession, error) {
	if tenantID.IsZero() || userID.IsZero() || ttl <= 0 {
		return CreatedSession{}, fmt.Errorf("%w: tenant, user, and positive session lifetime are required", shared.ErrValidation)
	}
	token, err := randomValue()
	if err != nil {
		return CreatedSession{}, err
	}
	csrfToken, err := randomValue()
	if err != nil {
		return CreatedSession{}, err
	}
	now := s.clock.Now().UTC()
	session, err := identity.NewSession(s.ids.NewID(), tenantID, userID, stateHash(token), stateHash(csrfToken), metadata, now.Add(ttl), now)
	if err != nil {
		return CreatedSession{}, err
	}
	if err := s.store.CreateSession(ctx, session); err != nil {
		return CreatedSession{}, fmt.Errorf("create opaque session: %w", err)
	}
	return CreatedSession{Session: session, Token: token, CSRFToken: csrfToken}, nil
}

// RotateSession atomically replaces an active session so discovery cannot leave both the old and
// new opaque credentials valid when a store operation fails.
func (s *Service) RotateSession(ctx context.Context, previous identity.Session, metadata map[string]string, ttl time.Duration) (CreatedSession, error) {
	if previous.ID.IsZero() || previous.TenantID.IsZero() || previous.UserID.IsZero() || ttl <= 0 {
		return CreatedSession{}, fmt.Errorf("%w: previous session and positive session lifetime are required", shared.ErrValidation)
	}
	token, err := randomValue()
	if err != nil {
		return CreatedSession{}, err
	}
	csrfToken, err := randomValue()
	if err != nil {
		return CreatedSession{}, err
	}
	now := s.clock.Now().UTC()
	// Enforce the absolute lifetime cap: a rotation refreshes the sliding TTL but must never extend the
	// lineage past MaxSessionAge measured from the original login. Past it, the browser is forced back
	// through OIDC. A zero OriginAt fails closed (BeyondMaxAge).
	if previous.BeyondMaxAge(now) {
		return CreatedSession{}, fmt.Errorf("%w: session exceeded its maximum lifetime; re-authentication required", shared.ErrForbidden)
	}
	replacement, err := identity.NewSession(s.ids.NewID(), previous.TenantID, previous.UserID, stateHash(token), stateHash(csrfToken), metadata, now.Add(ttl), now)
	if err != nil {
		return CreatedSession{}, err
	}
	// Carry the immutable origin so the cap is measured from first authentication, not this rotation.
	replacement.OriginAt = previous.OriginAt
	if err := s.store.RotateSession(ctx, previous.ID, replacement, now); err != nil {
		return CreatedSession{}, fmt.Errorf("rotate opaque session: %w", err)
	}
	return CreatedSession{Session: replacement, Token: token, CSRFToken: csrfToken}, nil
}

// AuthenticateSession resolves a tenant-bound opaque token only while the stored session remains active.
func (s *Service) AuthenticateSession(ctx context.Context, tenantID shared.ID, token string) (identity.Session, error) {
	if tenantID.IsZero() || strings.TrimSpace(token) == "" {
		return identity.Session{}, fmt.Errorf("%w: session tenant and token are required", shared.ErrValidation)
	}
	session, err := s.store.GetSessionByTokenHash(shared.WithTenant(ctx, tenantID), stateHash(token))
	if err != nil {
		return identity.Session{}, fmt.Errorf("get session: %w", err)
	}
	if !session.Active(s.clock.Now().UTC()) {
		return identity.Session{}, fmt.Errorf("session inactive: %w", shared.ErrForbidden)
	}
	return session, nil
}

func stateHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func transactionAAD(tenantID shared.ID, stateHash string) []byte {
	return []byte("oidc-authorization-transaction:" + tenantID.String() + ":" + stateHash)
}

func randomValue() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate secure random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
