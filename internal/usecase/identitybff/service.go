// Package identitybff orchestrates the OIDC browser flow without exposing provider credentials to HTTP handlers.
package identitybff

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	identityuc "github.com/KKloudTarus/synapse-ce/internal/usecase/identityuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	usersuc "github.com/KKloudTarus/synapse-ce/internal/usecase/users"
)

// ErrAccessDenied is returned by Complete when a verified subject has no approved link to an
// available user in the fixed tenant. It wraps shared.ErrForbidden.
var ErrAccessDenied = fmt.Errorf("OIDC access denied: %w", shared.ErrForbidden)

type Config struct {
	TenantID       shared.ID
	TransactionTTL time.Duration
	SessionTTL     time.Duration
}

type Authorization struct{ URL, Nonce string }
type Session struct {
	Token, CSRFToken string
	Principal        Principal
}

// Principal is the application identity a browser session resolves to. SessionID is the
// non-secret session row id and AuthenticatedAt is the lineage origin (first login).
type Principal struct {
	ID, Name, Role, TenantID string
	SessionID                string
	AuthenticatedAt          time.Time
}

type Service struct {
	provider   ports.OIDCProvider
	identities *identityuc.Service
	store      ports.IdentityStore
	users      ports.UserRepository
	clock      ports.Clock
	ids        ports.IDGenerator
	cfg        Config
	contacts   interface {
		ImportOIDCEmail(context.Context, shared.ID, shared.ID, string, string) error
		RevokeOIDCEmail(context.Context, shared.ID, shared.ID, string) error
	}
}

// SetVerifiedEmailImporter enables import only after the callback has resolved
// the account by issuer and subject. Email never participates in account lookup.
func (s *Service) SetVerifiedEmailImporter(importer interface {
	ImportOIDCEmail(context.Context, shared.ID, shared.ID, string, string) error
	RevokeOIDCEmail(context.Context, shared.ID, shared.ID, string) error
}) {
	s.contacts = importer
}

// NewService validates the BFF dependencies.
func NewService(provider ports.OIDCProvider, identities *identityuc.Service, store ports.IdentityStore, users ports.UserRepository, clock ports.Clock, ids ports.IDGenerator, cfg Config) (*Service, error) {
	if provider == nil || identities == nil || store == nil || users == nil || clock == nil || ids == nil || cfg.TenantID.IsZero() || cfg.TransactionTTL <= 0 || cfg.SessionTTL <= 0 {
		return nil, fmt.Errorf("%w: OIDC BFF service has invalid configuration", shared.ErrValidation)
	}
	return &Service{provider: provider, identities: identities, store: store, users: users, clock: clock, ids: ids, cfg: cfg}, nil
}

func (s *Service) Begin(ctx context.Context) (Authorization, error) {
	verifier := s.provider.GenerateVerifier()
	start, err := s.identities.BeginAuthorization(ctx, s.cfg.TenantID, verifier, s.cfg.TransactionTTL)
	if err != nil {
		return Authorization{}, fmt.Errorf("begin OIDC authorization: %w", err)
	}
	url, err := s.provider.AuthorizationURL(start.State, start.Nonce, verifier)
	if err != nil {
		return Authorization{}, fmt.Errorf("build OIDC authorization URL: %w", err)
	}
	return Authorization{URL: url, Nonce: start.Nonce}, nil
}

// Complete burns state before exchange, validates cookie and signed token nonce, then accepts
// only a preapproved exact issuer/subject link in the fixed tenant. An unknown subject is denied:
// no user, link, or session is created, and provider groups never touch any Synapse role.
func (s *Service) Complete(ctx context.Context, state, code, nonce string) (Session, error) {
	if strings.TrimSpace(nonce) == "" {
		return Session{}, fmt.Errorf("OIDC nonce cookie is missing: %w", shared.ErrForbidden)
	}
	transaction, err := s.identities.ConsumeAuthorization(ctx, s.cfg.TenantID, state)
	if err != nil {
		return Session{}, fmt.Errorf("consume OIDC authorization: %w", err)
	}
	if transaction.TenantID != s.cfg.TenantID || subtle.ConstantTimeCompare([]byte(hash(nonce)), []byte(transaction.NonceHash)) != 1 {
		return Session{}, fmt.Errorf("OIDC authorization tenant or nonce mismatch: %w", shared.ErrForbidden)
	}
	verified, err := s.provider.ExchangeAndVerify(ctx, code, transaction.PKCEVerifier, nonce)
	if err != nil {
		return Session{}, fmt.Errorf("verify OIDC callback: %w", err)
	}
	tenantCtx := shared.WithTenant(ctx, s.cfg.TenantID)
	u, err := s.resolveUser(tenantCtx, verified)
	if err != nil {
		return Session{}, err
	}
	if s.contacts != nil {
		var syncErr error
		if verified.EmailVerified {
			syncErr = s.contacts.ImportOIDCEmail(tenantCtx, s.cfg.TenantID, u.ID, verified.Issuer, verified.Email)
		} else {
			syncErr = s.contacts.RevokeOIDCEmail(tenantCtx, s.cfg.TenantID, u.ID, verified.Issuer)
		}
		if syncErr != nil {
			return Session{}, fmt.Errorf("synchronize verified OIDC contact: %w", syncErr)
		}
	}
	created, err := s.createSessionForExternalIdentity(ctx, u.ID, u.Audit.UpdatedAt, verified.Issuer, verified.Subject)
	if err != nil {
		return Session{}, err
	}
	return Session{Token: created.Token, CSRFToken: created.CSRFToken, Principal: s.principal(u, created.Session)}, nil
}

// createSessionForExternalIdentity generates opaque credentials, then delegates the final exact
// subject, enabled-user, and unchanged-approval checks plus persistence to one atomic store write.
func (s *Service) createSessionForExternalIdentity(ctx context.Context, userID shared.ID, approvedUserUpdatedAt time.Time, issuer, subject string) (identityuc.CreatedSession, error) {
	issuerStore, ok := s.store.(ports.ExternalIdentitySessionIssuer)
	if !ok {
		return identityuc.CreatedSession{}, fmt.Errorf("create OIDC session: %w", authz.ErrAuthenticationUnavailable)
	}
	if s.cfg.TenantID.IsZero() || userID.IsZero() || s.cfg.SessionTTL <= 0 {
		return identityuc.CreatedSession{}, fmt.Errorf("%w: tenant, user, and positive session lifetime are required", shared.ErrValidation)
	}
	token, err := opaqueToken()
	if err != nil {
		return identityuc.CreatedSession{}, err
	}
	csrfToken, err := opaqueToken()
	if err != nil {
		return identityuc.CreatedSession{}, err
	}
	now := s.clock.Now().UTC()
	session, err := identity.NewSession(s.ids.NewID(), s.cfg.TenantID, userID, hash(token), hash(csrfToken), nil, now.Add(s.cfg.SessionTTL), now)
	if err != nil {
		return identityuc.CreatedSession{}, err
	}
	if err := issuerStore.CreateSessionForExternalIdentity(ctx, issuer, subject, approvedUserUpdatedAt, session); err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return identityuc.CreatedSession{}, fmt.Errorf("OIDC subject or user is no longer available: %w", ErrAccessDenied)
		}
		return identityuc.CreatedSession{}, fmt.Errorf("create OIDC session: %w", err)
	}
	return identityuc.CreatedSession{Session: session, Token: token, CSRFToken: csrfToken}, nil
}

// resolveUser maps a verified issuer/subject to its preapproved tenant-scoped user. It only reads:
// the link must already exist (approved by an operator or carried over from earlier releases), and
// the user's stored role is authoritative.
func (s *Service) resolveUser(ctx context.Context, verified ports.OIDCIdentity) (*user.User, error) {
	external, err := s.store.GetExternalIdentity(ctx, verified.Issuer, verified.Subject)
	switch {
	case errors.Is(err, shared.ErrNotFound):
		return nil, fmt.Errorf("OIDC subject has no approved link: %w", ErrAccessDenied)
	case err != nil:
		return nil, fmt.Errorf("resolve linked OIDC identity: %w: %w", authz.ErrAuthenticationUnavailable, err)
	}
	if external.TenantID != s.cfg.TenantID {
		return nil, fmt.Errorf("OIDC linked identity tenant mismatch: %w", ErrAccessDenied)
	}
	u, err := s.users.GetByID(ctx, external.TenantID, external.UserID)
	switch {
	case errors.Is(err, shared.ErrNotFound):
		return nil, fmt.Errorf("OIDC user is unavailable: %w", ErrAccessDenied)
	case err != nil:
		return nil, fmt.Errorf("load linked OIDC user: %w: %w", authz.ErrAuthenticationUnavailable, err)
	}
	if !s.available(u) {
		return nil, fmt.Errorf("OIDC user is unavailable: %w", ErrAccessDenied)
	}
	return u, nil
}

// available reports whether u may hold a browser session: enabled, a valid human role, in the fixed
// tenant, and never the bootstrap operator, whose only credential is SYNAPSE_API_TOKEN.
func (s *Service) available(u *user.User) bool {
	return !u.Disabled && u.Role.Valid() && u.ID.String() != usersuc.BootstrapID &&
		shared.TenantOrDefault(shared.ID(u.TenantID)) == s.cfg.TenantID
}

func (s *Service) principal(u *user.User, session identity.Session) Principal {
	return Principal{
		ID: u.ID.String(), Name: u.Name, Role: string(u.Role), TenantID: s.cfg.TenantID.String(),
		SessionID: session.ID.String(), AuthenticatedAt: session.OriginAt,
	}
}

// sessionUser loads the user behind an authenticated session. A missing, disabled, or otherwise
// unavailable user makes the session invalid; a repository failure is a dependency outage.
func (s *Service) sessionUser(ctx context.Context, session identity.Session) (*user.User, error) {
	u, err := s.users.GetByID(ctx, session.TenantID, session.UserID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("session user not found: %w: %w", authz.ErrCredentialInvalid, shared.ErrForbidden)
	}
	if err != nil {
		return nil, fmt.Errorf("load session user: %w: %w", authz.ErrAuthenticationUnavailable, err)
	}
	if !s.available(u) {
		return nil, fmt.Errorf("session user is unavailable: %w: %w", authz.ErrCredentialInvalid, shared.ErrForbidden)
	}
	return u, nil
}

// Authenticate resolves a browser session for one request. The lineage cap, revocation, and the
// user's availability are checked every time. Errors wrap authz.ErrCredentialInvalid,
// authz.ErrCSRFInvalid, or authz.ErrAuthenticationUnavailable.
func (s *Service) Authenticate(ctx context.Context, token, csrfToken string, unsafe bool) (Principal, error) {
	session, err := s.identities.AuthenticateSession(ctx, s.cfg.TenantID, token)
	if err != nil {
		return Principal{}, err
	}
	if unsafe && (csrfToken == "" || subtle.ConstantTimeCompare([]byte(hash(csrfToken)), []byte(session.CSRFTokenHash)) != 1) {
		return Principal{}, fmt.Errorf("CSRF token mismatch: %w: %w", authz.ErrCSRFInvalid, shared.ErrForbidden)
	}
	u, err := s.sessionUser(ctx, session)
	if err != nil {
		return Principal{}, err
	}
	return s.principal(u, session), nil
}

// Discover validates a browser session and rotates its opaque session and CSRF tokens.
// It exposes only the application principal fields needed by the frontend.
func (s *Service) Discover(ctx context.Context, token string) (Session, error) {
	session, err := s.identities.AuthenticateSession(ctx, s.cfg.TenantID, token)
	if err != nil {
		return Session{}, err
	}
	u, err := s.sessionUser(ctx, session)
	if err != nil {
		return Session{}, err
	}
	created, err := s.identities.RotateSession(ctx, session, nil, s.cfg.SessionTTL)
	if err != nil {
		return Session{}, fmt.Errorf("rotate discovered OIDC session: %w", err)
	}
	return Session{Token: created.Token, CSRFToken: created.CSRFToken, Principal: s.principal(u, created.Session)}, nil
}

// Logout revokes the presented session. A session that is already invalid needs no revocation, so
// it succeeds; a dependency failure is returned so the caller can retry.
func (s *Service) Logout(ctx context.Context, token string) error {
	session, err := s.identities.AuthenticateSession(ctx, s.cfg.TenantID, token)
	if errors.Is(err, authz.ErrCredentialInvalid) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.store.RevokeSession(ctx, s.cfg.TenantID, session.ID, s.clock.Now().UTC()); err != nil && !errors.Is(err, shared.ErrConflict) {
		return fmt.Errorf("revoke OIDC session: %w: %w", authz.ErrAuthenticationUnavailable, err)
	}
	return nil
}

func hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func opaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate secure random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
