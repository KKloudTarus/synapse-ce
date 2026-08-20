// Package identitybff orchestrates the OIDC browser flow without exposing provider credentials to HTTP handlers.
package identitybff

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	identityuc "github.com/KKloudTarus/synapse-ce/internal/usecase/identityuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

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
type Principal struct{ ID, Name, Role, TenantID string }

type Service struct {
	provider   ports.OIDCProvider
	identities *identityuc.Service
	store      ports.IdentityStore
	users      ports.UserRepository
	clock      ports.Clock
	ids        ports.IDGenerator
	cfg        Config
}

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

// Complete burns state before exchange, validates cookie and signed token nonce, then accepts an exact issuer/subject link in the fixed tenant.
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
	if !verified.Role.Valid() {
		return Session{}, fmt.Errorf("OIDC group mapping produced no valid role: %w", shared.ErrForbidden)
	}
	tenantCtx := shared.WithTenant(ctx, s.cfg.TenantID)
	u, err := s.resolveUser(tenantCtx, verified)
	if err != nil {
		return Session{}, err
	}
	created, err := s.identities.CreateSession(ctx, s.cfg.TenantID, u.ID, nil, s.cfg.SessionTTL)
	if err != nil {
		return Session{}, fmt.Errorf("create OIDC session: %w", err)
	}
	return Session{Token: created.Token, CSRFToken: created.CSRFToken, Principal: Principal{ID: u.ID.String(), Name: u.Name, Role: string(u.Role), TenantID: s.cfg.TenantID.String()}}, nil
}

// resolveUser maps a verified issuer/subject to a tenant-scoped user, provisioning the link on
// first login. The operator-configured group mapping is authoritative for the role, so a group
// change at the provider is applied here rather than rejecting the login as a mismatch.
func (s *Service) resolveUser(ctx context.Context, verified ports.OIDCIdentity) (*user.User, error) {
	external, err := s.store.GetExternalIdentity(ctx, verified.Issuer, verified.Subject)
	switch {
	case err == nil:
		if external.TenantID != s.cfg.TenantID {
			return nil, fmt.Errorf("OIDC linked identity tenant mismatch: %w", shared.ErrForbidden)
		}
		u, getErr := s.users.GetByID(ctx, external.UserID)
		if getErr != nil || u.Disabled || shared.TenantOrDefault(shared.ID(u.TenantID)) != s.cfg.TenantID {
			return nil, fmt.Errorf("OIDC user is unavailable: %w", shared.ErrForbidden)
		}
		if u.Role != verified.Role {
			u.Role = verified.Role
			u.Audit.UpdatedAt = s.clock.Now().UTC()
			if err := s.users.Upsert(ctx, u); err != nil {
				return nil, fmt.Errorf("apply mapped OIDC role: %w", err)
			}
		}
		return u, nil
	case errors.Is(err, shared.ErrNotFound):
		return s.provisionUser(ctx, verified)
	default:
		return nil, fmt.Errorf("resolve linked OIDC identity: %w", err)
	}
}

// provisionUser creates the tenant-scoped user for a first-time subject and links it. The
// API-key hash is an unguessable random value, so a provisioned identity can never be
// authenticated with a bearer token.
func (s *Service) provisionUser(ctx context.Context, verified ports.OIDCIdentity) (*user.User, error) {
	unusableAPIKeyHash, err := randomHex()
	if err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	u, err := user.New(s.ids.NewID(), s.cfg.TenantID.String(), oidcDisplayName(verified), verified.Role, unusableAPIKeyHash, now)
	if err != nil {
		return nil, fmt.Errorf("build provisioned OIDC user: %w", err)
	}
	if err := s.users.Create(ctx, u); err != nil {
		return nil, fmt.Errorf("create provisioned OIDC user: %w", err)
	}
	if _, err := s.identities.LinkExternalIdentity(ctx, s.cfg.TenantID, u.ID, verified.Issuer, verified.Subject); err != nil {
		// A concurrent replica may have won the link. Re-read so both requests converge on the
		// same user rather than leaving this login broken.
		if errors.Is(err, shared.ErrConflict) {
			external, getErr := s.store.GetExternalIdentity(ctx, verified.Issuer, verified.Subject)
			if getErr == nil && external.TenantID == s.cfg.TenantID {
				if existing, userErr := s.users.GetByID(ctx, external.UserID); userErr == nil && !existing.Disabled {
					return existing, nil
				}
			}
		}
		return nil, fmt.Errorf("link provisioned OIDC identity: %w", err)
	}
	return u, nil
}

// oidcDisplayName never trusts a provider-supplied display string for identity; the subject is
// the stable identifier and the name is only shown in the UI.
func oidcDisplayName(verified ports.OIDCIdentity) string {
	if name := strings.TrimSpace(verified.Name); name != "" {
		return name
	}
	return verified.Subject
}

func randomHex() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate provisioned credential placeholder: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func (s *Service) Authenticate(ctx context.Context, token, csrfToken string, unsafe bool) (Principal, error) {
	session, err := s.identities.AuthenticateSession(ctx, s.cfg.TenantID, token)
	if err != nil {
		return Principal{}, err
	}
	if unsafe && (csrfToken == "" || subtle.ConstantTimeCompare([]byte(hash(csrfToken)), []byte(session.CSRFTokenHash)) != 1) {
		return Principal{}, fmt.Errorf("CSRF token mismatch: %w", shared.ErrForbidden)
	}
	u, err := s.users.GetByID(ctx, session.UserID)
	if err != nil || u.Disabled || shared.TenantOrDefault(shared.ID(u.TenantID)) != s.cfg.TenantID {
		return Principal{}, shared.ErrForbidden
	}
	return Principal{ID: u.ID.String(), Name: u.Name, Role: string(u.Role), TenantID: s.cfg.TenantID.String()}, nil
}

// Discover validates a browser session and rotates its opaque session and CSRF tokens.
// It exposes only the application principal fields needed by the frontend.
func (s *Service) Discover(ctx context.Context, token string) (Session, error) {
	session, err := s.identities.AuthenticateSession(ctx, s.cfg.TenantID, token)
	if err != nil {
		return Session{}, err
	}
	u, err := s.users.GetByID(ctx, session.UserID)
	if err != nil || u.Disabled || shared.TenantOrDefault(shared.ID(u.TenantID)) != s.cfg.TenantID || !u.Role.Valid() {
		return Session{}, shared.ErrForbidden
	}
	created, err := s.identities.RotateSession(ctx, session, nil, s.cfg.SessionTTL)
	if err != nil {
		return Session{}, fmt.Errorf("rotate discovered OIDC session: %w", err)
	}
	return Session{Token: created.Token, CSRFToken: created.CSRFToken, Principal: Principal{ID: u.ID.String(), Name: u.Name, Role: string(u.Role), TenantID: s.cfg.TenantID.String()}}, nil
}

func (s *Service) Logout(ctx context.Context, token string) error {
	session, err := s.identities.AuthenticateSession(ctx, s.cfg.TenantID, token)
	if err != nil {
		return err
	}
	if err := s.store.RevokeSession(ctx, s.cfg.TenantID, session.ID, s.clock.Now().UTC()); err != nil {
		return fmt.Errorf("revoke OIDC session: %w", err)
	}
	return nil
}

func hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
