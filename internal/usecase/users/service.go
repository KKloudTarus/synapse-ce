// Package users manages operator identities + API keys. It
// issues a per-user bearer key (shown once), authenticates a presented token by its
// hash, and seeds a bootstrap admin from SYNAPSE_API_TOKEN so existing deployments
// keep working and historical "operator" attribution stays valid.
package users

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// BootstrapID is the stable id of the bootstrap admin. Historical actions were
// attributed to "operator", so the bootstrap user owns that id and history stays
// coherent ("who did this?" resolves to the bootstrap admin, not a dangling string).
const BootstrapID = "operator"

const apiKeyPrefix = "syn_"

// Service manages users + authentication.
type Service struct {
	repo  ports.UserRepository
	audit ports.AuditLogger
	clock ports.Clock
	ids   ports.IDGenerator
}

// NewService validates dependencies and returns the users service.
func NewService(repo ports.UserRepository, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if repo == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: users service is missing a dependency", shared.ErrValidation)
	}
	return &Service{repo: repo, audit: audit, clock: clock, ids: ids}, nil
}

// HashToken returns the lowercase-hex SHA-256 of a bearer token (the only form
// stored or compared). Exported so the auth resolver and tests agree on the format.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func generateKey() (plaintext, hash string, err error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate api key: %w", err)
	}
	plaintext = apiKeyPrefix + hex.EncodeToString(b)
	return plaintext, HashToken(plaintext), nil
}

// EnsureBootstrapAdmin idempotently makes the bootstrap admin (id "operator") whose
// key is the env SYNAPSE_API_TOKEN, so the existing token keeps authenticating –
// now as a real, admin user. Safe to call on every startup.
func (s *Service) EnsureBootstrapAdmin(ctx context.Context, token string) error {
	if token == "" {
		return fmt.Errorf("%w: bootstrap token is required", shared.ErrValidation)
	}
	// Bootstrap admin lives in tenant '' – the deliberate single-tenant / default-tenant superadmin.
	u, err := user.New(BootstrapID, "", "Operator (bootstrap admin)", user.RoleAdmin, HashToken(token), s.clock.Now())
	if err != nil {
		return err
	}
	if err := s.repo.Upsert(ctx, u); err != nil {
		return fmt.Errorf("seed bootstrap admin: %w", err)
	}
	return nil
}

// CreateUser provisions a new operator in tenantID and returns the raw API key ONCE (it is
// never recoverable afterwards). tenantID is assigned server-side by the admin provisioning the
// user (never from the new user's own token); ” = the single default tenant (single-tenant
// mode). The tenant the user lands in is what scopes every read/write they later make,
// so it is captured in the audit record. Audited.
func (s *Service) CreateUser(ctx context.Context, actor string, tenantID string, name string, role user.Role) (*user.User, string, error) {
	plaintext, hash, err := generateKey()
	if err != nil {
		return nil, "", err
	}
	// The provisioning admin assigns the tenant – the aggregate owns it from birth.
	u, err := user.New(s.ids.NewID(), tenantID, name, role, hash, s.clock.Now())
	if err != nil {
		return nil, "", err
	}
	if err := s.repo.Create(ctx, u); err != nil {
		return nil, "", fmt.Errorf("create user: %w", err)
	}
	_ = s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor, Action: "user.created", Target: u.ID.String(),
		Metadata: map[string]string{"name": u.Name, "role": string(u.Role), "tenant": tenantID},
		At:       s.clock.Now(),
	})
	return u, plaintext, nil
}

// List returns all users (hash is on the struct; the adapter must not serialize it).
func (s *Service) List(ctx context.Context) ([]*user.User, error) {
	return s.repo.List(ctx)
}

// Authenticate resolves a presented bearer token to its (enabled) user, or an error.
func (s *Service) Authenticate(ctx context.Context, token string) (*user.User, error) {
	if token == "" {
		return nil, fmt.Errorf("%w: empty token", shared.ErrValidation)
	}
	u, err := s.repo.GetByAPIKeyHash(ctx, HashToken(token))
	if err != nil {
		return nil, err
	}
	if u.Disabled {
		return nil, fmt.Errorf("%w: user disabled", shared.ErrForbidden)
	}
	return u, nil
}
