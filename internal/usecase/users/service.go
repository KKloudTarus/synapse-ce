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
	"strings"

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
	if err := s.repo.Bootstrap(ctx, u, ports.AuditEntry{
		Actor:  BootstrapID,
		Action: "user.bootstrap_admin_seeded",
		Target: BootstrapID,
		Metadata: map[string]string{
			"idempotency_key": "bootstrap-admin:" + BootstrapID,
		},
		At: s.clock.Now(),
	}); err != nil {
		return fmt.Errorf("seed bootstrap admin: %w", err)
	}
	return nil
}

// Actor is the authenticated caller of a user-management action. It carries the caller's own
// tenant, which is the tenant every action is confined to.
type Actor struct {
	ID       string
	TenantID string
}

// tenant returns the actor's normalized tenant (” and "default" name the same tenant).
func (a Actor) tenant() shared.ID { return shared.TenantOrDefault(shared.ID(a.TenantID)) }

// platformAdmin reports whether the actor may act outside its own tenant.
//
// There is deliberately no platform-admin ROLE: a role would be assignable by any tenant admin
// through the same user-management API this guards, which is the escalation being closed. The one
// cross-tenant identity is the bootstrap principal seeded from SYNAPSE_API_TOKEN (id "operator"),
// which only somebody with the deployment's environment can present, and which already owns the
// default-tenant superadmin position. Its single cross-tenant power is provisioning a user in
// another tenant, so a new tenant can be given its first admin; reads and every other mutation stay
// confined to the actor's own tenant for the bootstrap principal too.
func (a Actor) platformAdmin() bool { return a.ID == BootstrapID }

// targetTenant resolves the tenant an action applies to. An empty request means "my own tenant".
// A different tenant is refused unless the actor is the platform admin, so a tenant-A admin can
// neither provision into tenant B nor receive that user's API key.
func (a Actor) targetTenant(requested string) (shared.ID, error) {
	if strings.TrimSpace(requested) == "" {
		return a.tenant(), nil
	}
	target := shared.TenantOrDefault(shared.ID(strings.TrimSpace(requested)))
	if target != a.tenant() && !a.platformAdmin() {
		return "", fmt.Errorf("%w: user management is confined to the caller's own tenant", shared.ErrForbidden)
	}
	return target, nil
}

// CreateUser provisions a new operator and returns the raw API key ONCE (it is never recoverable
// afterwards). tenantID is assigned server-side by the admin provisioning the user (never from the
// new user's own token) and must be the actor's own tenant unless the actor is the platform admin;
// empty means the actor's tenant, so a single-tenant admin keeps creating users with no ceremony.
// The tenant the user lands in is what scopes every read/write they later make, so it is captured
// in the audit record. Audited.
func (s *Service) CreateUser(ctx context.Context, actor Actor, tenantID string, name string, role user.Role) (*user.User, string, error) {
	target, err := actor.targetTenant(tenantID)
	if err != nil {
		return nil, "", err
	}
	plaintext, hash, err := generateKey()
	if err != nil {
		return nil, "", err
	}
	// The provisioning admin assigns the tenant – the aggregate owns it from birth.
	u, err := user.New(s.ids.NewID(), target.String(), name, role, hash, s.clock.Now())
	if err != nil {
		return nil, "", err
	}
	if err := s.repo.Create(ctx, u); err != nil {
		return nil, "", fmt.Errorf("create user: %w", err)
	}
	_ = s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor.ID, Action: "user.created", Target: u.ID.String(),
		Metadata: map[string]string{"name": u.Name, "role": string(u.Role), "tenant": target.String()},
		At:       s.clock.Now(),
	})
	return u, plaintext, nil
}

// List returns the users of the actor's own tenant (the hash is on the struct; the adapter must not
// serialize it). No caller, the platform admin included, lists another tenant's roster.
func (s *Service) List(ctx context.Context, actor Actor) ([]*user.User, error) {
	return s.repo.List(ctx, actor.tenant())
}

// Update changes a user's display name and role inside the actor's tenant. An empty name or role
// leaves that field unchanged, so a caller can rename without knowing the current role. Demoting
// the tenant's last enabled admin is refused, else the tenant would be left unmanageable. Audited.
func (s *Service) Update(ctx context.Context, actor Actor, id shared.ID, name string, role user.Role) (*user.User, error) {
	u, err := s.repo.GetByID(ctx, actor.tenant(), id)
	if err != nil {
		return nil, fmt.Errorf("load user: %w", err)
	}
	before := *u
	now := s.clock.Now()
	if strings.TrimSpace(name) != "" {
		if err := u.Rename(name, now); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(string(role)) != "" {
		if err := u.SetRole(role, now); err != nil {
			return nil, err
		}
		if before.Role.Can(user.PermAdminister) && !u.Role.Can(user.PermAdminister) {
			if err := s.assertNotLastEnabledAdmin(ctx, actor, u.ID, "demote"); err != nil {
				return nil, err
			}
		}
	}
	if err := s.repo.Update(ctx, actor.tenant(), u); err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}
	_ = s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor.ID, Action: "user.updated", Target: u.ID.String(),
		Metadata: map[string]string{
			"name": u.Name, "role": string(u.Role), "tenant": actor.tenant().String(),
			"previous_name": before.Name, "previous_role": string(before.Role),
		},
		At: now,
	})
	return u, nil
}

// SetDisabled turns a user's credentials off or back on inside the actor's tenant. Disabling is the
// revocation the product offers instead of deletion: the identity, and therefore every past
// attribution, is preserved while authentication stops. Disabling the tenant's last enabled admin
// is refused, else nobody could administer the tenant afterwards. Audited.
func (s *Service) SetDisabled(ctx context.Context, actor Actor, id shared.ID, disabled bool) (*user.User, error) {
	u, err := s.repo.GetByID(ctx, actor.tenant(), id)
	if err != nil {
		return nil, fmt.Errorf("load user: %w", err)
	}
	if disabled && u.Role.Can(user.PermAdminister) && !u.Disabled {
		if err := s.assertNotLastEnabledAdmin(ctx, actor, u.ID, "disable"); err != nil {
			return nil, err
		}
	}
	now := s.clock.Now()
	u.SetDisabled(disabled, now)
	if err := s.repo.Update(ctx, actor.tenant(), u); err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}
	action := "user.enabled"
	if disabled {
		action = "user.disabled"
	}
	_ = s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor.ID, Action: action, Target: u.ID.String(),
		Metadata: map[string]string{"name": u.Name, "role": string(u.Role), "tenant": actor.tenant().String()},
		At:       now,
	})
	return u, nil
}

// RotateAPIKey issues a new API key for a user in the actor's tenant and returns it ONCE. The
// previous key stops authenticating immediately, which is how a leaked key is revoked from the
// product. Audited; the key itself never reaches the audit log. A disabled user may be rotated —
// rotation invalidates the old credential whether or not the account is currently usable.
func (s *Service) RotateAPIKey(ctx context.Context, actor Actor, id shared.ID) (*user.User, string, error) {
	u, err := s.repo.GetByID(ctx, actor.tenant(), id)
	if err != nil {
		return nil, "", fmt.Errorf("load user: %w", err)
	}
	plaintext, hash, err := generateKey()
	if err != nil {
		return nil, "", err
	}
	now := s.clock.Now()
	if err := u.SetAPIKeyHash(hash, now); err != nil {
		return nil, "", err
	}
	if err := s.repo.Update(ctx, actor.tenant(), u); err != nil {
		return nil, "", fmt.Errorf("update user: %w", err)
	}
	_ = s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor.ID, Action: "user.api_key_rotated", Target: u.ID.String(),
		Metadata: map[string]string{"name": u.Name, "role": string(u.Role), "tenant": actor.tenant().String()},
		At:       now,
	})
	return u, plaintext, nil
}

// assertNotLastEnabledAdmin refuses an action that would leave the tenant with no enabled admin.
// It counts the tenant's OTHER enabled admins, so an admin cannot lock the tenant out by disabling
// or demoting itself.
func (s *Service) assertNotLastEnabledAdmin(ctx context.Context, actor Actor, id shared.ID, action string) error {
	roster, err := s.repo.List(ctx, actor.tenant())
	if err != nil {
		return fmt.Errorf("count tenant admins: %w", err)
	}
	for _, other := range roster {
		if other.ID == id || other.Disabled {
			continue
		}
		if other.Role.Can(user.PermAdminister) {
			return nil
		}
	}
	return fmt.Errorf("%w: cannot %s the last enabled admin of tenant %q", shared.ErrConflict, action, actor.tenant())
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
