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
	"sync"

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
	// transactions makes the last-admin guard and its write one unit. Optional: the in-memory and
	// file stores have no transactions, and the Postgres composition roots set it.
	transactions ports.TenantTransactionRunner
	// roster serializes the guarded mutations within this process. The guard is a read-modify-write
	// over the tenant's roster, so two concurrent demotions each see the other admin still enabled,
	// both pass, and the tenant is left with nobody who can administer it. A single mutex is enough
	// because user management is a rare, human-paced operation; across replicas the row lock taken
	// by ports.UserRosterLocker inside the transaction is what serializes them.
	roster sync.Mutex
}

// SetTransactionRunner makes the last-admin guard atomic against a concurrent second mutation.
// Without it the count and the write commit separately, and the roster can change in between.
func (s *Service) SetTransactionRunner(transactions ports.TenantTransactionRunner) {
	s.transactions = transactions
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

// mayMutate refuses a user-management mutation aimed at the bootstrap principal by anybody else.
//
// The bootstrap admin is stored with an empty tenant_id, which normalizes to the default tenant, so
// it is a member of that tenant's roster and reachable by its admins through the ordinary
// tenant-scoped lookup. Without this guard a default-tenant admin could rotate the bootstrap key,
// read the new plaintext from the response, and present it to become the platform principal that
// every global-resource guard in the product tests for. Disabling or demoting it would equally lock
// the deployment operator out of its own deployment.
//
// The bootstrap credential is owned by SYNAPSE_API_TOKEN and rotated by changing that variable and
// restarting, which is the only path that should move it.
func (a Actor) mayMutate(id shared.ID) error {
	if id.String() == BootstrapID && a.ID != BootstrapID {
		return fmt.Errorf("%w: the bootstrap operator is managed through SYNAPSE_API_TOKEN, not through user management", shared.ErrForbidden)
	}
	return nil
}

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
	if err := actor.mayMutate(id); err != nil {
		return nil, err
	}
	return guarded(ctx, s, actor, func(txCtx context.Context) (*user.User, error) {
		return s.update(txCtx, actor, id, name, role)
	})
}

func (s *Service) update(ctx context.Context, actor Actor, id shared.ID, name string, role user.Role) (*user.User, error) {
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
	if err := actor.mayMutate(id); err != nil {
		return nil, err
	}
	return guarded(ctx, s, actor, func(txCtx context.Context) (*user.User, error) {
		return s.setDisabled(txCtx, actor, id, disabled)
	})
}

func (s *Service) setDisabled(ctx context.Context, actor Actor, id shared.ID, disabled bool) (*user.User, error) {
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
	if err := actor.mayMutate(id); err != nil {
		return nil, "", err
	}
	// Rotation does not touch the admin count, so it needs no roster guard; it still takes the
	// mutex so a rotation cannot interleave with a demotion of the same row.
	s.roster.Lock()
	defer s.roster.Unlock()
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
	roster, err := s.lockedRoster(ctx, actor.tenant())
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

// guarded runs one roster mutation with the last-admin guard held: serialized in this process by
// the service mutex, and against other replicas by the row lock the guard's read takes inside the
// transaction. Both are needed, and neither alone is sufficient.
func guarded(ctx context.Context, s *Service, actor Actor, fn func(context.Context) (*user.User, error)) (*user.User, error) {
	s.roster.Lock()
	defer s.roster.Unlock()
	if s.transactions == nil {
		return fn(ctx)
	}
	var out *user.User
	if err := s.transactions.Run(ctx, actor.tenant(), func(txCtx context.Context) error {
		var mutateErr error
		out, mutateErr = fn(txCtx)
		return mutateErr
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// lockedRoster reads the tenant's roster, locking the rows for the rest of the caller's transaction
// where the repository supports it. A repository that cannot lock falls back to a plain read, which
// leaves the in-process mutex as the only serialization.
func (s *Service) lockedRoster(ctx context.Context, tenant shared.ID) ([]*user.User, error) {
	if locker, ok := s.repo.(ports.UserRosterLocker); ok {
		return locker.ListForUpdate(ctx, tenant)
	}
	return s.repo.List(ctx, tenant)
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
