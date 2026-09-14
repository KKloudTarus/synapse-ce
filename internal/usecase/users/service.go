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
	// legacyCredentials is enabled only when the configured repository exposes the PostgreSQL D5
	// projection capability. It is derived state: users.api_key_hash remains authoritative.
	legacyCredentials ports.LegacyCredentialProjectionStore
	// roster serializes the guarded mutations within this process. The guard is a read-modify-write
	// over the tenant's roster, so two concurrent demotions each see the other admin still enabled,
	// both pass, and the tenant is left with nobody who can administer it. A single mutex is enough
	// because user management is a rare, human-paced operation; across replicas the row lock taken
	// by ports.UserRosterLocker inside the transaction is what serializes them.
	roster sync.Mutex
}

// SetTransactionRunner makes the last-admin guard atomic against a concurrent second mutation.
// The PostgreSQL user repository also implements the D5 projection port; capability detection here
// enables dual-write only after a transaction runner exists, so no-DSN/memory behavior is unchanged.
func (s *Service) SetTransactionRunner(transactions ports.TenantTransactionRunner) {
	s.transactions = transactions
	if transactions == nil {
		return
	}
	if store, ok := s.repo.(ports.LegacyCredentialProjectionStore); ok {
		s.legacyCredentials = store
	}
}

// SetLegacyCredentialProjectionStore enables D5 dual-write explicitly (primarily for composition
// tests or alternate PostgreSQL adapters). It is deliberately refused without a transaction runner:
// source, derived credential, exact-hash index and mandatory audit must share one commit.
func (s *Service) SetLegacyCredentialProjectionStore(store ports.LegacyCredentialProjectionStore) error {
	if store == nil || s.transactions == nil {
		return fmt.Errorf("%w: legacy credential projection requires store and tenant transaction runner", shared.ErrValidation)
	}
	s.legacyCredentials = store
	return nil
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

func (a Actor) tenant() shared.ID { return shared.TenantOrDefault(shared.ID(a.TenantID)) }
func (a Actor) platformAdmin() bool { return a.ID == BootstrapID }

func (a Actor) mayMutate(id shared.ID) error {
	if id.String() == BootstrapID {
		return fmt.Errorf("%w: the bootstrap operator is managed through SYNAPSE_API_TOKEN, not through user management", shared.ErrForbidden)
	}
	return nil
}

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

// CreateUser provisions a new operator and returns the raw API key once.
func (s *Service) CreateUser(ctx context.Context, actor Actor, tenantID string, name string, role user.Role) (*user.User, string, error) {
	target, err := actor.targetTenant(tenantID)
	if err != nil {
		return nil, "", err
	}
	if s.legacyCredentials == nil {
		return s.createUser(ctx, actor, target, name, role)
	}
	var (
		created   *user.User
		plaintext string
	)
	if err := s.transactions.Run(ctx, target, func(txCtx context.Context) error {
		var createErr error
		created, plaintext, createErr = s.createUser(txCtx, actor, target, name, role)
		return createErr
	}); err != nil {
		return nil, "", err
	}
	return created, plaintext, nil
}

func (s *Service) createUser(ctx context.Context, actor Actor, target shared.ID, name string, role user.Role) (*user.User, string, error) {
	plaintext, hash, err := generateKey()
	if err != nil {
		return nil, "", err
	}
	now := s.clock.Now()
	u, err := user.New(s.ids.NewID(), target.String(), name, role, hash, now)
	if err != nil {
		return nil, "", err
	}
	if err := s.repo.Create(ctx, u); err != nil {
		return nil, "", fmt.Errorf("create user: %w", err)
	}
	if err := s.recordUserAudit(ctx, ports.AuditEntry{
		Actor: actor.ID, Action: "user.created", Target: u.ID.String(),
		Metadata: map[string]string{"name": u.Name, "role": string(u.Role), "tenant": target.String()}, At: now,
	}); err != nil {
		return nil, "", err
	}
	return u, plaintext, nil
}

func (s *Service) List(ctx context.Context, actor Actor) ([]*user.User, error) {
	return s.repo.List(ctx, actor.tenant())
}

func (s *Service) Update(ctx context.Context, actor Actor, id shared.ID, name string, role user.Role) (*user.User, error) {
	if err := actor.mayMutate(id); err != nil {
		return nil, err
	}
	return guarded(ctx, s, actor, func(txCtx context.Context) (*user.User, error) {
		return s.update(txCtx, actor, id, name, role)
	})
}

func (s *Service) update(ctx context.Context, actor Actor, id shared.ID, name string, role user.Role) (*user.User, error) {
	// Read the aggregate under the same roster lock used by rotation/disable. UserRepository.Update
	// writes the whole mutable aggregate, so an unlocked stale read could otherwise restore an old
	// api_key_hash after a concurrent rotation committed on another replica.
	u, err := s.lockedUser(ctx, actor.tenant(), id)
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
	if err := s.recordUserAudit(ctx, ports.AuditEntry{
		Actor: actor.ID, Action: "user.updated", Target: u.ID.String(),
		Metadata: map[string]string{"name": u.Name, "role": string(u.Role), "tenant": actor.tenant().String(), "previous_name": before.Name, "previous_role": string(before.Role)}, At: now,
	}); err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Service) SetDisabled(ctx context.Context, actor Actor, id shared.ID, disabled bool) (*user.User, error) {
	if err := actor.mayMutate(id); err != nil {
		return nil, err
	}
	return guarded(ctx, s, actor, func(txCtx context.Context) (*user.User, error) {
		return s.setDisabled(txCtx, actor, id, disabled)
	})
}

func (s *Service) setDisabled(ctx context.Context, actor Actor, id shared.ID, disabled bool) (*user.User, error) {
	// Disable/enable and rotation are one-writer operations over the same legacy row. Lock the row
	// before reading it so disabling can never write an old hash over a newly rotated credential.
	u, err := s.lockedUser(ctx, actor.tenant(), id)
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
	if s.legacyCredentials != nil {
		if _, _, err := s.legacyCredentials.SyncLegacyCredentialDisabled(ctx, ports.LegacyCredentialSyncRequest{
			TenantID: actor.tenant(), UserID: u.ID, Digest: u.APIKeyHash, Disabled: u.Disabled,
			SourceUpdatedAt: u.Audit.UpdatedAt, At: now,
		}); err != nil {
			return nil, fmt.Errorf("project user credential disable: %w", err)
		}
	}
	action := "user.enabled"
	if disabled {
		action = "user.disabled"
	}
	if err := s.recordUserAudit(ctx, ports.AuditEntry{
		Actor: actor.ID, Action: action, Target: u.ID.String(),
		Metadata: map[string]string{"name": u.Name, "role": string(u.Role), "tenant": actor.tenant().String()}, At: now,
	}); err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Service) RotateAPIKey(ctx context.Context, actor Actor, id shared.ID) (*user.User, string, error) {
	if err := actor.mayMutate(id); err != nil {
		return nil, "", err
	}
	u, plaintext, err := guardedKey(ctx, s, actor, func(txCtx context.Context) (*user.User, string, error) {
		return s.rotateAPIKey(txCtx, actor, id)
	})
	if err != nil {
		return nil, "", err
	}
	return u, plaintext, nil
}

func (s *Service) rotateAPIKey(ctx context.Context, actor Actor, id shared.ID) (*user.User, string, error) {
	u, err := s.lockedUser(ctx, actor.tenant(), id)
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
	if s.legacyCredentials != nil {
		if _, _, err := s.legacyCredentials.SyncIssuedLegacyCredential(ctx, ports.LegacyCredentialSyncRequest{
			TenantID: actor.tenant(), UserID: u.ID, Digest: u.APIKeyHash, Disabled: u.Disabled,
			SourceUpdatedAt: u.Audit.UpdatedAt, At: now,
		}); err != nil {
			return nil, "", fmt.Errorf("project rotated user credential: %w", err)
		}
	}
	if err := s.recordUserAudit(ctx, ports.AuditEntry{
		Actor: actor.ID, Action: "user.api_key_rotated", Target: u.ID.String(),
		Metadata: map[string]string{"name": u.Name, "role": string(u.Role), "tenant": actor.tenant().String()}, At: now,
	}); err != nil {
		return nil, "", err
	}
	return u, plaintext, nil
}

func (s *Service) recordUserAudit(ctx context.Context, entry ports.AuditEntry) error {
	if err := s.audit.Record(ctx, entry); err != nil {
		if s.legacyCredentials != nil {
			return fmt.Errorf("record user audit: %w", err)
		}
	}
	return nil
}

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

func guardedKey(ctx context.Context, s *Service, actor Actor, fn func(context.Context) (*user.User, string, error)) (*user.User, string, error) {
	s.roster.Lock()
	defer s.roster.Unlock()
	if s.transactions == nil {
		return fn(ctx)
	}
	var (
		out       *user.User
		plaintext string
	)
	if err := s.transactions.Run(ctx, actor.tenant(), func(txCtx context.Context) error {
		var mutateErr error
		out, plaintext, mutateErr = fn(txCtx)
		return mutateErr
	}); err != nil {
		return nil, "", err
	}
	return out, plaintext, nil
}

// lockedUser resolves one user from the locked tenant roster. PostgreSQL ListForUpdate holds every
// roster row through the caller's bound transaction; memory/file adapters fall back to process-local
// serialization, preserving their historical development behavior.
func (s *Service) lockedUser(ctx context.Context, tenant, id shared.ID) (*user.User, error) {
	roster, err := s.lockedRoster(ctx, tenant)
	if err != nil {
		return nil, err
	}
	for _, candidate := range roster {
		if candidate.ID == id {
			return candidate, nil
		}
	}
	return nil, shared.ErrNotFound
}

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
