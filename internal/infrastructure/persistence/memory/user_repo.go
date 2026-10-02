package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// UserRepository is an in-memory ports.UserRepository for dev/tests.
type UserRepository struct {
	mu   sync.RWMutex
	byID map[shared.ID]*user.User
}

// NewUserRepository returns an empty in-memory user store.
func NewUserRepository() *UserRepository {
	return &UserRepository{byID: map[shared.ID]*user.User{}}
}

var _ ports.UserRepository = (*UserRepository)(nil)

func (r *UserRepository) Create(ctx context.Context, u *user.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[u.ID]; ok {
		return fmt.Errorf("%w: user %s already exists", shared.ErrValidation, u.ID)
	}
	cp := *u
	r.byID[u.ID] = &cp
	r.registerRestore(ctx, u.ID, nil)
	return nil
}

// registerRestore joins the tenant transaction bound to ctx, if any, so a later failure in the
// same unit (an audit write, for example) restores the user exactly as it was. previous is the
// stored row before the write, or nil when the write created it. Callers hold r.mu; the
// compensation runs after they return and takes the lock itself.
func (r *UserRepository) registerRestore(ctx context.Context, id shared.ID, previous *user.User) {
	registerTenantRollback(ctx, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if previous == nil {
			delete(r.byID, id)
			return
		}
		r.byID[id] = previous
	})
}

func (r *UserRepository) Upsert(ctx context.Context, u *user.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	previous := r.byID[u.ID]
	cp := *u
	r.byID[u.ID] = &cp
	r.registerRestore(ctx, u.ID, previous)
	return nil
}

// Bootstrap preserves the in-memory repository's historical seed behavior. Durable
// audit-chain guarantees are provided by the PostgreSQL implementation.
func (r *UserRepository) Bootstrap(ctx context.Context, u *user.User, _ ports.AuditEntry) error {
	return r.Upsert(ctx, u)
}

// sameTenant reports whether a stored row belongs to the requested tenant. Both sides are
// normalized, so the empty tenant of the bootstrap admin and an explicit "default" name one tenant.
func sameTenant(rowTenant string, tenantID shared.ID) bool {
	return shared.TenantOrDefault(shared.ID(rowTenant)) == shared.TenantOrDefault(tenantID)
}

func (r *UserRepository) GetByID(_ context.Context, tenantID, id shared.ID) (*user.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if u, ok := r.byID[id]; ok && sameTenant(u.TenantID, tenantID) {
		cp := *u
		return &cp, nil
	}
	// A user in another tenant is not found, never forbidden: existence is not revealed.
	return nil, shared.ErrNotFound
}

// Update writes the mutable fields of an existing user inside tenantID. The tenant of the stored
// row is preserved, so an update can never move a user between tenants.
func (r *UserRepository) Update(ctx context.Context, tenantID shared.ID, u *user.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.byID[u.ID]
	if !ok || !sameTenant(existing.TenantID, tenantID) {
		return shared.ErrNotFound
	}
	updated := *u
	updated.TenantID = existing.TenantID
	r.byID[u.ID] = &updated
	r.registerRestore(ctx, u.ID, existing)
	return nil
}

func (r *UserRepository) GetByAPIKeyHash(_ context.Context, hash string) (*user.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.byID {
		if u.APIKeyHash == hash {
			cp := *u
			return &cp, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (r *UserRepository) List(_ context.Context, tenantID shared.ID) ([]*user.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*user.User, 0, len(r.byID))
	for _, u := range r.byID {
		if !sameTenant(u.TenantID, tenantID) {
			continue
		}
		cp := *u
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Audit.CreatedAt.Before(out[j].Audit.CreatedAt) })
	return out, nil
}
