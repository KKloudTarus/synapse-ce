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

func (r *UserRepository) Create(_ context.Context, u *user.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[u.ID]; ok {
		return fmt.Errorf("%w: user %s already exists", shared.ErrValidation, u.ID)
	}
	cp := *u
	r.byID[u.ID] = &cp
	return nil
}

func (r *UserRepository) Upsert(_ context.Context, u *user.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *u
	r.byID[u.ID] = &cp
	return nil
}

// Bootstrap preserves the in-memory repository's historical seed behavior. Durable
// audit-chain guarantees are provided by the PostgreSQL implementation.
func (r *UserRepository) Bootstrap(ctx context.Context, u *user.User, _ ports.AuditEntry) error {
	return r.Upsert(ctx, u)
}

func (r *UserRepository) GetByID(_ context.Context, id shared.ID) (*user.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if u, ok := r.byID[id]; ok {
		cp := *u
		return &cp, nil
	}
	return nil, shared.ErrNotFound
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

func (r *UserRepository) List(_ context.Context) ([]*user.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*user.User, 0, len(r.byID))
	for _, u := range r.byID {
		cp := *u
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Audit.CreatedAt.Before(out[j].Audit.CreatedAt) })
	return out, nil
}
