package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
)

// TenantSettingsStore is the in-memory ports.TenantSettingsStore. Rows are keyed by tenant, so one
// tenant can never read or overwrite another's settings.
type TenantSettingsStore struct {
	mu   sync.Mutex
	rows map[shared.ID]tenancy.Settings
}

// NewTenantSettingsStore returns an empty store.
func NewTenantSettingsStore() *TenantSettingsStore {
	return &TenantSettingsStore{rows: map[shared.ID]tenancy.Settings{}}
}

func (s *TenantSettingsStore) GetTenantSettings(_ context.Context, tenant shared.ID) (tenancy.Settings, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.rows[tenant]
	return row, ok, nil
}

func (s *TenantSettingsStore) SaveTenantSettings(_ context.Context, next tenancy.Settings, expectedRevision int) (tenancy.Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rows[next.TenantID].Revision != expectedRevision {
		return tenancy.Settings{}, fmt.Errorf("%w: tenant settings revision is stale", shared.ErrConflict)
	}
	next.Revision = expectedRevision + 1
	s.rows[next.TenantID] = next
	return next, nil
}
