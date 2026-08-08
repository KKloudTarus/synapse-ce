package memory

import (
	"context"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ScannedImageStore is the in-memory scanned-image digest index (#446), tenant-scoped. It normalizes
// the empty tenant to the default so an image scan and the agent that observes the image correlate
// under one tenant, matching the Postgres store.
type ScannedImageStore struct {
	mu   sync.RWMutex
	byTn map[shared.ID]map[string]bool
}

// NewScannedImageStore constructs an empty in-memory store.
func NewScannedImageStore() *ScannedImageStore {
	return &ScannedImageStore{byTn: map[shared.ID]map[string]bool{}}
}

var _ ports.ScannedImageStore = (*ScannedImageStore)(nil)

// MarkScanned records digest as scanned for the tenant (idempotent).
func (s *ScannedImageStore) MarkScanned(_ context.Context, tenantID shared.ID, digest string, _ time.Time) error {
	tenant := shared.TenantOrDefault(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.byTn[tenant]
	if set == nil {
		set = map[string]bool{}
		s.byTn[tenant] = set
	}
	set[digest] = true
	return nil
}

// ScannedDigests returns a copy of the scanned-digest set for the tenant.
func (s *ScannedImageStore) ScannedDigests(_ context.Context, tenantID shared.ID) (map[string]bool, error) {
	tenant := shared.TenantOrDefault(tenantID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]bool, len(s.byTn[tenant]))
	for d := range s.byTn[tenant] {
		out[d] = true
	}
	return out, nil
}
