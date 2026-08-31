package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/legalhold"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// LegalHoldStore is an in-memory legal-hold store (#635), tenant-scoped, keeping an append-only history
// per (tenant, engagement) so hold+release is auditable.
type LegalHoldStore struct {
	mu   sync.Mutex
	rows map[shared.ID]map[shared.ID][]legalhold.Hold // tenant -> engagement -> holds (newest last)
}

var _ ports.LegalHoldStore = (*LegalHoldStore)(nil)

func NewLegalHoldStore() *LegalHoldStore {
	return &LegalHoldStore{rows: map[shared.ID]map[shared.ID][]legalhold.Hold{}}
}

func (s *LegalHoldStore) tenant(ctx context.Context) (shared.ID, error) {
	t, ok := shared.TenantFrom(ctx)
	if !ok || t.IsZero() {
		return "", fmt.Errorf("%w: legal hold requires a tenant in context", shared.ErrValidation)
	}
	return t, nil
}

func (s *LegalHoldStore) Place(ctx context.Context, h legalhold.Hold) (legalhold.Hold, error) {
	tenant, err := s.tenant(ctx)
	if err != nil {
		return legalhold.Hold{}, err
	}
	if h.TenantID != tenant {
		return legalhold.Hold{}, fmt.Errorf("%w: legal-hold tenant disagrees with context", shared.ErrForbidden)
	}
	if err := h.Validate(); err != nil {
		return legalhold.Hold{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rows[tenant] == nil {
		s.rows[tenant] = map[shared.ID][]legalhold.Hold{}
	}
	for _, existing := range s.rows[tenant][h.EngagementID] {
		if existing.Active() {
			return existing, nil // idempotent: an active hold already exists
		}
	}
	s.rows[tenant][h.EngagementID] = append(s.rows[tenant][h.EngagementID], h)
	return h, nil
}

func (s *LegalHoldStore) Release(ctx context.Context, engagementID shared.ID, releasedBy string, at time.Time) error {
	tenant, err := s.tenant(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	holds := s.rows[tenant][engagementID]
	for i := range holds {
		if holds[i].Active() {
			holds[i].ReleasedBy = releasedBy
			holds[i].ReleasedAt = at.UTC()
			return nil
		}
	}
	return nil // no active hold: release is a no-op
}

func (s *LegalHoldStore) IsHeld(ctx context.Context, engagementID shared.ID) (bool, error) {
	tenant, err := s.tenant(ctx)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.rows[tenant][engagementID] {
		if h.Active() {
			return true, nil
		}
	}
	return false, nil
}

func (s *LegalHoldStore) ListActive(ctx context.Context) ([]legalhold.Hold, error) {
	tenant, err := s.tenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []legalhold.Hold
	for _, holds := range s.rows[tenant] {
		for _, h := range holds {
			if h.Active() {
				out = append(out, h)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EngagementID < out[j].EngagementID })
	return out, nil
}
