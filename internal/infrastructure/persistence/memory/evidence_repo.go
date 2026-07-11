package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// EvidenceStore is an in-memory append-only evidence ledger.
type EvidenceStore struct {
	mu    sync.RWMutex
	items map[shared.ID][]evidence.Evidence // by engagement, in append order
}

// NewEvidenceStore returns an empty in-memory evidence store.
func NewEvidenceStore() *EvidenceStore {
	return &EvidenceStore{items: map[shared.ID][]evidence.Evidence{}}
}

var _ ports.EvidenceStore = (*EvidenceStore)(nil)

func (s *EvidenceStore) Append(_ context.Context, items []evidence.Evidence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Fork guard: one child per parent. Validate the WHOLE batch before mutating –
	// against existing links AND earlier items in the same batch – so a mid-batch conflict
	// leaves nothing appended (atomic, mirroring the Postgres transaction + unique index).
	for i, e := range items {
		for _, existing := range s.items[e.EngagementID] {
			if existing.PreviousHash == e.PreviousHash {
				return fmt.Errorf("evidence chain: parent already linked: %w", shared.ErrConflict)
			}
		}
		for j := 0; j < i; j++ {
			if items[j].EngagementID == e.EngagementID && items[j].PreviousHash == e.PreviousHash {
				return fmt.Errorf("evidence chain: parent already linked within batch: %w", shared.ErrConflict)
			}
		}
	}
	for _, e := range items {
		s.items[e.EngagementID] = append(s.items[e.EngagementID], e)
	}
	return nil
}

func (s *EvidenceStore) ListByEngagement(_ context.Context, engagementID shared.ID) ([]evidence.Evidence, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src := s.items[engagementID]
	out := make([]evidence.Evidence, len(src))
	copy(out, src)
	return out, nil
}

func (s *EvidenceStore) Head(_ context.Context, engagementID shared.ID) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	chain := s.items[engagementID]
	if len(chain) == 0 {
		return "", nil
	}
	return chain[len(chain)-1].Hash, nil
}
