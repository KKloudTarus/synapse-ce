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
	mu          sync.RWMutex
	items       map[shared.ID][]evidence.Evidence // by engagement, in append order
	engagements map[shared.ID]shared.ID           // engagement -> tenant; first append establishes ownership
}

// NewEvidenceStore returns an empty in-memory evidence store.
func NewEvidenceStore() *EvidenceStore {
	return &EvidenceStore{
		items:       map[shared.ID][]evidence.Evidence{},
		engagements: map[shared.ID]shared.ID{},
	}
}

// sameEvidence compares the complete sealed record, including chain metadata.
var _ ports.EvidenceStore = (*EvidenceStore)(nil)

func (s *EvidenceStore) Append(ctx context.Context, items []evidence.Evidence) error {
	tenantID, scoped := shared.TenantFrom(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	// Validate the whole batch before mutating. Reserved-ID replay is resolved
	// by the evidence service before append; this store preserves legacy ID
	// generator compatibility for ordinary, non-reserved evidence links.
	for i, e := range items {
		if owner, exists := s.engagements[e.EngagementID]; exists && scoped && owner != tenantID {
			return fmt.Errorf("evidence engagement %s: %w", e.EngagementID, shared.ErrNotFound)
		}
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
		if scoped {
			s.engagements[e.EngagementID] = tenantID
		}
	}
	return nil
}

func (s *EvidenceStore) ListByEngagement(ctx context.Context, engagementID shared.ID) ([]evidence.Evidence, error) {
	tenantID, scoped := shared.TenantFrom(ctx)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if owner, exists := s.engagements[engagementID]; exists && scoped && owner != tenantID {
		return nil, fmt.Errorf("evidence engagement %s: %w", engagementID, shared.ErrNotFound)
	}
	src := s.items[engagementID]
	out := make([]evidence.Evidence, len(src))
	copy(out, src)
	return out, nil
}

func (s *EvidenceStore) Head(ctx context.Context, engagementID shared.ID) (string, error) {
	tenantID, scoped := shared.TenantFrom(ctx)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if owner, exists := s.engagements[engagementID]; exists && scoped && owner != tenantID {
		return "", fmt.Errorf("evidence engagement %s: %w", engagementID, shared.ErrNotFound)
	}
	chain := s.items[engagementID]
	if len(chain) == 0 {
		return "", nil
	}
	return chain[len(chain)-1].Hash, nil
}

// LookupSealedForFinding returns the most recent sealed evidence link of the
// given kind for the specified finding, or (zero, false, nil) if none exists.
// Used for crash-recoverable evidence reservation in the promotion recorder.
func (s *EvidenceStore) LookupSealedForFinding(_ context.Context, engagementID, findingID shared.ID, kind string) (evidence.Evidence, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	chain := s.items[engagementID]
	// Scan backward to find the most recent matching link.
	for i := len(chain) - 1; i >= 0; i-- {
		e := chain[i]
		if e.FindingID == findingID && e.Kind == kind {
			out := e // defensive copy
			return out, true, nil
		}
	}
	return evidence.Evidence{}, false, nil
}
