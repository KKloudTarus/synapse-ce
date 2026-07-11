package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeupdraft"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// WriteupDraftStore is the in-memory write-up-draft repository (dev/tests). It mirrors the Postgres
// adapter to come: Save is an UPSERT by draft id (a draft is mutable working data – edited then
// accepted/rejected), and reads are engagement-scoped (tenant isolation is enforced upstream at the
// route). ListByEngagement returns a deterministic (created_at, id) order to match the SQL adapter.
type WriteupDraftStore struct {
	mu    sync.Mutex
	byEng map[shared.ID][]writeupdraft.Draft
}

// NewWriteupDraftStore builds an empty in-memory draft store.
func NewWriteupDraftStore() *WriteupDraftStore {
	return &WriteupDraftStore{byEng: map[shared.ID][]writeupdraft.Draft{}}
}

var _ ports.WriteupDraftStore = (*WriteupDraftStore)(nil)

// Save upserts a draft by id within its engagement (replace in place if present, else append).
func (s *WriteupDraftStore) Save(_ context.Context, d writeupdraft.Draft) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.byEng[d.EngagementID]
	for i := range list {
		if list[i].ID == d.ID {
			list[i] = d
			return nil
		}
	}
	s.byEng[d.EngagementID] = append(list, d)
	return nil
}

// Get returns the engagement's draft by id, or shared.ErrNotFound.
func (s *WriteupDraftStore) Get(_ context.Context, engagementID, id shared.ID) (writeupdraft.Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.byEng[engagementID] {
		if d.ID == id {
			return d, nil
		}
	}
	return writeupdraft.Draft{}, shared.ErrNotFound
}

// ListByEngagement returns a copy of the engagement's drafts ordered by (created_at, id).
func (s *WriteupDraftStore) ListByEngagement(_ context.Context, engagementID shared.ID) ([]writeupdraft.Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.byEng[engagementID]
	out := make([]writeupdraft.Draft, len(src))
	copy(out, src)
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}
