package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// JudgmentStore is the in-memory judgment repository (dev/tests). It mirrors the Postgres adapter
// to come: SetScoreState is the ONLY score/state mover and is guarded by optimistic concurrency
// (expectedVersion → shared.ErrConflict on mismatch), the same discipline as the finding repo's
// SetEvidenceScore. The score mover is deliberately not exposed on a broad read port.
type JudgmentStore struct {
	mu    sync.Mutex
	byEng map[shared.ID][]judgment.Judgment
}

// NewJudgmentStore returns an empty in-memory judgment store.
func NewJudgmentStore() *JudgmentStore {
	return &JudgmentStore{byEng: map[shared.ID][]judgment.Judgment{}}
}

var _ ports.JudgmentStore = (*JudgmentStore)(nil)

// Save inserts or replaces a judgment within its engagement (idempotent by id).
func (s *JudgmentStore) Save(_ context.Context, j judgment.Judgment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.byEng[j.EngagementID]
	for i := range list {
		if list[i].ID == j.ID {
			return nil // insert-only: mirror postgres ON CONFLICT (id) DO NOTHING – never clobber an existing judgment's score/state
		}
	}
	s.byEng[j.EngagementID] = append(list, j)
	return nil
}

// ListByEngagement returns a copy of the engagement's judgments.
func (s *JudgmentStore) ListByEngagement(_ context.Context, engagementID shared.ID) ([]judgment.Judgment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.byEng[engagementID]
	out := make([]judgment.Judgment, len(src))
	copy(out, src)
	return out, nil
}

// ListBySubject returns the engagement's judgments about a given subject id.
func (s *JudgmentStore) ListBySubject(_ context.Context, engagementID, subjectID shared.ID) ([]judgment.Judgment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []judgment.Judgment
	for _, j := range s.byEng[engagementID] {
		if j.SubjectID == subjectID {
			out = append(out, j)
		}
	}
	return out, nil
}

// SetScoreState moves a judgment's score + state under optimistic concurrency. A version mismatch
// returns shared.ErrConflict (lost-update guard); an unknown id returns shared.ErrNotFound.
func (s *JudgmentStore) SetScoreState(_ context.Context, engagementID, id shared.ID, score int, state judgment.State, expectedVersion int) (judgment.Judgment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.byEng[engagementID]
	for i := range list {
		if list[i].ID == id {
			if list[i].Version != expectedVersion {
				return judgment.Judgment{}, fmt.Errorf("%w: judgment %s version %d != expected %d", shared.ErrConflict, id, list[i].Version, expectedVersion)
			}
			list[i].EvidenceScore = score
			list[i].State = state
			list[i].Version++
			return list[i], nil
		}
	}
	return judgment.Judgment{}, fmt.Errorf("judgment %s: %w", id, shared.ErrNotFound)
}
