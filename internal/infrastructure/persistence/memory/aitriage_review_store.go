package memory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aitriagereview"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type AITriageReviewStore struct {
	mu   sync.RWMutex
	data map[shared.ID]aitriagereview.Review
}

func NewAITriageReviewStore() *AITriageReviewStore {
	return &AITriageReviewStore{data: map[shared.ID]aitriagereview.Review{}}
}

func (s *AITriageReviewStore) UpsertPending(_ context.Context, review aitriagereview.Review) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, current := range s.data {
		if current.TenantID == review.TenantID && current.EngagementID == review.EngagementID &&
			current.DedupKey == review.DedupKey && current.PolicyVersion == review.PolicyVersion &&
			current.PromptVersion == review.PromptVersion && current.ProposerModel == review.ProposerModel &&
			current.VerifierModel == review.VerifierModel {
			if current.State == aitriagereview.StatePending {
				review.ID, review.CreatedAt, review.Owner = current.ID, current.CreatedAt, current.Owner
				review.Version = current.Version + 1
				s.data[id] = review
			}
			return nil
		}
	}
	s.data[review.ID] = review
	return nil
}

func (s *AITriageReviewStore) Get(_ context.Context, tenantID, id shared.ID) (aitriagereview.Review, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	review, ok := s.data[id]
	if !ok || review.TenantID != tenantID {
		return aitriagereview.Review{}, shared.ErrNotFound
	}
	return review, nil
}

func (s *AITriageReviewStore) List(_ context.Context, tenantID shared.ID, filter ports.AITriageReviewFilter) ([]aitriagereview.Review, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]aitriagereview.Review, 0)
	for _, review := range s.data {
		if review.TenantID != tenantID || (filter.Severity != "" && review.Severity != filter.Severity) ||
			(filter.ProjectID != "" && review.ProjectID != filter.ProjectID) || (filter.State != "" && review.State != filter.State) ||
			(filter.CWE != "" && !strings.EqualFold(review.CWE, filter.CWE)) {
			continue
		}
		out = append(out, review)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (s *AITriageReviewStore) SaveDecision(_ context.Context, review aitriagereview.Review, expectedVersion int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.data[review.ID]
	if !ok || current.TenantID != review.TenantID {
		return shared.ErrNotFound
	}
	if current.Version != expectedVersion || current.State != aitriagereview.StatePending {
		return fmt.Errorf("%w: AI-triage review changed", shared.ErrConflict)
	}
	s.data[review.ID] = review
	return nil
}

func (s *AITriageReviewStore) SaveOwner(_ context.Context, review aitriagereview.Review, expectedVersion int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.data[review.ID]
	if !ok || current.TenantID != review.TenantID {
		return shared.ErrNotFound
	}
	if current.Version != expectedVersion || current.State != aitriagereview.StatePending {
		return fmt.Errorf("%w: AI-triage review changed", shared.ErrConflict)
	}
	s.data[review.ID] = review
	return nil
}

var _ ports.AITriageReviewStore = (*AITriageReviewStore)(nil)
