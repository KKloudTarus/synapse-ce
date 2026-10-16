package memory

import (
	"context"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// CommentRepository is an in-memory per-finding comment thread (dev/tests).
type CommentRepository struct {
	mu       sync.RWMutex
	data     map[shared.ID][]finding.Comment // findingID -> comments (append order)
	mentions map[shared.ID][]shared.ID
}

// NewCommentRepository returns an empty in-memory comment repository.
func NewCommentRepository() *CommentRepository {
	return &CommentRepository{data: map[shared.ID][]finding.Comment{}, mentions: map[shared.ID][]shared.ID{}}
}

var _ ports.CommentRepository = (*CommentRepository)(nil)
var _ ports.CommentMentionRepository = (*CommentRepository)(nil)

func (r *CommentRepository) Add(_ context.Context, c finding.Comment) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[c.FindingID] = append(r.data[c.FindingID], c)
	return nil
}

// AddWithMentions appends one native comment and its canonical mention relation.
// The memory transaction checkpoint restores both on an outbox or audit failure.
func (r *CommentRepository) AddWithMentions(ctx context.Context, c finding.Comment, mentioned []shared.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	registerTenantCheckpoint(ctx, r, func(_ shared.ID) func() {
		data := make(map[shared.ID][]finding.Comment, len(r.data))
		for id, comments := range r.data {
			data[id] = append([]finding.Comment(nil), comments...)
		}
		mentions := make(map[shared.ID][]shared.ID, len(r.mentions))
		for id, users := range r.mentions {
			mentions[id] = append([]shared.ID(nil), users...)
		}
		return func() { r.mu.Lock(); defer r.mu.Unlock(); r.data, r.mentions = data, mentions }
	})
	c.MentionUserIDs = append([]shared.ID(nil), mentioned...)
	r.data[c.FindingID] = append(r.data[c.FindingID], c)
	r.mentions[c.ID] = append([]shared.ID(nil), mentioned...)
	return nil
}

func (r *CommentRepository) ListByEngagementFinding(_ context.Context, engagementID, findingID shared.ID) ([]finding.Comment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]finding.Comment, 0)
	for _, c := range r.data[findingID] {
		if c.EngagementID == engagementID {
			out = append(out, c)
		}
	}
	return out, nil
}
