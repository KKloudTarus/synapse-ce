package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// CommentMentionRepository persists an immutable canonical mention relation with
// a finding comment. Native comments use it when available; legacy and mirrored
// comments retain the body-only CommentRepository path.
type CommentMentionRepository interface {
	AddWithMentions(context.Context, finding.Comment, []shared.ID) error
}
