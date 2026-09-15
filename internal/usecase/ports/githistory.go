package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
)

// GitHistoryResult represents bounded first-parent commit history evidence.
type GitHistoryResult struct {
	HeadCommit      string                             `json:"head_commit"`
	Requested       int                                `json:"requested"`
	Evaluated       int                                `json:"evaluated"`
	ReachedRoot     bool                               `json:"reached_root"`
	ShallowBoundary bool                               `json:"shallow_boundary"`
	DirtyWorktree   bool                               `json:"dirty_worktree"`
	Commits         []measure.BehavioralCommitEvidence `json:"commits,omitempty"`
	Available       bool                               `json:"available"`
	Reason          string                             `json:"reason,omitempty"`
}

// GitHistoryCollector reads bounded first-parent commit history from a local git repository.
type GitHistoryCollector interface {
	CollectHistory(ctx context.Context, dir string, head string, depth int) (GitHistoryResult, error)
}
