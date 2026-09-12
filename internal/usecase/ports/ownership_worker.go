package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// OwnershipWork is a frozen input, not a request to reread a mutable workspace.
// A job may contain many items; readers and commits are bounded independently.
type OwnershipWork struct {
	Input          ownership.Input `json:"input"`
	FindingVersion int             `json:"finding_version"`
	PolicyID       shared.ID       `json:"policy_id"`
	PolicyVersion  int             `json:"policy_version"`
	PolicyRevision int             `json:"policy_revision"`
	BindingHash    string          `json:"binding_hash"`
	RunID          shared.ID       `json:"run_id,omitempty"`
	Mode           string          `json:"mode"`
}

type OwnershipWorkerStore interface {
	OwnershipRunStarter
	OwnershipRunReplayer
	// Dispatch scans a bounded page per tenant, atomically freezing inputs,
	// enqueueing work and acknowledging only the observed producer generation.
	DispatchOwnership(context.Context, string, int) (int, error)
	LoadOwnershipWork(context.Context, QueuedJob, int) ([]OwnershipWork, error)
	CommitOwnershipWork(context.Context, QueuedJob, OwnershipWork, ownership.Result, string, bool) error
	FailOwnershipWork(context.Context, QueuedJob) error
}

type OwnershipRunReplayer interface {
	ReplayOwnershipRun(context.Context, shared.ID, shared.ID, int) error
}
