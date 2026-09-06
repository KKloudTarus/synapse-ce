package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// DASTRunStore persists the durable DAST verification run and reads it back, tenant-scoped.
type DASTRunStore interface {
	SaveDASTRun(context.Context, dastrun.Run) error
	GetDASTRun(ctx context.Context, tenantID, runID shared.ID) (dastrun.Run, error)
	// StartRun transitions a run 'queued' -> 'running' with a compare-and-set, reporting whether it won.
	// Only the worker that wins the transition executes the probe; a redelivered or lease-overlapping
	// worker that finds the run already running or terminal loses and must not probe. This is the entry
	// half of the run's CAS pair (StartRun claims execution, FinishRun records the outcome), so the probe
	// runs exactly once even though SaveDASTRun's terminal-immutability makes a losing start a silent
	// no-op that could otherwise be mistaken for a successful claim.
	StartRun(ctx context.Context, tenantID shared.ID, run dastrun.Run) (bool, error)
	// FinishRun writes a terminal run only if the stored run is still 'running', and reports whether it
	// won that transition. This is the compare-and-set that stops a redelivered or lease-overlapping
	// worker from overwriting a run another delivery already terminalized (e.g. clobbering a recorded
	// success with a late failure). The run must be terminal.
	FinishRun(ctx context.Context, tenantID shared.ID, run dastrun.Run) (bool, error)
}

// DASTRunEnqueuer atomically persists one queued run and its durable job, so a run is never enqueued
// without a record and never recorded without being enqueued.
type DASTRunEnqueuer interface {
	EnqueueDASTRun(ctx context.Context, run dastrun.Run, jobKind string, payload []byte) error
}
