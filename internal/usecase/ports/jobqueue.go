package ports

import (
	"context"
	"errors"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// QueuedJob is a unit of deferred work claimed from the JobQueue. Payload is an opaque,
// JSON-encoded job spec the worker decodes by Kind. Attempts counts deliveries (it has
// been incremented for this claim), so a handler can give up after N tries.
type QueuedJob struct {
	ID       string
	TenantID shared.ID
	Kind     string // e.g. "recon" | "sca"
	Payload  []byte
	Attempts int
	Fence    int64 // monotonically increasing generation assigned by Claim
}

// ErrStaleLease indicates that the claimed job was reclaimed by another worker.
var (
	// ErrStaleLease indicates that the claimed job was reclaimed by another worker.
	ErrStaleLease = errors.New("job lease is stale: the job was reclaimed by another worker")
	// ErrRetryable tells the claim loop to release the current delivery without consuming an
	// attempt. It is used when another worker owns the run-level execution lease.
	ErrRetryable = errors.New("job execution is temporarily owned by another worker")
)

type JobStats struct {
	Queued         int        `json:"queued"`
	Claimed        int        `json:"claimed"`
	Failed         int        `json:"failed"`
	Done           int        `json:"done"`
	OldestActiveAt *time.Time `json:"oldest_active_at,omitempty"`
}

type JobStatus struct {
	Attempts     int
	DeadLettered bool
}

type JobStatusReader interface {
	JobStatus(ctx context.Context, id string) (JobStatus, error)
}

// AggregateJobQueueStatsReader reads queue totals across all tenants for
// operator-only telemetry. Implementations retain tenant isolation internally
// (mirroring Claim's per-tenant RLS scoping) and never expose tenant labels.
type AggregateJobQueueStatsReader interface {
	AggregateJobQueueStats(ctx context.Context, kinds ...string) (JobStats, error)
}

// SCAObserver receives terminal SCA outcomes. Durations are recorded only for
// completed synchronous or asynchronous scan execution, not queue/gate failures.
type SCAObserver interface {
	ObserveSCAOutcome(outcome string)
	ObserveSCAScan(duration time.Duration, outcome string)
}

// JobQueue is a durable, at-least-once work queue with a visibility timeout.
// It replaces the in-process jobs.Pool (which loses queued work on restart and
// cannot reach a separate worker process). Claim hands a job to exactly one worker for
// the visibility window; if the worker dies without Complete/Fail, the lease expires and
// the job is redelivered (hence at-least-once – handlers must be idempotent). A Postgres
// adapter (SELECT … FOR UPDATE SKIP LOCKED) is the durable implementation; an in-memory
// adapter is the single-process/dev degrade.
type JobQueue interface {
	// Enqueue persists a new job and returns its id.
	Enqueue(ctx context.Context, kind string, payload []byte) (string, error)
	// Claim atomically leases the next available job for visibility, or returns
	// (nil, nil) when none is ready. A claimed job whose lease has expired is eligible
	// again (crash recovery). Each claim increments and returns a fence generation; callers
	// must supply it to Heartbeat, Complete, Fail, and Deadletter. When kinds are given, only
	// jobs of those kinds are claimed
	// – so specialized workers (a privileged recon worker, an in-process SCA worker) draw
	// only the kinds they can handle and never park each other's jobs; empty = any kind.
	Claim(ctx context.Context, visibility time.Duration, kinds ...string) (*QueuedJob, error)
	// Heartbeat extends a claimed job's lease only when fence is still its current claim
	// generation. ErrStaleLease means another worker owns this job now; abandon it silently
	// and do not publish terminal state or evidence.
	Heartbeat(ctx context.Context, id string, fence int64, extend time.Duration) error
	// Complete marks a job done only when fence is still its current claim generation.
	// ErrStaleLease means another worker owns this job now; abandon it silently and do not
	// publish terminal state or evidence.
	Complete(ctx context.Context, id string, fence int64) error
	// Fail requeues a job only when fence is still its current claim generation. The caller
	// decides when Attempts is high enough to stop retrying. ErrStaleLease means another
	// worker owns this job now; abandon it silently and do not publish terminal state or evidence.
	Fail(ctx context.Context, id string, fence int64, retryIn time.Duration) error
	// Retry releases a claimed job with backoff without consuming a delivery attempt. It is
	// reserved for contention outcomes such as a live run-level execution lease.
	Retry(ctx context.Context, id string, fence int64, retryIn time.Duration) error
	// Deadletter marks a job permanently FAILED only when fence is still its current claim
	// generation. This terminal state is distinct from done so an abandoned authorized scan is
	// operator-visible and queryable, not silently indistinguishable from success. ErrStaleLease
	// means another worker owns this job now; abandon it silently and do not publish terminal state
	// or evidence.
	Deadletter(ctx context.Context, id string, fence int64) error
	// Depth returns the number of NOT-yet-terminal jobs (queued or claimed/in-flight) – the
	// admission signal for durable backpressure. When kinds are given only those kinds are
	// counted (empty = any). 'done' and 'failed' (dead-lettered) are terminal and excluded.
	Depth(ctx context.Context, kinds ...string) (int, error)
	Stats(ctx context.Context, kinds ...string) (JobStats, error)
}

// RunLocker guards a SINGLE ACTIVE execution per run across processes (F9). The durable
// queue is at-least-once, so a redelivery (lease expiry / crash / heartbeat failure) can
// re-invoke a run another worker is STILL executing – duplicating a live scan and its
// custody entries. TryLock acquires an exclusive lease on runID held for the execution;
// a concurrent delivery gets ok=false and skips. release frees the lease.
type RunLocker interface {
	TryLock(ctx context.Context, runID string) (release func(), ok bool, err error)
}

// LeaseRunLocker is an optional RunLocker capability for locks whose lease can be LOST mid-run
// – a row lease (renewed by a background goroutine), unlike a connection-pinned advisory lock
// that cannot expire while held. TryLockLeased is TryLock that also returns a context cancelled
// when the lease is lost (renew matched no owned row, or repeated renew failure past the TTL so
// another worker could steal it) – so the caller ABORTS the in-flight execution instead of
// continuing against a host another worker may now own (the double-live-run hazard). The
// returned context is also cancelled when the parent ctx is (shutdown) and on release.
type LeaseRunLocker interface {
	RunLocker
	TryLockLeased(ctx context.Context, runID string) (leaseCtx context.Context, release func(), ok bool, err error)
}
