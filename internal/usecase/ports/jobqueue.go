package ports

import (
	"context"
	"time"
)

// QueuedJob is a unit of deferred work claimed from the JobQueue. Payload is an opaque,
// JSON-encoded job spec the worker decodes by Kind. Attempts counts deliveries (it has
// been incremented for this claim), so a handler can give up after N tries.
type QueuedJob struct {
	ID       string
	Kind     string // e.g. "recon" | "sca"
	Payload  []byte
	Attempts int
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
	// again (crash recovery). When kinds are given, only jobs of those kinds are claimed
	// – so specialized workers (a privileged recon worker, an in-process SCA worker) draw
	// only the kinds they can handle and never park each other's jobs; empty = any kind.
	Claim(ctx context.Context, visibility time.Duration, kinds ...string) (*QueuedJob, error)
	// Heartbeat extends a claimed job's lease while it is still being processed.
	Heartbeat(ctx context.Context, id string, extend time.Duration) error
	// Complete marks a job done (it will not be redelivered).
	Complete(ctx context.Context, id string) error
	// Fail requeues a job to run again after retryIn (backoff); the caller decides when
	// Attempts is high enough to stop retrying.
	Fail(ctx context.Context, id string, retryIn time.Duration) error
	// Deadletter marks a job permanently FAILED (gave up after MaxAttempts) – a terminal
	// state distinct from done so an abandoned authorized scan is operator-visible and
	// queryable, not silently indistinguishable from success.
	Deadletter(ctx context.Context, id string) error
	// Depth returns the number of NOT-yet-terminal jobs (queued or claimed/in-flight) – the
	// admission signal for durable backpressure. When kinds are given only those kinds are
	// counted (empty = any). 'done' and 'failed' (dead-lettered) are terminal and excluded.
	Depth(ctx context.Context, kinds ...string) (int, error)
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
