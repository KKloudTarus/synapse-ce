package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// LeaseRunLock implements ports.RunLocker via a jobs_run_lock ROW lease instead of a session
// advisory lock. Unlike RunLock it does NOT hold a pooled connection for the duration of the
// run – each operation borrows a connection transiently – so N concurrent runs cannot starve
// the pool (the ≤8-default-pool hazard the hostile review flagged). A background renewer
// extends the lease while the run is live; a crash lets the lease expire so another worker can
// reclaim it. Used for RECON; the agent SESSION lock stays the advisory RunLock (it must not
// expire mid-LLM-loop). owner is a per-process id so renew/release are owner-scoped.
type LeaseRunLock struct {
	pool  *pgxpool.Pool
	owner string
	lease time.Duration
}

// NewLeaseRunLock returns a row-lease run locker. lease is the claim TTL (set it comfortably
// above the longest run, e.g. ReconTimeout + a minute); the renewer ticks at lease/4 so several
// renews fall inside one TTL.
func NewLeaseRunLock(pool *pgxpool.Pool, owner string, lease time.Duration) *LeaseRunLock {
	if lease <= 0 {
		lease = 5 * time.Minute
	}
	return &LeaseRunLock{pool: pool, owner: owner, lease: lease}
}

var (
	_ ports.RunLocker      = (*LeaseRunLock)(nil)
	_ ports.LeaseRunLocker = (*LeaseRunLock)(nil)
)

// TryLock claims the lease (see TryLockLeased) and discards the lease-loss context – for
// callers that don't observe lease loss (e.g. the stale-run sweeper's liveness probe).
func (l *LeaseRunLock) TryLock(ctx context.Context, runID string) (func(), bool, error) {
	_, release, ok, err := l.TryLockLeased(ctx, runID)
	return release, ok, err
}

// TryLockLeased claims the lease for runID if it is free or expired. On success it starts a
// renewer and returns: a leaseCtx cancelled when the lease is LOST (so the caller aborts the
// in-flight run), plus a release that stops the renewer, cancels leaseCtx, and deletes the
// owner's row. A claim held by a live owner returns ok=false (the at-least-once queue retries).
func (l *LeaseRunLock) TryLockLeased(ctx context.Context, runID string) (context.Context, func(), bool, error) {
	// Acquire iff there is no row, or the existing claim has expired. Uses DB now() as the single
	// clock. RETURNING yields a row only when the INSERT or the (expired-claim) UPDATE applied.
	var got string
	err := l.pool.QueryRow(ctx,
		`INSERT INTO jobs_run_lock (run_id, owner, claimed_until, created_at)
		 VALUES ($1, $2, now() + $3::interval, now())
		 ON CONFLICT (run_id) DO UPDATE
		   SET owner = EXCLUDED.owner, claimed_until = EXCLUDED.claimed_until
		   WHERE jobs_run_lock.claimed_until < now()
		 RETURNING owner`,
		runID, l.owner, l.lease.String()).Scan(&got)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, false, nil // a live owner holds the lease
	}
	if err != nil {
		return nil, nil, false, fmt.Errorf("acquire run lease: %w", err)
	}

	// leaseCtx is cancelled on: parent ctx done (shutdown), lease loss (renewer), or release.
	leaseCtx, leaseCancel := context.WithCancel(ctx)
	rctx, stopRenew := context.WithCancel(context.Background())
	var once sync.Once
	go l.renew(rctx, runID, leaseCancel)
	release := func() {
		once.Do(func() {
			stopRenew()
			leaseCancel()
			_, _ = l.pool.Exec(context.Background(),
				`DELETE FROM jobs_run_lock WHERE run_id=$1 AND owner=$2`, runID, l.owner)
		})
	}
	return leaseCtx, release, true, nil
}

// renew extends the lease, owner-scoped, while the run is live. It ticks at lease/4 so several
// renews fall inside one TTL – a single transient DB stall cannot let the claim expire and be
// stolen (the double-run hazard). Each renew gets its own short timeout so a stalled call does
// not wedge the loop. On a DEFINITIVE loss (renew matched no owned row – the claim expired and
// another worker stole it, or the row was deleted) OR a full lease-TTL window of consecutive
// renew failures (the claim can now be stolen), it calls onLost – cancelling the run's lease
// context so the caller ABORTS – and stops. A silently-lost lease is exactly what would let a
// second worker double-run an admitted action against a live host.
func (l *LeaseRunLock) renew(ctx context.Context, runID string, onLost func()) {
	interval := l.lease / 4
	if interval <= 0 {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	lastOK := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rc, cancel := context.WithTimeout(ctx, interval)
			tag, err := l.pool.Exec(rc,
				`UPDATE jobs_run_lock SET claimed_until = now() + $1::interval WHERE run_id=$2 AND owner=$3`,
				l.lease.String(), runID, l.owner)
			cancel()
			switch {
			case err == nil && tag.RowsAffected() == 0:
				// Our owned, unexpired row is gone → the lease was stolen/expired. Definitive loss.
				slog.Warn("run lease lost (renew matched no owned row); aborting in-flight run", "run", runID)
				onLost()
				return
			case err == nil:
				lastOK = time.Now()
			case ctx.Err() == nil: // err != nil, not a shutdown
				slog.Warn("run lease renew failed; will retry until the TTL elapses", "run", runID, "err", err)
				if time.Since(lastOK) >= l.lease {
					// The full TTL has elapsed since the last successful renew – another worker
					// can now claim the expired lease, so abort rather than risk a double-run.
					slog.Warn("run lease expired after repeated renew failures; aborting in-flight run", "run", runID)
					onLost()
					return
				}
			}
		}
	}
}
