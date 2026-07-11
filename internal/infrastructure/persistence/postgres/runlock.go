package postgres

import (
	"context"
	"fmt"
	"hash/fnv"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// RunLock implements ports.RunLocker with a PostgreSQL session advisory lock keyed by the
// run id (F9). The lock is held on a dedicated pooled connection for the duration of the
// execution and released (with the connection) afterwards – so across the API + the
// worker, at most one delivery of a given run executes at a time. A redelivery that finds
// the lock held gets ok=false and skips, preventing a duplicate live scan.
type RunLock struct {
	pool *pgxpool.Pool
}

// NewRunLock returns a Postgres-backed run locker.
func NewRunLock(pool *pgxpool.Pool) *RunLock { return &RunLock{pool: pool} }

var _ ports.RunLocker = (*RunLock)(nil)

// runLockKey derives a stable advisory-lock key from the run id (64-bit fnv → negligible
// collision; a collision only causes a spurious skip, which the at-least-once queue retries).
func runLockKey(runID string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("synapse:run:" + runID))
	return int64(h.Sum64())
}

func (l *RunLock) TryLock(ctx context.Context, runID string) (func(), bool, error) {
	conn, err := l.pool.Acquire(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("acquire run-lock connection: %w", err)
	}
	key := runLockKey(runID)
	var ok bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&ok); err != nil {
		conn.Release()
		return nil, false, fmt.Errorf("run advisory lock: %w", err)
	}
	if !ok {
		conn.Release() // another delivery is executing this run
		return nil, false, nil
	}
	release := func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", key)
		conn.Release()
	}
	return release, true, nil
}
