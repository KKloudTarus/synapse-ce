package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// JobQueue is the durable ports.JobQueue on PostgreSQL. Claim uses FOR UPDATE
// SKIP LOCKED so concurrent workers never hand the same job to two claimants, and an
// expired lease (claimed_until < now) makes a job claimable again – at-least-once
// delivery with crash recovery.
type JobQueue struct {
	pool *pgxpool.Pool
	ids  ports.IDGenerator
}

// NewJobQueue returns a Postgres-backed job queue.
func NewJobQueue(pool *pgxpool.Pool, ids ports.IDGenerator) *JobQueue {
	return &JobQueue{pool: pool, ids: ids}
}

var _ ports.JobQueue = (*JobQueue)(nil)

func (q *JobQueue) Enqueue(ctx context.Context, kind string, payload []byte) (string, error) {
	if kind == "" {
		return "", fmt.Errorf("%w: job kind is required", shared.ErrValidation)
	}
	id := q.ids.NewID().String()
	if payload == nil {
		payload = []byte{} // a nil []byte encodes as SQL NULL; the column is NOT NULL and empty is valid
	}
	if _, err := q.pool.Exec(ctx,
		`INSERT INTO jobs (id, kind, payload, status, available_at) VALUES ($1, $2, $3, 'queued', now())`,
		id, kind, payload); err != nil {
		return "", fmt.Errorf("enqueue job: %w", err)
	}
	return id, nil
}

func (q *JobQueue) Claim(ctx context.Context, visibility time.Duration, kinds ...string) (*ports.QueuedJob, error) {
	// Optional kind filter: only claim the kinds this worker handles (empty = any).
	kindFilter, args := "", []any{visibility.Seconds()}
	if len(kinds) > 0 {
		kindFilter = " AND kind = ANY($2)"
		args = append(args, kinds)
	}
	var j ports.QueuedJob
	err := q.pool.QueryRow(ctx,
		`UPDATE jobs SET status='claimed', attempts=attempts+1,
		        claimed_until = now() + make_interval(secs => $1), updated_at = now()
		 WHERE id = (
		     SELECT id FROM jobs
		     WHERE status <> 'done'
		       AND available_at <= now()
		       AND (status = 'queued' OR claimed_until < now())`+kindFilter+`
		     ORDER BY available_at
		     FOR UPDATE SKIP LOCKED
		     LIMIT 1
		 )
		 RETURNING id, kind, payload, attempts`,
		args...).Scan(&j.ID, &j.Kind, &j.Payload, &j.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil // nothing ready
	}
	if err != nil {
		return nil, fmt.Errorf("claim job: %w", err)
	}
	return &j, nil
}

func (q *JobQueue) Heartbeat(ctx context.Context, id string, extend time.Duration) error {
	tag, err := q.pool.Exec(ctx,
		`UPDATE jobs SET claimed_until = now() + make_interval(secs => $2), updated_at = now()
		 WHERE id = $1 AND status = 'claimed'`,
		id, extend.Seconds())
	if err != nil {
		return fmt.Errorf("heartbeat job: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("job %s: %w", id, shared.ErrNotFound)
	}
	return nil
}

func (q *JobQueue) Complete(ctx context.Context, id string) error {
	tag, err := q.pool.Exec(ctx,
		`UPDATE jobs SET status='done', claimed_until=NULL, updated_at=now() WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("complete job: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("job %s: %w", id, shared.ErrNotFound)
	}
	return nil
}

func (q *JobQueue) Deadletter(ctx context.Context, id string) error {
	tag, err := q.pool.Exec(ctx,
		`UPDATE jobs SET status='failed', claimed_until=NULL, updated_at=now() WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("deadletter job: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("job %s: %w", id, shared.ErrNotFound)
	}
	return nil
}

// Depth counts not-yet-terminal jobs (queued or claimed) – the durable-backpressure
// admission signal. 'done' and 'failed' are terminal and excluded. Optional kind filter.
func (q *JobQueue) Depth(ctx context.Context, kinds ...string) (int, error) {
	query := `SELECT count(*) FROM jobs WHERE status IN ('queued','claimed')`
	var args []any
	if len(kinds) > 0 {
		query += ` AND kind = ANY($1)`
		args = append(args, kinds)
	}
	var n int
	if err := q.pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("queue depth: %w", err)
	}
	return n, nil
}

func (q *JobQueue) Fail(ctx context.Context, id string, retryIn time.Duration) error {
	tag, err := q.pool.Exec(ctx,
		`UPDATE jobs SET status='queued', claimed_until=NULL,
		        available_at = now() + make_interval(secs => $2), updated_at = now()
		 WHERE id = $1`,
		id, retryIn.Seconds())
	if err != nil {
		return fmt.Errorf("fail job: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("job %s: %w", id, shared.ErrNotFound)
	}
	return nil
}
