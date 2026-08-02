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
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return "", fmt.Errorf("%w: tenant context is required for durable job", shared.ErrValidation)
	}
	if payload == nil {
		payload = []byte{} // a nil []byte encodes as SQL NULL; the column is NOT NULL and empty is valid
	}
	if _, err := q.pool.Exec(ctx,
		`INSERT INTO jobs (id, tenant_id, kind, payload, status, available_at) VALUES ($1, $2, $3, $4, 'queued', now())`,
		id, tenantID.String(), kind, payload); err != nil {
		return "", fmt.Errorf("enqueue job: %w", err)
	}
	return id, nil
}

func (q *JobQueue) Claim(ctx context.Context, visibility time.Duration, kinds ...string) (*ports.QueuedJob, error) {
	tenantRows, err := q.pool.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list queue tenants: %w", err)
	}
	tenantIDs := []shared.ID{}
	for tenantRows.Next() {
		var tenant string
		if err := tenantRows.Scan(&tenant); err != nil {
			tenantRows.Close()
			return nil, fmt.Errorf("scan queue tenant: %w", err)
		}
		tenantIDs = append(tenantIDs, shared.ID(tenant))
	}
	if err := tenantRows.Err(); err != nil {
		tenantRows.Close()
		return nil, fmt.Errorf("list queue tenants: %w", err)
	}
	tenantRows.Close()
	for _, tenantID := range tenantIDs {
		var job *ports.QueuedJob
		err := WithTenantTx(ctx, q.pool, tenantID, func(tx pgx.Tx) error {
			kindFilter, args := "", []any{visibility.Seconds()}
			if len(kinds) > 0 {
				kindFilter = " AND kind = ANY($2)"
				args = append(args, kinds)
			}
			var claimed ports.QueuedJob
			err := tx.QueryRow(ctx,
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
				 RETURNING id, tenant_id, kind, payload, attempts`,
				args...).Scan(&claimed.ID, &claimed.TenantID, &claimed.Kind, &claimed.Payload, &claimed.Attempts)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("claim job: %w", err)
			}
			job = &claimed
			return nil
		})
		if err != nil {
			return nil, err
		}
		if job != nil {
			return job, nil
		}
	}
	return nil, nil
}

func (q *JobQueue) Heartbeat(ctx context.Context, id string, extend time.Duration) error {
	return WithContextTenantTx(ctx, q.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
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
	})
}

func (q *JobQueue) Complete(ctx context.Context, id string) error {
	return WithContextTenantTx(ctx, q.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE jobs SET status='done', claimed_until=NULL, updated_at=now() WHERE id=$1`, id)
		if err != nil {
			return fmt.Errorf("complete job: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("job %s: %w", id, shared.ErrNotFound)
		}
		return nil
	})
}

func (q *JobQueue) Deadletter(ctx context.Context, id string) error {
	return WithContextTenantTx(ctx, q.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE jobs SET status='failed', claimed_until=NULL, updated_at=now() WHERE id=$1`, id)
		if err != nil {
			return fmt.Errorf("deadletter job: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("job %s: %w", id, shared.ErrNotFound)
		}
		return nil
	})
}

// Depth counts not-yet-terminal jobs (queued or claimed) – the durable-backpressure
// admission signal. 'done' and 'failed' are terminal and excluded. Optional kind filter.
func (q *JobQueue) Depth(ctx context.Context, kinds ...string) (int, error) {
	var n int
	err := WithContextTenantTx(ctx, q.pool, func(tx pgx.Tx) error {
		query := `SELECT count(*) FROM jobs WHERE status IN ('queued','claimed')`
		var args []any
		if len(kinds) > 0 {
			query += ` AND kind = ANY($1)`
			args = append(args, kinds)
		}
		if err := tx.QueryRow(ctx, query, args...).Scan(&n); err != nil {
			return fmt.Errorf("queue depth: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (q *JobQueue) Fail(ctx context.Context, id string, retryIn time.Duration) error {
	return WithContextTenantTx(ctx, q.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
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
	})
}
