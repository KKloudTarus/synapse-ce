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

// JobQueue is the durable PostgreSQL queue with tenant-bound at-least-once delivery.
type JobQueue struct {
	pool *pgxpool.Pool
	ids  ports.IDGenerator
}

func NewJobQueue(pool *pgxpool.Pool, ids ports.IDGenerator) *JobQueue {
	return &JobQueue{pool: pool, ids: ids}
}

var _ ports.JobQueue = (*JobQueue)(nil)
var _ ports.JobStatusReader = (*JobQueue)(nil)
var _ ports.AggregateJobQueueStatsReader = (*JobQueue)(nil)

func (q *JobQueue) Enqueue(ctx context.Context, kind string, payload []byte) (string, error) {
	if kind == "" {
		return "", fmt.Errorf("%w: job kind is required", shared.ErrValidation)
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return "", fmt.Errorf("%w: tenant context is required for durable job", shared.ErrValidation)
	}
	id := q.ids.NewID().String()
	if payload == nil {
		payload = []byte{}
	}
	err := WithTenant(ctx, q.pool, tenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO jobs (id,tenant_id,kind,payload,status,available_at) VALUES ($1,$2,$3,$4,'queued',now())`, id, tenantID.String(), kind, payload)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("enqueue job: %w", err)
	}
	return id, nil
}

func (q *JobQueue) Claim(ctx context.Context, visibility time.Duration, kinds ...string) (*ports.QueuedJob, error) {
	rows, err := q.pool.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list queue tenants: %w", err)
	}
	var tenantIDs []shared.ID
	for rows.Next() {
		var tenantID shared.ID
		if err := rows.Scan(&tenantID); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan queue tenant: %w", err)
		}
		tenantIDs = append(tenantIDs, tenantID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("list queue tenants: %w", err)
	}
	rows.Close()

	for _, tenantID := range tenantIDs {
		var claimed *ports.QueuedJob
		err := WithTenant(ctx, q.pool, tenantID.String(), func(tx pgx.Tx) error {
			kindFilter, args := "", []any{visibility.Seconds()}
			if len(kinds) > 0 {
				kindFilter = " AND kind = ANY($2)"
				args = append(args, kinds)
			}
			var job ports.QueuedJob
			err := tx.QueryRow(ctx, `UPDATE jobs SET status='claimed',attempts=attempts+1,claim_fence=claim_fence+1,claimed_until=now()+make_interval(secs=>$1),updated_at=now()
				WHERE id=(SELECT id FROM jobs WHERE status IN ('queued','claimed') AND available_at<=now() AND (status='queued' OR claimed_until<now())`+kindFilter+`
				ORDER BY available_at,id FOR UPDATE SKIP LOCKED LIMIT 1)
				RETURNING id,tenant_id,kind,payload,attempts,claim_fence`, args...).Scan(&job.ID, &job.TenantID, &job.Kind, &job.Payload, &job.Attempts, &job.Fence)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("claim job: %w", err)
			}
			claimed = &job
			return nil
		})
		if err != nil {
			return nil, err
		}
		if claimed != nil {
			return claimed, nil
		}
	}
	return nil, nil
}

func (q *JobQueue) Heartbeat(ctx context.Context, id string, fence int64, extend time.Duration) error {
	return q.update(ctx, id, fence, `UPDATE jobs SET claimed_until=now()+make_interval(secs=>$3),updated_at=now() WHERE id=$1 AND status='claimed' AND claim_fence=$2`, extend.Seconds())
}

func (q *JobQueue) Complete(ctx context.Context, id string, fence int64) error {
	return q.update(ctx, id, fence, `UPDATE jobs SET status='done',claimed_until=NULL,updated_at=now() WHERE id=$1 AND status='claimed' AND claim_fence=$2`)
}

func (q *JobQueue) Deadletter(ctx context.Context, id string, fence int64) error {
	return q.update(ctx, id, fence, `UPDATE jobs SET status='failed',claimed_until=NULL,updated_at=now() WHERE id=$1 AND status='claimed' AND claim_fence=$2`)
}

func (q *JobQueue) Fail(ctx context.Context, id string, fence int64, retryIn time.Duration) error {
	return q.update(ctx, id, fence, `UPDATE jobs SET status='queued',claimed_until=NULL,available_at=now()+$3::interval,updated_at=now() WHERE id=$1 AND status='claimed' AND claim_fence=$2`, retryIn.String())
}

// Retry releases a contention delivery without charging it against the job's attempt budget.
func (q *JobQueue) Retry(ctx context.Context, id string, fence int64, retryIn time.Duration) error {
	return q.update(ctx, id, fence, `UPDATE jobs SET status='queued',claimed_until=NULL,available_at=now()+$3::interval,attempts=GREATEST(attempts-1, 0),updated_at=now() WHERE id=$1 AND status='claimed' AND claim_fence=$2`, retryIn.String())
}

func (q *JobQueue) update(ctx context.Context, id string, fence int64, query string, args ...any) error {
	return WithContextTenant(ctx, q.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, query, append([]any{id, fence}, args...)...)
		if err != nil {
			return fmt.Errorf("update job %s: %w", id, err)
		}
		if tag.RowsAffected() != 0 {
			return nil
		}

		var exists bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM jobs WHERE id=$1)`, id).Scan(&exists)
		if err != nil {
			return fmt.Errorf("check job %s after fenced update: %w", id, err)
		}
		if !exists {
			return fmt.Errorf("job %s: %w", id, shared.ErrNotFound)
		}
		return fmt.Errorf("job %s fence %d: %w", id, fence, ports.ErrStaleLease)
	})
}

func (q *JobQueue) Depth(ctx context.Context, kinds ...string) (count int, err error) {
	err = WithContextTenant(ctx, q.pool, func(tx pgx.Tx) error {
		query := `SELECT count(*) FROM jobs WHERE status IN ('queued','claimed')`
		var args []any
		if len(kinds) > 0 {
			query += ` AND kind=ANY($1)`
			args = append(args, kinds)
		}
		return tx.QueryRow(ctx, query, args...).Scan(&count)
	})
	return count, err
}

func (q *JobQueue) Stats(ctx context.Context, kinds ...string) (stats ports.JobStats, err error) {
	err = WithContextTenant(ctx, q.pool, func(tx pgx.Tx) error {
		query := `SELECT count(*) FILTER (WHERE status='queued'), count(*) FILTER (WHERE status='claimed'), count(*) FILTER (WHERE status='failed'), count(*) FILTER (WHERE status='done'), min(available_at) FILTER (WHERE status IN ('queued','claimed')) FROM jobs`
		var args []any
		if len(kinds) > 0 {
			query += ` WHERE kind=ANY($1)`
			args = append(args, kinds)
		}
		return tx.QueryRow(ctx, query, args...).Scan(&stats.Queued, &stats.Claimed, &stats.Failed, &stats.Done, &stats.OldestActiveAt)
	})
	return stats, err
}

func (q *JobQueue) JobStatus(ctx context.Context, id string) (status ports.JobStatus, err error) {
	err = WithContextTenant(ctx, q.pool, func(tx pgx.Tx) error {
		var jobState string
		if err := tx.QueryRow(ctx, `SELECT attempts,status FROM jobs WHERE id=$1`, id).Scan(&status.Attempts, &jobState); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("job %s: %w", id, shared.ErrNotFound)
			}
			return err
		}
		status.DeadLettered = jobState == "failed"
		return nil
	})
	return status, err
}

// AggregateJobQueueStats aggregates each tenant's RLS-scoped queue statistics for the
// operator metrics collector. The tenant enumeration mirrors Claim so the forced-RLS
// per-tenant transaction remains the only way any job row is read; no tenant label is
// ever attached to the aggregated totals.
func (q *JobQueue) AggregateJobQueueStats(ctx context.Context, kinds ...string) (ports.JobStats, error) {
	rows, err := q.pool.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
	if err != nil {
		return ports.JobStats{}, fmt.Errorf("list queue tenants: %w", err)
	}
	var tenantIDs []shared.ID
	for rows.Next() {
		var tenantID shared.ID
		if err := rows.Scan(&tenantID); err != nil {
			rows.Close()
			return ports.JobStats{}, fmt.Errorf("scan queue tenant: %w", err)
		}
		tenantIDs = append(tenantIDs, tenantID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return ports.JobStats{}, fmt.Errorf("list queue tenants: %w", err)
	}
	rows.Close()

	var total ports.JobStats
	for _, tenantID := range tenantIDs {
		stats, err := q.Stats(shared.WithTenant(ctx, tenantID), kinds...)
		if err != nil {
			return ports.JobStats{}, fmt.Errorf("queue stats for tenant: %w", err)
		}
		total.Queued += stats.Queued
		total.Claimed += stats.Claimed
		total.Failed += stats.Failed
		total.Done += stats.Done
		if stats.OldestActiveAt != nil && (total.OldestActiveAt == nil || stats.OldestActiveAt.Before(*total.OldestActiveAt)) {
			at := *stats.OldestActiveAt
			total.OldestActiveAt = &at
		}
	}
	return total, nil
}
