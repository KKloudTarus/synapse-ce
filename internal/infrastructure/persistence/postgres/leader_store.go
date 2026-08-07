package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// LeaderStore is the Postgres fenced-lease implementation of leader election. It is global
// control-plane state (no tenant scoping, no RLS; see migration 0061).
type LeaderStore struct{ pool *pgxpool.Pool }

// NewLeaderStore constructs the Postgres leader store.
func NewLeaderStore(pool *pgxpool.Pool) *LeaderStore { return &LeaderStore{pool: pool} }

var _ ports.LeaderStore = (*LeaderStore)(nil)

// Acquire atomically takes or renews leadership in a single upsert: it takes the lease when the
// row is absent, already held by holder (renewal), or expired (takeover, which bumps the fence),
// and otherwise leaves a live foreign lease untouched. held is true iff holder owns it afterwards.
func (s *LeaderStore) Acquire(ctx context.Context, resource, holder string, term time.Duration, now time.Time) (bool, int64, error) {
	expires := now.Add(term)
	var (
		winner string
		fence  int64
	)
	err := s.pool.QueryRow(ctx, `
		INSERT INTO leader_leases (resource, holder, fence, term_expires, updated_at)
		VALUES ($1, $2, 1, $3, $4)
		ON CONFLICT (resource) DO UPDATE SET
			holder = CASE
				WHEN leader_leases.holder = $2 OR leader_leases.term_expires <= $4 THEN $2
				ELSE leader_leases.holder END,
			fence = CASE
				WHEN leader_leases.holder <> $2 AND leader_leases.term_expires <= $4 THEN leader_leases.fence + 1
				ELSE leader_leases.fence END,
			term_expires = CASE
				WHEN leader_leases.holder = $2 OR leader_leases.term_expires <= $4 THEN $3
				ELSE leader_leases.term_expires END,
			updated_at = $4
		RETURNING holder, fence`,
		resource, holder, expires, now).Scan(&winner, &fence)
	if err != nil {
		return false, 0, err
	}
	return winner == holder, fence, nil
}

// Resign releases the lease if held by holder.
func (s *LeaderStore) Resign(ctx context.Context, resource, holder string, _ time.Time) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM leader_leases WHERE resource=$1 AND holder=$2`, resource, holder)
	return err
}
