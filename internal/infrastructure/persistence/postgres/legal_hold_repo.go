package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/legalhold"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// LegalHoldRepository is the Postgres tier for legal holds (#635). Append-only history per (tenant,
// engagement); at most one active hold per engagement (partial unique index). Every method runs under the
// ctx tenant via WithContextTenant (RLS) with an explicit tenant_id predicate as defense-in-depth.
type LegalHoldRepository struct {
	pool *pgxpool.Pool
}

var _ ports.LegalHoldStore = (*LegalHoldRepository)(nil)

func NewLegalHoldRepository(pool *pgxpool.Pool) *LegalHoldRepository {
	return &LegalHoldRepository{pool: pool}
}

func requireLegalHoldTenant(ctx context.Context) (shared.ID, error) {
	if t, ok := shared.TenantFrom(ctx); ok && t != "" {
		return t, nil
	}
	return "", fmt.Errorf("%w: legal hold operation requires a tenant in context", shared.ErrValidation)
}

func (r *LegalHoldRepository) Place(ctx context.Context, h legalhold.Hold) (legalhold.Hold, error) {
	tenant, err := requireLegalHoldTenant(ctx)
	if err != nil {
		return legalhold.Hold{}, err
	}
	if h.TenantID != tenant {
		return legalhold.Hold{}, fmt.Errorf("%w: legal-hold tenant disagrees with context", shared.ErrForbidden)
	}
	if err := h.Validate(); err != nil {
		return legalhold.Hold{}, err
	}
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		// Idempotent: if an active hold already exists, keep it (return its identity via the caller's h).
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM legal_holds WHERE tenant_id=$1 AND engagement_id=$2 AND released_at IS NULL)`,
			tenant.String(), h.EngagementID.String()).Scan(&exists); err != nil {
			return fmt.Errorf("check active hold: %w", err)
		}
		if exists {
			return nil
		}
		if _, err := tx.Exec(ctx, `INSERT INTO legal_holds (tenant_id, engagement_id, reason, placed_by, placed_at)
			VALUES ($1,$2,$3,$4,$5)`, tenant.String(), h.EngagementID.String(), h.Reason, h.PlacedBy, h.PlacedAt.UTC()); err != nil {
			return fmt.Errorf("insert legal hold: %w", err)
		}
		return nil
	})
	if err != nil {
		return legalhold.Hold{}, err
	}
	return h, nil
}

func (r *LegalHoldRepository) Release(ctx context.Context, engagementID shared.ID, releasedBy string, at time.Time) error {
	tenant, err := requireLegalHoldTenant(ctx)
	if err != nil {
		return err
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE legal_holds SET released_by=$3, released_at=$4
			WHERE tenant_id=$1 AND engagement_id=$2 AND released_at IS NULL`,
			tenant.String(), engagementID.String(), releasedBy, at.UTC())
		if err != nil {
			return fmt.Errorf("release legal hold: %w", err)
		}
		return nil
	})
}

func (r *LegalHoldRepository) IsHeld(ctx context.Context, engagementID shared.ID) (bool, error) {
	tenant, err := requireLegalHoldTenant(ctx)
	if err != nil {
		return false, err
	}
	var held bool
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM legal_holds WHERE tenant_id=$1 AND engagement_id=$2 AND released_at IS NULL)`,
			tenant.String(), engagementID.String()).Scan(&held)
	})
	return held, err
}

func (r *LegalHoldRepository) ListActive(ctx context.Context) ([]legalhold.Hold, error) {
	tenant, err := requireLegalHoldTenant(ctx)
	if err != nil {
		return nil, err
	}
	var out []legalhold.Hold
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT engagement_id, reason, placed_by, placed_at FROM legal_holds
			WHERE tenant_id=$1 AND released_at IS NULL ORDER BY engagement_id`, tenant.String())
		if err != nil {
			return fmt.Errorf("list legal holds: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var eng, reason, placedBy string
			var placedAt time.Time
			if err := rows.Scan(&eng, &reason, &placedBy, &placedAt); err != nil {
				return fmt.Errorf("scan legal hold: %w", err)
			}
			out = append(out, legalhold.Hold{TenantID: tenant, EngagementID: shared.ID(eng), Reason: reason, PlacedBy: placedBy, PlacedAt: placedAt})
		}
		return rows.Err()
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return out, err
}
