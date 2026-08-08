package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ScannedImageStore is the Postgres-backed scanned-image digest index (#446). Every operation routes
// through WithTenant so the Row Level Security policy on scanned_image (migration 0063) enforces
// tenant isolation at the database — a query that bypassed WithTenant would resolve the tenant to
// NULL and see nothing.
type ScannedImageStore struct{ pool *pgxpool.Pool }

// NewScannedImageStore constructs the Postgres scanned-image store.
func NewScannedImageStore(pool *pgxpool.Pool) *ScannedImageStore {
	return &ScannedImageStore{pool: pool}
}

var _ ports.ScannedImageStore = (*ScannedImageStore)(nil)

// MarkScanned records digest as scanned for the tenant. Idempotent by (tenant, digest): a repeat
// keeps the earliest first_scanned_at.
func (s *ScannedImageStore) MarkScanned(ctx context.Context, tenantID shared.ID, digest string, at time.Time) error {
	tenant := shared.TenantOrDefault(tenantID).String()
	return WithTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO scanned_image (tenant_id, digest, first_scanned_at)
			VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id, digest) DO NOTHING`,
			tenant, digest, at)
		if err != nil {
			return fmt.Errorf("scanned image: mark: %w", err)
		}
		return nil
	})
}

// ScannedDigests returns the set of scanned digests for the tenant.
func (s *ScannedImageStore) ScannedDigests(ctx context.Context, tenantID shared.ID) (map[string]bool, error) {
	tenant := shared.TenantOrDefault(tenantID).String()
	out := map[string]bool{}
	err := WithTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT digest FROM scanned_image WHERE tenant_id = $1`, tenant)
		if err != nil {
			return fmt.Errorf("scanned image: query: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var d string
			if err := rows.Scan(&d); err != nil {
				return fmt.Errorf("scanned image: scan: %w", err)
			}
			out[d] = true
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
