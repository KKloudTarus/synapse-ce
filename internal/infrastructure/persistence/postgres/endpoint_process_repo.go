package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// EndpointProcessRepository is the Postgres tier for the per-host process snapshot projection (B5). A
// snapshot is a MUTABLE projection keyed by (tenant, asset, entity), upserted in place. Every method runs
// under the authenticated ctx tenant via WithContextTenant (RLS) with an explicit tenant_id predicate as
// defense-in-depth. Reached only through ports.EndpointProcessStore.
type EndpointProcessRepository struct {
	pool *pgxpool.Pool
}

var _ ports.EndpointProcessStore = (*EndpointProcessRepository)(nil)

// NewEndpointProcessRepository constructs the process snapshot store over a pgx pool.
func NewEndpointProcessRepository(pool *pgxpool.Pool) *EndpointProcessRepository {
	return &EndpointProcessRepository{pool: pool}
}

func requireEndpointProcessTenant(ctx context.Context) (shared.ID, error) {
	if t, ok := shared.TenantFrom(ctx); ok && t != "" {
		return t, nil
	}
	return "", fmt.Errorf("%w: endpoint process store operation requires a tenant in context", shared.ErrValidation)
}

// SaveProcesses upserts snapshots by (tenant, asset, entity) in one transaction.
func (r *EndpointProcessRepository) SaveProcesses(ctx context.Context, snapshots []ports.ProcessSnapshot) error {
	tenant, err := requireEndpointProcessTenant(ctx)
	if err != nil {
		return err
	}
	if len(snapshots) == 0 {
		return nil
	}
	for _, p := range snapshots {
		if err := p.Validate(); err != nil {
			return err
		}
		if p.TenantID != tenant {
			return fmt.Errorf("%w: snapshot tenant %q does not match context tenant %q", shared.ErrValidation, p.TenantID, tenant)
		}
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		for _, p := range snapshots {
			_, err := tx.Exec(ctx, `INSERT INTO endpoint_processes
				(tenant_id, asset_id, entity_id, pid, comm, path, running, last_seen_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
				ON CONFLICT (tenant_id, asset_id, entity_id) DO UPDATE SET
					pid = EXCLUDED.pid,
					comm = EXCLUDED.comm,
					path = EXCLUDED.path,
					running = EXCLUDED.running,
					last_seen_at = EXCLUDED.last_seen_at`,
				tenant.String(), p.AssetID.String(), p.EntityID.String(), p.PID, p.Comm, p.Path, p.Running, p.LastSeenAt.UTC())
			if err != nil {
				return fmt.Errorf("upsert process snapshot: %w", err)
			}
		}
		return nil
	})
}

// ListRunningByAsset returns the running snapshots for an asset, ordered by entity_id (COLLATE "C" so the
// SQL order matches the memory twin's Go bytewise ordering).
func (r *EndpointProcessRepository) ListRunningByAsset(ctx context.Context, assetID shared.ID) ([]ports.ProcessSnapshot, error) {
	tenant, err := requireEndpointProcessTenant(ctx)
	if err != nil {
		return nil, err
	}
	if assetID.IsZero() {
		return nil, fmt.Errorf("%w: asset id is required", shared.ErrValidation)
	}
	out := make([]ports.ProcessSnapshot, 0) // non-nil empty for parity with the memory twin
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT entity_id, pid, comm, path, last_seen_at
			FROM endpoint_processes
			WHERE tenant_id = $1 AND asset_id = $2 AND running = true
			ORDER BY entity_id COLLATE "C"`, tenant.String(), assetID.String())
		if err != nil {
			return fmt.Errorf("list running processes: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			p := ports.ProcessSnapshot{TenantID: tenant, AssetID: assetID, Running: true}
			var entityID string
			if err := rows.Scan(&entityID, &p.PID, &p.Comm, &p.Path, &p.LastSeenAt); err != nil {
				return fmt.Errorf("scan process snapshot: %w", err)
			}
			p.LastSeenAt = p.LastSeenAt.UTC() // normalize zone for parity with the write path
			p.EntityID = shared.ID(entityID)
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
