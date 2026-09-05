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
	// One multi-row upsert over unnest, not a row-per-round-trip loop: a host at the 4096-process cap
	// otherwise makes 4096 sequential round trips holding a pooled connection the whole time, which a
	// synchronized fleet restart turns into pool saturation. This collapses it to a single round trip.
	assetIDs := make([]string, len(snapshots))
	entityIDs := make([]string, len(snapshots))
	pids := make([]int, len(snapshots))
	comms := make([]string, len(snapshots))
	paths := make([]string, len(snapshots))
	running := make([]bool, len(snapshots))
	lastSeen := make([]time.Time, len(snapshots))
	for i, p := range snapshots {
		assetIDs[i] = p.AssetID.String()
		entityIDs[i] = p.EntityID.String()
		pids[i] = p.PID
		comms[i] = p.Comm
		paths[i] = p.Path
		running[i] = p.Running
		lastSeen[i] = p.LastSeenAt.UTC()
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO endpoint_processes
			(tenant_id, asset_id, entity_id, pid, comm, path, running, last_seen_at)
			SELECT $1, u.asset_id, u.entity_id, u.pid, u.comm, u.path, u.running, u.last_seen_at
			FROM unnest($2::text[], $3::text[], $4::int[], $5::text[], $6::text[], $7::bool[], $8::timestamptz[])
				AS u(asset_id, entity_id, pid, comm, path, running, last_seen_at)
			ON CONFLICT (tenant_id, asset_id, entity_id) DO UPDATE SET
				pid = EXCLUDED.pid,
				comm = EXCLUDED.comm,
				path = EXCLUDED.path,
				running = EXCLUDED.running,
				last_seen_at = EXCLUDED.last_seen_at`,
			tenant.String(), assetIDs, entityIDs, pids, comms, paths, running, lastSeen)
		if err != nil {
			return fmt.Errorf("upsert process snapshots: %w", err)
		}
		return nil
	})
}

// ReplaceRunningProcesses makes the asset's running set exactly the reported snapshots in one transaction:
// it upserts them (multi-row unnest) and marks every other currently-running row for that asset that the
// report omitted as not-running. Without this a process that exits between reports stays running=true
// forever. An empty report clears the asset's running set.
func (r *EndpointProcessRepository) ReplaceRunningProcesses(ctx context.Context, assetID shared.ID, snapshots []ports.ProcessSnapshot) error {
	tenant, err := requireEndpointProcessTenant(ctx)
	if err != nil {
		return err
	}
	entityIDs := make([]string, len(snapshots))
	assetIDs := make([]string, len(snapshots))
	pids := make([]int, len(snapshots))
	comms := make([]string, len(snapshots))
	paths := make([]string, len(snapshots))
	running := make([]bool, len(snapshots))
	lastSeen := make([]time.Time, len(snapshots))
	for i, p := range snapshots {
		if err := p.Validate(); err != nil {
			return err
		}
		if p.TenantID != tenant {
			return fmt.Errorf("%w: snapshot tenant %q does not match context tenant %q", shared.ErrValidation, p.TenantID, tenant)
		}
		entityIDs[i] = p.EntityID.String()
		assetIDs[i] = p.AssetID.String()
		pids[i] = p.PID
		comms[i] = p.Comm
		paths[i] = p.Path
		running[i] = p.Running
		lastSeen[i] = p.LastSeenAt.UTC()
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		if len(snapshots) > 0 {
			if _, err := tx.Exec(ctx, `INSERT INTO endpoint_processes
				(tenant_id, asset_id, entity_id, pid, comm, path, running, last_seen_at)
				SELECT $1, u.asset_id, u.entity_id, u.pid, u.comm, u.path, u.running, u.last_seen_at
				FROM unnest($2::text[], $3::text[], $4::int[], $5::text[], $6::text[], $7::bool[], $8::timestamptz[])
					AS u(asset_id, entity_id, pid, comm, path, running, last_seen_at)
				ON CONFLICT (tenant_id, asset_id, entity_id) DO UPDATE SET
					pid = EXCLUDED.pid, comm = EXCLUDED.comm, path = EXCLUDED.path,
					running = EXCLUDED.running, last_seen_at = EXCLUDED.last_seen_at`,
				tenant.String(), assetIDs, entityIDs, pids, comms, paths, running, lastSeen); err != nil {
				return fmt.Errorf("upsert process snapshots: %w", err)
			}
		}
		// Retire any running row for this asset the report omitted.
		if _, err := tx.Exec(ctx, `UPDATE endpoint_processes SET running = false
			WHERE tenant_id = $1 AND asset_id = $2 AND running = true AND NOT (entity_id = ANY($3::text[]))`,
			tenant.String(), assetID.String(), entityIDs); err != nil {
			return fmt.Errorf("retire exited processes: %w", err)
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
