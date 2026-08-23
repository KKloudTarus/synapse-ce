package postgres

import (
	"context"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// defaultEndpointTimelineLimit caps an unbounded QueryTimeline; mirrors the memory tier.
const defaultEndpointTimelineLimit = 10000

// EndpointTimelineRepository is the Postgres tier for the durable endpoint State Timeline (Phase B / B7).
// Every method runs under the authenticated ctx tenant via WithContextTenant, so RLS binds the partition,
// and reads carry an explicit tenant_id predicate as defense-in-depth. Appends are idempotent by
// (tenant, asset, event_id). Reached only through ports.EndpointTimelineStore.
type EndpointTimelineRepository struct {
	pool *pgxpool.Pool
}

var _ ports.EndpointTimelineStore = (*EndpointTimelineRepository)(nil)

// NewEndpointTimelineRepository constructs the endpoint-timeline store over a pgx pool.
func NewEndpointTimelineRepository(pool *pgxpool.Pool) *EndpointTimelineRepository {
	return &EndpointTimelineRepository{pool: pool}
}

func requireEndpointTenant(ctx context.Context) (shared.ID, error) {
	if t, ok := shared.TenantFrom(ctx); ok && t != "" {
		return t, nil
	}
	return "", fmt.Errorf("%w: endpoint timeline operation requires a tenant in context", shared.ErrValidation)
}

// AppendTimeline persists the transitions idempotently (ON CONFLICT DO NOTHING on the (tenant, asset,
// event_id) key). Every entry's TenantID must equal the context tenant.
func (r *EndpointTimelineRepository) AppendTimeline(ctx context.Context, list []endpoint.TimelineEntry) error {
	tenant, err := requireEndpointTenant(ctx)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		return nil
	}
	for _, e := range list {
		if e.TenantID != tenant {
			return fmt.Errorf("%w: timeline entry tenant %s does not match context tenant %s", shared.ErrValidation, e.TenantID, tenant)
		}
		if e.AssetID.IsZero() || e.EventID.IsZero() {
			return fmt.Errorf("%w: timeline entry requires an asset id and event id", shared.ErrValidation)
		}
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		for _, e := range list {
			if _, err := tx.Exec(ctx, `INSERT INTO endpoint_timeline
				(tenant_id, asset_id, event_id, occurred_at, entity_kind, entity_id, kind, summary)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
				ON CONFLICT (tenant_id, asset_id, event_id) DO NOTHING`,
				tenant.String(), e.AssetID.String(), e.EventID.String(), e.OccurredAt,
				string(e.EntityKind), e.EntityID.String(), string(e.Kind), e.Summary); err != nil {
				return fmt.Errorf("append endpoint timeline entry: %w", err)
			}
		}
		return nil
	})
}

// QueryTimeline returns the stored transitions matching q, ordered by (occurred_at, event_id).
func (r *EndpointTimelineRepository) QueryTimeline(ctx context.Context, q ports.EndpointTimelineQuery) ([]endpoint.TimelineEntry, error) {
	tenant, err := requireEndpointTenant(ctx)
	if err != nil {
		return nil, err
	}
	if q.AssetID.IsZero() {
		return nil, fmt.Errorf("%w: timeline query requires an asset id", shared.ErrValidation)
	}
	limit := q.Limit
	if limit <= 0 || limit > defaultEndpointTimelineLimit {
		limit = defaultEndpointTimelineLimit
	}

	sql := `SELECT event_id, occurred_at, entity_kind, entity_id, kind, summary FROM endpoint_timeline
		WHERE tenant_id=$1 AND asset_id=$2`
	args := []any{tenant.String(), q.AssetID.String()}
	add := func(clause string, val any) {
		args = append(args, val)
		sql += " AND " + clause + "$" + strconv.Itoa(len(args))
	}
	if !q.From.IsZero() {
		add("occurred_at >= ", q.From)
	}
	if !q.To.IsZero() {
		add("occurred_at <= ", q.To)
	}
	if !q.EntityID.IsZero() {
		add("entity_id = ", q.EntityID.String())
	}
	if q.Kind != "" {
		add("kind = ", string(q.Kind))
	}
	args = append(args, limit)
	// event_id ordered COLLATE "C" (bytewise) so the total order matches the memory twin's Go bytewise
	// tiebreak regardless of the DB's default collation (house convention; see migration 0111).
	sql += ` ORDER BY occurred_at, event_id COLLATE "C" LIMIT $` + strconv.Itoa(len(args))

	var out []endpoint.TimelineEntry
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return fmt.Errorf("query endpoint timeline: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			e := endpoint.TimelineEntry{TenantID: tenant, AssetID: q.AssetID}
			var eventID, entityKind, entityID, kind, summary string
			if err := rows.Scan(&eventID, &e.OccurredAt, &entityKind, &entityID, &kind, &summary); err != nil {
				return fmt.Errorf("scan endpoint timeline row: %w", err)
			}
			e.EventID = shared.ID(eventID)
			e.EntityKind = endpoint.EntityKind(entityKind)
			e.EntityID = shared.ID(entityID)
			e.Kind = endpoint.TimelineEntryKind(kind)
			e.Summary = summary
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
