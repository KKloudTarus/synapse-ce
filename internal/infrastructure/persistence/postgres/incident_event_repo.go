package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// defaultIncidentListLimit caps ListIncidentIDs; mirrors the memory tier.
const defaultIncidentListLimit = 1000

// IncidentEventRepository is the Postgres tier for the append-only incident event log (Phase C / C7).
// Every method runs under the authenticated ctx tenant via WithContextTenant (RLS) with an explicit
// tenant_id predicate as defense-in-depth. Appends are optimistic-concurrency by log position: the
// (tenant, incident, seq) primary key makes two writers unable to both claim the next position. Reached
// only through ports.IncidentEventStore.
type IncidentEventRepository struct {
	pool *pgxpool.Pool
}

var _ ports.IncidentEventStore = (*IncidentEventRepository)(nil)

// NewIncidentEventRepository constructs the incident event store over a pgx pool.
func NewIncidentEventRepository(pool *pgxpool.Pool) *IncidentEventRepository {
	return &IncidentEventRepository{pool: pool}
}

// AppendEvents appends events under optimistic concurrency: the current event count must equal
// expectedRevision, and the new rows take positions after it. A position collision (concurrent writer) or
// a count mismatch returns shared.ErrConflict.
func (r *IncidentEventRepository) AppendEvents(ctx context.Context, incidentID shared.ID, expectedRevision int, events []incident.IncidentEvent) error {
	tenant, err := requireIncidentRepoTenant(ctx)
	if err != nil {
		return err
	}
	if incidentID.IsZero() {
		return fmt.Errorf("%w: incident id is required", shared.ErrValidation)
	}
	if len(events) == 0 {
		return nil
	}
	for _, e := range events {
		if err := e.Validate(); err != nil {
			return err
		}
		if e.IncidentID != incidentID {
			return fmt.Errorf("%w: event belongs to %s, not %s", shared.ErrValidation, e.IncidentID, incidentID)
		}
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM incident_events WHERE tenant_id=$1 AND incident_id=$2`,
			tenant.String(), incidentID.String()).Scan(&count); err != nil {
			return fmt.Errorf("count incident events: %w", err)
		}
		if count != expectedRevision {
			return fmt.Errorf("%w: incident %s at revision %d, expected %d", shared.ErrConflict, incidentID, count, expectedRevision)
		}
		for i, e := range events {
			payload, err := json.Marshal(e)
			if err != nil {
				return fmt.Errorf("marshal incident event: %w", err)
			}
			_, err = tx.Exec(ctx, `INSERT INTO incident_events
				(tenant_id, incident_id, seq, kind, occurred_at, actor, asset_id, payload)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
				tenant.String(), incidentID.String(), expectedRevision+i+1, string(e.Kind), e.At, e.Actor, e.AssetID.String(), payload)
			if err != nil {
				if isUniqueViolation(err) {
					return fmt.Errorf("%w: incident %s position %d already written", shared.ErrConflict, incidentID, expectedRevision+i+1)
				}
				return fmt.Errorf("append incident event: %w", err)
			}
		}
		return nil
	})
}

// LoadEvents returns one incident's event log in seq order.
func (r *IncidentEventRepository) LoadEvents(ctx context.Context, incidentID shared.ID) ([]incident.IncidentEvent, error) {
	tenant, err := requireIncidentRepoTenant(ctx)
	if err != nil {
		return nil, err
	}
	var out []incident.IncidentEvent
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT payload FROM incident_events WHERE tenant_id=$1 AND incident_id=$2 ORDER BY seq`,
			tenant.String(), incidentID.String())
		if err != nil {
			return fmt.Errorf("query incident events: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var payload []byte
			if err := rows.Scan(&payload); err != nil {
				return fmt.Errorf("scan incident event: %w", err)
			}
			var e incident.IncidentEvent
			if err := json.Unmarshal(payload, &e); err != nil {
				return fmt.Errorf("unmarshal incident event: %w", err)
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListIncidentIDs returns incident ids matching the query, ordered by id.
func (r *IncidentEventRepository) ListIncidentIDs(ctx context.Context, q ports.IncidentQuery) ([]shared.ID, error) {
	tenant, err := requireIncidentRepoTenant(ctx)
	if err != nil {
		return nil, err
	}
	limit := q.Limit
	if limit <= 0 || limit > defaultIncidentListLimit {
		limit = defaultIncidentListLimit
	}
	// GROUP BY (not DISTINCT) dedups incident_id while allowing ORDER BY a collated grouped column;
	// COLLATE "C" makes the order match the memory twin's Go bytewise ordering regardless of DB collation.
	sql := `SELECT incident_id FROM incident_events WHERE tenant_id=$1`
	args := []any{tenant.String()}
	if !q.AssetID.IsZero() {
		args = append(args, q.AssetID.String())
		sql += ` AND asset_id=$2`
	}
	args = append(args, limit)
	sql += fmt.Sprintf(` GROUP BY incident_id ORDER BY incident_id COLLATE "C" LIMIT $%d`, len(args))

	var ids []shared.ID
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return fmt.Errorf("list incidents: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return fmt.Errorf("scan incident id: %w", err)
			}
			ids = append(ids, shared.ID(id))
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return ids, nil
}

func requireIncidentRepoTenant(ctx context.Context) (shared.ID, error) {
	if t, ok := shared.TenantFrom(ctx); ok && t != "" {
		return t, nil
	}
	return "", fmt.Errorf("%w: incident store operation requires a tenant in context", shared.ErrValidation)
}
