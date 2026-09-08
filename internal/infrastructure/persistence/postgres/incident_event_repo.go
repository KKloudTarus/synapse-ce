package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const defaultIncidentListLimit = 1000
const maxCanonicalHops = 1024

type IncidentEventRepository struct{ pool *pgxpool.Pool }

var _ ports.IncidentEventStore = (*IncidentEventRepository)(nil)

func NewIncidentEventRepository(pool *pgxpool.Pool) *IncidentEventRepository {
	return &IncidentEventRepository{pool: pool}
}

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
	return r.withTx(ctx, tenant, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM incident_events WHERE tenant_id=$1 AND incident_id=$2`, tenant.String(), incidentID.String()).Scan(&count); err != nil {
			return fmt.Errorf("count incident events: %w", err)
		}
		if count != expectedRevision {
			return fmt.Errorf("%w: incident %s at revision %d, expected %d", shared.ErrConflict, incidentID, count, expectedRevision)
		}
		for _, e := range events {
			if e.Kind == incident.EventMerged {
				var targetCount int
				if err := tx.QueryRow(ctx, `SELECT count(*) FROM incident_events WHERE tenant_id=$1 AND incident_id=$2`, tenant.String(), e.MergedInto.String()).Scan(&targetCount); err != nil {
					return fmt.Errorf("count canonical merge target: %w", err)
				}
				if targetCount == 0 {
					return fmt.Errorf("%w: canonical merge target %s does not exist", shared.ErrNotFound, e.MergedInto)
				}
				root, err := resolveCanonicalTx(ctx, tx, tenant, e.MergedInto)
				if err != nil {
					return err
				}
				if root != e.MergedInto {
					return fmt.Errorf("%w: merge target %s is not canonical", shared.ErrConflict, e.MergedInto)
				}
				if root == incidentID {
					return fmt.Errorf("%w: incident merge would form a cycle", shared.ErrConflict)
				}
				var existing string
				err = tx.QueryRow(ctx, `SELECT canonical_incident_id FROM incident_merge_edges WHERE tenant_id=$1 AND source_incident_id=$2`, tenant.String(), incidentID.String()).Scan(&existing)
				if err == nil {
					if existing != e.MergedInto.String() {
						return fmt.Errorf("%w: incident %s already has immutable canonical target %s", shared.ErrConflict, incidentID, existing)
					}
				} else if err != pgx.ErrNoRows {
					return fmt.Errorf("load incident merge edge: %w", err)
				}
			}
		}
		for i, e := range events {
			payload, err := json.Marshal(e)
			if err != nil {
				return fmt.Errorf("marshal incident event: %w", err)
			}
			_, err = tx.Exec(ctx, `INSERT INTO incident_events (tenant_id, incident_id, seq, kind, occurred_at, actor, asset_id, payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, tenant.String(), incidentID.String(), expectedRevision+i+1, string(e.Kind), e.At, e.Actor, e.AssetID.String(), payload)
			if err != nil {
				if isUniqueViolation(err) {
					return fmt.Errorf("%w: incident %s position %d already written", shared.ErrConflict, incidentID, expectedRevision+i+1)
				}
				return fmt.Errorf("append incident event: %w", err)
			}
			if e.Kind == incident.EventMerged {
				_, err = tx.Exec(ctx, `INSERT INTO incident_merge_edges (tenant_id,source_incident_id,canonical_incident_id,bridge_key,source_event_seq,actor,merged_at) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id,source_incident_id) DO NOTHING`, tenant.String(), incidentID.String(), e.MergedInto.String(), e.CorrelationKey, expectedRevision+i+1, e.Actor, e.At)
				if err != nil {
					return fmt.Errorf("append incident merge edge: %w", err)
				}
			}
		}
		return nil
	})
}
func (r *IncidentEventRepository) withTx(ctx context.Context, tenant shared.ID, fn func(pgx.Tx) error) error {
	if tx, bound, err := contextTenantTx(ctx, tenant); err != nil {
		return err
	} else if bound {
		return fn(tx)
	}
	return WithContextTenant(ctx, r.pool, fn)
}
func (r *IncidentEventRepository) LoadEvents(ctx context.Context, incidentID shared.ID) ([]incident.IncidentEvent, error) {
	tenant, err := requireIncidentRepoTenant(ctx)
	if err != nil {
		return nil, err
	}
	var out []incident.IncidentEvent
	err = r.withTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT payload FROM incident_events WHERE tenant_id=$1 AND incident_id=$2 ORDER BY seq`, tenant.String(), incidentID.String())
		if err != nil {
			return fmt.Errorf("query incident events: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var payload []byte
			if err := rows.Scan(&payload); err != nil {
				return err
			}
			var e incident.IncidentEvent
			if err := json.Unmarshal(payload, &e); err != nil {
				return fmt.Errorf("unmarshal incident event: %w", err)
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}
func (r *IncidentEventRepository) ListIncidentIDs(ctx context.Context, q ports.IncidentQuery) ([]shared.ID, error) {
	tenant, err := requireIncidentRepoTenant(ctx)
	if err != nil {
		return nil, err
	}
	sql := `SELECT incident_id FROM incident_events WHERE tenant_id=$1`
	args := []any{tenant.String()}
	if !q.AssetID.IsZero() {
		args = append(args, q.AssetID.String())
		sql += ` AND asset_id=$2`
	}
	sql += ` GROUP BY incident_id ORDER BY incident_id COLLATE "C"`
	if q.Limit >= 0 {
		if q.Limit == 0 || q.Limit > defaultIncidentListLimit {
			q.Limit = defaultIncidentListLimit
		}
		args = append(args, q.Limit)
		sql += fmt.Sprintf(` LIMIT $%d`, len(args))
	}
	var ids []shared.ID
	err = r.withTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return fmt.Errorf("list incidents: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, shared.ID(id))
		}
		return rows.Err()
	})
	return ids, err
}
func (r *IncidentEventRepository) ResolveCanonicalID(ctx context.Context, id shared.ID) (shared.ID, error) {
	tenant, err := requireIncidentRepoTenant(ctx)
	if err != nil {
		return "", err
	}
	var root shared.ID
	err = r.withTx(ctx, tenant, func(tx pgx.Tx) error { var err error; root, err = resolveCanonicalTx(ctx, tx, tenant, id); return err })
	return root, err
}
func resolveCanonicalTx(ctx context.Context, tx pgx.Tx, tenant, id shared.ID) (shared.ID, error) {
	seen := map[shared.ID]struct{}{}
	for hop := 0; hop < maxCanonicalHops; hop++ {
		if _, ok := seen[id]; ok {
			return "", fmt.Errorf("%w: incident merge cycle", shared.ErrConflict)
		}
		seen[id] = struct{}{}
		var target string
		err := tx.QueryRow(ctx, `SELECT canonical_incident_id FROM incident_merge_edges WHERE tenant_id=$1 AND source_incident_id=$2`, tenant.String(), id.String()).Scan(&target)
		if err == pgx.ErrNoRows {
			return id, nil
		}
		if err != nil {
			return "", fmt.Errorf("load canonical incident: %w", err)
		}
		id = shared.ID(target)
	}
	return "", fmt.Errorf("%w: incident merge resolution exceeds bound", shared.ErrConflict)
}
func (r *IncidentEventRepository) ListMergeEdges(ctx context.Context, canonicalID shared.ID) ([]incident.MergeEdge, error) {
	tenant, err := requireIncidentRepoTenant(ctx)
	if err != nil {
		return nil, err
	}
	var out []incident.MergeEdge
	err = r.withTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT source_incident_id,canonical_incident_id,bridge_key,source_event_seq,actor,merged_at FROM incident_merge_edges WHERE tenant_id=$1 ORDER BY source_incident_id COLLATE "C"`, tenant.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e incident.MergeEdge
			var source, target string
			if err := rows.Scan(&source, &target, &e.BridgeKey, &e.SourceEventSeq, &e.Actor, &e.At); err != nil {
				return err
			}
			e.SourceID = shared.ID(source)
			e.CanonicalID = shared.ID(target)
			root, err := resolveCanonicalTx(ctx, tx, tenant, e.SourceID)
			if err != nil {
				return err
			}
			if root == canonicalID {
				out = append(out, e)
			}
		}
		return rows.Err()
	})
	return out, err
}
func (r *IncidentEventRepository) ListPendingResponseLinks(ctx context.Context) ([]incident.ResponseLink, error) {
	tenant, err := requireIncidentRepoTenant(ctx)
	if err != nil {
		return nil, err
	}
	var linksByKey = map[string]incident.ResponseLink{}
	err = r.withTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT incident_id,payload FROM incident_events WHERE tenant_id=$1 ORDER BY incident_id COLLATE "C",seq`, tenant.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		var current shared.ID
		var events []incident.IncidentEvent
		project := func() error {
			if current.IsZero() {
				return nil
			}
			p, err := incident.Project(events)
			if err != nil {
				return err
			}
			root, err := resolveCanonicalTx(ctx, tx, tenant, current)
			if err != nil {
				return err
			}
			for _, ref := range p.Responses {
				if !ref.Verified {
					linksByKey[root.String()+"\x00"+ref.ActionID.String()] = incident.ResponseLink{IncidentID: root, Response: ref}
				}
			}
			return nil
		}
		for rows.Next() {
			var id string
			var payload []byte
			if err := rows.Scan(&id, &payload); err != nil {
				return err
			}
			next := shared.ID(id)
			if !current.IsZero() && next != current {
				if err := project(); err != nil {
					return err
				}
				events = nil
			}
			current = next
			var e incident.IncidentEvent
			if err := json.Unmarshal(payload, &e); err != nil {
				return err
			}
			events = append(events, e)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		return project()
	})
	if err != nil {
		return nil, err
	}
	links := make([]incident.ResponseLink, 0, len(linksByKey))
	for _, link := range linksByKey {
		links = append(links, link)
	}
	sort.Slice(links, func(i, j int) bool {
		if links[i].IncidentID != links[j].IncidentID {
			return links[i].IncidentID < links[j].IncidentID
		}
		return links[i].Response.ActionID < links[j].Response.ActionID
	})
	return links, nil
}
func requireIncidentRepoTenant(ctx context.Context) (shared.ID, error) {
	if t, ok := shared.TenantFrom(ctx); ok && t != "" {
		return t, nil
	}
	return "", fmt.Errorf("%w: incident store operation requires a tenant in context", shared.ErrValidation)
}
