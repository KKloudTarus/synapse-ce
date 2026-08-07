package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// WorkOrderRepository is the Postgres-backed fleet work order store. Every method runs through
// WithTenant so Row Level Security (migration 0059 via the 0057 procedure) isolates by tenant.
type WorkOrderRepository struct{ pool *pgxpool.Pool }

// NewWorkOrderRepository constructs the Postgres work order repository.
func NewWorkOrderRepository(pool *pgxpool.Pool) *WorkOrderRepository {
	return &WorkOrderRepository{pool: pool}
}

var _ ports.WorkOrderStore = (*WorkOrderRepository)(nil)

const workOrderCols = `id, tenant_id, asset_id, agent_id, capability, authorization_id, idempotency_key, not_after, time_bucket, state, refuse_reason, signature, created_at, updated_at`

// Issue inserts wo. It is idempotent by (tenant, idempotency key): a duplicate returns the existing
// order. A second LIVE order for the same (tenant, asset, capability, time bucket) returns
// shared.ErrConflict (the partial unique index).
func (r *WorkOrderRepository) Issue(ctx context.Context, wo *workorder.WorkOrder) (*workorder.WorkOrder, error) {
	// Idempotency first: if an order already exists for this (tenant, idempotency key), return it.
	// Doing this before the insert is what makes a re-issue idempotent rather than colliding with
	// the in-flight uniqueness index (both constraints would fire for the same key, and Postgres
	// reports only one, non-deterministically).
	if existing, err := r.getByIdem(ctx, wo.TenantID, wo.IdempotencyKey); err == nil {
		return existing, nil
	} else if !errors.Is(err, shared.ErrNotFound) {
		return nil, err
	}
	insertErr := WithTenant(ctx, r.pool, wo.TenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO work_orders (`+workOrderCols+`)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			wo.ID.String(), wo.TenantID.String(), wo.AssetID.String(), wo.AgentID.String(), wo.Capability,
			wo.AuthorizationID.String(), wo.IdempotencyKey, wo.NotAfter, wo.TimeBucket, string(wo.State),
			wo.RefuseReason, wo.Signature, wo.Audit.CreatedAt, wo.Audit.UpdatedAt)
		return err
	})
	if insertErr == nil {
		out := *wo
		return &out, nil
	}
	var pgErr *pgconn.PgError
	if errors.As(insertErr, &pgErr) && pgErr.Code == "23505" {
		switch pgErr.ConstraintName {
		case "work_orders_idem":
			// Idempotent issue: return the existing order.
			return r.getByIdem(ctx, wo.TenantID, wo.IdempotencyKey)
		case "work_orders_inflight":
			return nil, shared.ErrConflict
		}
	}
	return nil, insertErr
}

func (r *WorkOrderRepository) getByIdem(ctx context.Context, tenantID shared.ID, idem string) (*workorder.WorkOrder, error) {
	var out *workorder.WorkOrder
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		wo, e := scanWorkOrder(tx.QueryRow(ctx, `SELECT `+workOrderCols+` FROM work_orders WHERE tenant_id=$1 AND idempotency_key=$2`,
			tenantID.String(), idem))
		if e != nil {
			return e
		}
		out = wo
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetByID returns the order for (tenantID, id) or shared.ErrNotFound.
func (r *WorkOrderRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*workorder.WorkOrder, error) {
	var out *workorder.WorkOrder
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		wo, e := scanWorkOrder(tx.QueryRow(ctx, `SELECT `+workOrderCols+` FROM work_orders WHERE tenant_id=$1 AND id=$2`,
			tenantID.String(), id.String()))
		if e != nil {
			return e
		}
		out = wo
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Claim atomically moves up to max unexpired issued orders addressed to agentID into claimed and
// returns them, using FOR UPDATE SKIP LOCKED so concurrent claimers never double-claim.
func (r *WorkOrderRepository) Claim(ctx context.Context, tenantID, agentID shared.ID, max int, now time.Time) ([]*workorder.WorkOrder, error) {
	var out []*workorder.WorkOrder
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `
			UPDATE work_orders SET state='claimed', updated_at=$4
			WHERE id IN (
				SELECT id FROM work_orders
				WHERE tenant_id=$1 AND agent_id=$2 AND state='issued' AND not_after > $4
				ORDER BY created_at, id
				LIMIT $3
				FOR UPDATE SKIP LOCKED
			)
			RETURNING `+workOrderCols, tenantID.String(), agentID.String(), max, now)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			wo, e := scanWorkOrder(rows)
			if e != nil {
				return e
			}
			out = append(out, wo)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Transition applies to with an optimistic expected-state check. It returns shared.ErrConflict when
// no row matched (the state changed concurrently or the order does not exist under this tenant).
func (r *WorkOrderRepository) Transition(ctx context.Context, tenantID, id shared.ID, to workorder.State, reason string, expected workorder.State) error {
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE work_orders SET state=$3, refuse_reason=$4, updated_at=now()
			WHERE tenant_id=$1 AND id=$2 AND state=$5`,
			tenantID.String(), id.String(), string(to), reason, string(expected))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return shared.ErrConflict
		}
		return nil
	})
}

func scanWorkOrder(row rowScanner) (*workorder.WorkOrder, error) {
	var (
		id, tid, asset, agent, cap, auth, idem, state, reason, sig string
		wo                                                         workorder.WorkOrder
	)
	if err := row.Scan(&id, &tid, &asset, &agent, &cap, &auth, &idem, &wo.NotAfter, &wo.TimeBucket,
		&state, &reason, &sig, &wo.Audit.CreatedAt, &wo.Audit.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, err
	}
	wo.ID = shared.ID(id)
	wo.TenantID = shared.ID(tid)
	wo.AssetID = shared.ID(asset)
	wo.AgentID = shared.ID(agent)
	wo.Capability = cap
	wo.AuthorizationID = shared.ID(auth)
	wo.IdempotencyKey = idem
	wo.State = workorder.State(state)
	wo.RefuseReason = reason
	wo.Signature = sig
	return &wo, nil
}
