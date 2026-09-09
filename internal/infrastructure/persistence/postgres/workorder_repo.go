package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// WorkOrderRepository is the Postgres-backed fleet work order store. Every method runs through
// WithTenant so Row Level Security (migration 0059 via the 0057 procedure) isolates by tenant.
type WorkOrderRepository struct {
	pool   *pgxpool.Pool
	audits *FleetAuditRepository
}

// NewWorkOrderRepository constructs the Postgres work order repository.
func NewWorkOrderRepository(pool *pgxpool.Pool) *WorkOrderRepository {
	return &WorkOrderRepository{pool: pool, audits: &FleetAuditRepository{pool: pool}}
}

var _ ports.WorkOrderAuditStore = (*WorkOrderRepository)(nil)

const workOrderCols = `id, tenant_id, asset_id, agent_id, capability, authorization_id, idempotency_key, not_after, lease_id, lease_until, time_bucket, state, refuse_reason, signature, created_at, updated_at, priority, response_command, response_halt_command, response_observation, response_result`

// Issue inserts wo. It is idempotent by (tenant, idempotency key): a duplicate returns the existing
// order. A second LIVE order for the same (tenant, asset, capability, time bucket) returns
// shared.ErrConflict (the partial unique index).
func (r *WorkOrderRepository) Issue(ctx context.Context, wo *workorder.WorkOrder) (*workorder.WorkOrder, error) {
	return r.issue(ctx, wo, nil)
}

// IssueWithAudit atomically persists a signed order and its normalized audit obligation.
func (r *WorkOrderRepository) ListPendingFleetAudits(ctx context.Context) ([]ports.FleetAuditIntent, error) {
	return r.audits.ListPendingFleetAudits(ctx)
}

func (r *WorkOrderRepository) AcknowledgeFleetAudit(ctx context.Context, id string) error {
	return r.audits.AcknowledgeFleetAudit(ctx, id)
}

func postgresWorkOrderAudit(id, actor, action, target string, at time.Time, metadata map[string]string) (ports.FleetAuditIntent, []byte, error) {
	metadata["idempotency_key"] = id
	return validateFleetAuditIntent(ports.FleetAuditIntent{ID: id, Entry: ports.AuditEntry{Actor: actor, Action: action, Target: target, At: at, Metadata: metadata}})
}

func (r *WorkOrderRepository) ClaimWithAudit(ctx context.Context, tenantID, agentID shared.ID, max int, now time.Time, leaseID string, leaseUntil time.Time, actor string) ([]*workorder.WorkOrder, []ports.FleetAuditIntent, error) {
	var out []*workorder.WorkOrder
	var intents []ports.FleetAuditIntent
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE work_orders SET state='issued',lease_id='',lease_until=NULL,updated_at=$3 WHERE tenant_id=$1 AND agent_id=$2 AND state IN ('claimed','running') AND lease_until <= $3 AND not_after > $3`, tenantID.String(), agentID.String(), now); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `UPDATE work_orders SET state='claimed',lease_id=$5,lease_until=LEAST(not_after,$6),updated_at=$4 WHERE id IN (SELECT id FROM work_orders WHERE tenant_id=$1 AND agent_id=$2 AND state='issued' AND not_after>$4 ORDER BY priority DESC,created_at,id LIMIT $3 FOR UPDATE SKIP LOCKED) RETURNING `+workOrderCols, tenantID.String(), agentID.String(), max, now, leaseID, leaseUntil)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			wo, e := scanWorkOrder(rows)
			if e != nil {
				return e
			}
			key := "work_order.claimed:v1:" + tenantID.String() + ":" + wo.ID.String()
			intent, meta, e := postgresWorkOrderAudit(key, actor, "work_order.claimed", wo.ID.String(), now, map[string]string{"tenant_id": tenantID.String(), "agent_id": agentID.String()})
			if e != nil {
				return e
			}
			if e = insertFleetAuditTx(ctx, tx, tenantID, intent, meta); e != nil {
				return e
			}
			out = append(out, wo)
			intents = append(intents, intent)
		}
		return rows.Err()
	})
	return out, intents, err
}

func (r *WorkOrderRepository) TransitionLeasedWithAudit(ctx context.Context, tenantID, id shared.ID, leaseID string, to workorder.State, reason string, expected workorder.State, now time.Time, actor string) (ports.FleetAuditIntent, error) {
	key := "work_order.transitioned:v1:" + tenantID.String() + ":" + id.String() + ":" + string(to)
	intent, meta, err := postgresWorkOrderAudit(key, actor, "work_order.transitioned", id.String(), now, map[string]string{"tenant_id": tenantID.String(), "from": string(expected), "to": string(to), "reason": reason})
	if err != nil {
		return ports.FleetAuditIntent{}, err
	}
	err = WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		q := `UPDATE work_orders SET state=$3,refuse_reason=$4,updated_at=$7 WHERE tenant_id=$1 AND id=$2 AND state=$5 AND lease_id=$6`
		if to == workorder.StateRunning {
			q += ` AND lease_until>$7 AND not_after>$7`
		}
		tag, e := tx.Exec(ctx, q, tenantID.String(), id.String(), string(to), reason, string(expected), leaseID, now)
		if e != nil {
			return e
		}
		if tag.RowsAffected() == 0 {
			return shared.ErrConflict
		}
		return insertFleetAuditTx(ctx, tx, tenantID, intent, meta)
	})
	return intent, err
}

func (r *WorkOrderRepository) CompleteResponseWithAudit(ctx context.Context, tenantID, id shared.ID, result fleetagent.ResponseExecutionResult, reason string, now time.Time, actor string) (bool, ports.FleetAuditIntent, error) {
	key := "work-order-response-completed:v1:" + tenantID.String() + ":" + id.String() + ":" + result.AttemptKey
	intent, meta, err := postgresWorkOrderAudit(key, actor, "work_order.response_completed", id.String(), result.CompletedAt.UTC(), map[string]string{"tenant_id": tenantID.String(), "execution_state": string(result.State), "attempt_key": result.AttemptKey, "command_digest": result.CommandDigest, "reason": reason})
	if err != nil {
		return false, ports.FleetAuditIntent{}, err
	}
	changed := false
	err = WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		wo, e := scanWorkOrder(tx.QueryRow(ctx, `SELECT `+workOrderCols+` FROM work_orders WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID.String(), id.String()))
		if e != nil {
			return e
		}
		changed, e = wo.CompleteResponse(result, reason, now)
		if e != nil || !changed {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE work_orders SET state=$3,refuse_reason=$4,response_result=$5,updated_at=$6 WHERE tenant_id=$1 AND id=$2`, tenantID.String(), id.String(), string(wo.State), wo.RefuseReason, wo.ResponseResult, wo.Audit.UpdatedAt); e != nil {
			return e
		}
		return insertFleetAuditTx(ctx, tx, tenantID, intent, meta)
	})
	return changed, intent, err
}

func (r *WorkOrderRepository) CancelResponsesBelowGenerationWithAudit(ctx context.Context, tenantID shared.ID, generation int64, reason string, now time.Time, actor string) (int, ports.FleetAuditIntent, error) {
	if generation <= 0 {
		return 0, ports.FleetAuditIntent{}, shared.ErrValidation
	}
	key := "work_order.responses_fenced:v1:" + tenantID.String() + ":" + fmt.Sprint(generation)
	cancelled := 0
	var intent ports.FleetAuditIntent
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `UPDATE work_orders SET state='cancelled',refuse_reason=$3,updated_at=$4 WHERE tenant_id=$1 AND capability='response.process' AND state IN ('issued','claimed','running') AND (response_command->>'HaltGeneration')::BIGINT < $2`, tenantID.String(), generation, reason, now)
		if e != nil {
			return e
		}
		cancelled = int(tag.RowsAffected())
		var meta []byte
		intent, meta, e = postgresWorkOrderAudit(key, actor, "work_order.responses_fenced", tenantID.String(), now, map[string]string{"tenant_id": tenantID.String(), "generation": fmt.Sprint(generation), "cancelled": fmt.Sprint(cancelled), "reason": reason})
		if e != nil {
			return e
		}
		return insertFleetAuditTx(ctx, tx, tenantID, intent, meta)
	})
	return cancelled, intent, err
}

func (r *WorkOrderRepository) IssueWithAudit(ctx context.Context, wo *workorder.WorkOrder, intent ports.FleetAuditIntent) (*workorder.WorkOrder, ports.FleetAuditIntent, error) {
	intent, metadata, err := validateFleetAuditIntent(intent)
	if err != nil {
		return nil, ports.FleetAuditIntent{}, err
	}
	stored, err := r.issue(ctx, wo, func(tx pgx.Tx) error {
		return insertFleetAuditTx(ctx, tx, wo.TenantID, intent, metadata)
	})
	if err != nil {
		return nil, ports.FleetAuditIntent{}, err
	}
	return stored, intent, nil
}

func (r *WorkOrderRepository) issue(ctx context.Context, wo *workorder.WorkOrder, afterInsert func(pgx.Tx) error) (*workorder.WorkOrder, error) {
	if wo == nil || wo.TenantID.IsZero() {
		return nil, shared.ErrValidation
	}
	var stored *workorder.WorkOrder
	err := WithTenant(ctx, r.pool, wo.TenantID.String(), func(tx pgx.Tx) error {
		existing, err := scanWorkOrder(tx.QueryRow(ctx, `SELECT `+workOrderCols+` FROM work_orders WHERE tenant_id=$1 AND idempotency_key=$2`, wo.TenantID.String(), wo.IdempotencyKey))
		if err == nil {
			if !workorder.SameRequest(existing, wo) {
				return shared.ErrConflict
			}
			stored = existing
		} else if !errors.Is(err, shared.ErrNotFound) {
			return err
		} else {
			if _, err := tx.Exec(ctx, `INSERT INTO work_orders (`+workOrderCols+`)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
				wo.ID.String(), wo.TenantID.String(), wo.AssetID.String(), wo.AgentID.String(), wo.Capability,
				wo.AuthorizationID.String(), wo.IdempotencyKey, wo.NotAfter, wo.LeaseID, nullableTime(wo.LeaseUntil), wo.TimeBucket, string(wo.State),
				wo.RefuseReason, wo.Signature, wo.Audit.CreatedAt, wo.Audit.UpdatedAt, wo.Priority, wo.ResponseCommand, wo.ResponseHalt, wo.ResponseObserve, wo.ResponseResult); err != nil {
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) && pgErr.Code == "23505" {
					return shared.ErrConflict
				}
				return err
			}
			copy := *wo
			stored = &copy
		}
		if afterInsert != nil {
			return afterInsert(tx)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return stored, nil
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

func (r *WorkOrderRepository) GetByIdempotencyKey(ctx context.Context, tenantID shared.ID, idempotencyKey string) (*workorder.WorkOrder, error) {
	return r.getByIdem(ctx, tenantID, idempotencyKey)
}

// Claim atomically moves up to max unexpired issued orders addressed to agentID into claimed and
// returns them, using FOR UPDATE SKIP LOCKED so concurrent claimers never double-claim.
func (r *WorkOrderRepository) Claim(ctx context.Context, tenantID, agentID shared.ID, max int, now time.Time, leaseID string, leaseUntil time.Time) ([]*workorder.WorkOrder, error) {
	var out []*workorder.WorkOrder
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `
			UPDATE work_orders SET state='issued', lease_id='', lease_until=NULL, updated_at=$3
			WHERE tenant_id=$1 AND agent_id=$2 AND state IN ('claimed','running') AND lease_until <= $3 AND not_after > $3`,
			tenantID.String(), agentID.String(), now); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `
			UPDATE work_orders SET state='expired', updated_at=$3
			WHERE tenant_id=$1 AND agent_id=$2 AND state IN ('issued','claimed','running') AND not_after <= $3`,
			tenantID.String(), agentID.String(), now); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `
			UPDATE work_orders SET state='claimed', lease_id=$5, lease_until=LEAST(not_after,$6), updated_at=$4
			WHERE id IN (
				SELECT id FROM work_orders
				WHERE tenant_id=$1 AND agent_id=$2 AND state='issued' AND not_after > $4
		ORDER BY priority DESC, created_at, id
				LIMIT $3
				FOR UPDATE SKIP LOCKED
			)
			RETURNING `+workOrderCols, tenantID.String(), agentID.String(), max, now, leaseID, leaseUntil)
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

func (r *WorkOrderRepository) TransitionLeased(ctx context.Context, tenantID, id shared.ID, leaseID string, to workorder.State, reason string, expected workorder.State, now time.Time) error {
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		query := `UPDATE work_orders SET state=$3, refuse_reason=$4, updated_at=$7
			WHERE tenant_id=$1 AND id=$2 AND state=$5 AND lease_id=$6`
		if to == workorder.StateRunning {
			query += ` AND lease_until > $7 AND not_after > $7`
		}
		tag, err := tx.Exec(ctx, query, tenantID.String(), id.String(), string(to), reason, string(expected), leaseID, now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM work_orders WHERE tenant_id=$1 AND id=$2)`, tenantID.String(), id.String()).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return shared.ErrNotFound
			}
			return shared.ErrConflict
		}
		return nil
	})
}

func (r *WorkOrderRepository) CompleteResponse(ctx context.Context, tenantID, id shared.ID, result fleetagent.ResponseExecutionResult, reason string, now time.Time) (bool, error) {
	var changed bool
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		wo, err := scanWorkOrder(tx.QueryRow(ctx, `SELECT `+workOrderCols+` FROM work_orders WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID.String(), id.String()))
		if err != nil {
			return err
		}
		changed, err = wo.CompleteResponse(result, reason, now)
		if err != nil || !changed {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE work_orders SET state=$3, refuse_reason=$4, response_result=$5, updated_at=$6 WHERE tenant_id=$1 AND id=$2`,
			tenantID.String(), id.String(), string(wo.State), wo.RefuseReason, wo.ResponseResult, wo.Audit.UpdatedAt)
		return err
	})
	return changed, err
}

func (r *WorkOrderRepository) CancelResponsesBelowGeneration(ctx context.Context, tenantID shared.ID, generation int64, reason string, now time.Time) (int, error) {
	if generation <= 0 {
		return 0, fmt.Errorf("%w: response halt generation must be positive", shared.ErrValidation)
	}
	var cancelled int
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE work_orders SET state='cancelled', refuse_reason=$3, updated_at=$4
			WHERE tenant_id=$1 AND capability='response.process' AND state IN ('issued','claimed','running')
			AND (response_command->>'HaltGeneration')::BIGINT < $2`, tenantID.String(), generation, reason, now)
		if err != nil {
			return err
		}
		cancelled = int(tag.RowsAffected())
		return nil
	})
	return cancelled, err
}

// ListByTenant returns every work order for the tenant, ordered deterministically. Read-only, used by
// the coverage projection (#413); routed through WithTenant so RLS scopes it to the tenant.
func (r *WorkOrderRepository) ListByTenant(ctx context.Context, tenantID shared.ID) ([]*workorder.WorkOrder, error) {
	var out []*workorder.WorkOrder
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT `+workOrderCols+` FROM work_orders WHERE tenant_id=$1 ORDER BY id`, tenantID.String())
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
		return nil, fmt.Errorf("list work orders by tenant: %w", err)
	}
	return out, nil
}

// Transition applies to with an optimistic expected-state check. It returns shared.ErrConflict when
// no row matched (the state changed concurrently or the order does not exist under this tenant).
func (r *WorkOrderRepository) Transition(ctx context.Context, tenantID, id shared.ID, to workorder.State, reason string, expected workorder.State, now time.Time) error {
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE work_orders SET state=$3, refuse_reason=$4, updated_at=$6
			WHERE tenant_id=$1 AND id=$2 AND state=$5`,
			tenantID.String(), id.String(), string(to), reason, string(expected), now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			// Distinguish "no such order under this tenant" (ErrNotFound) from "state no longer
			// matches expected" (ErrConflict), matching the memory store's contract.
			var exists bool
			if e := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM work_orders WHERE tenant_id=$1 AND id=$2)`,
				tenantID.String(), id.String()).Scan(&exists); e != nil {
				return e
			}
			if !exists {
				return shared.ErrNotFound
			}
			return shared.ErrConflict
		}
		return nil
	})
}

// CancelForAgent cancels every live order addressed to agentID (used on agent revocation).
func (r *WorkOrderRepository) CancelForAgent(ctx context.Context, tenantID, agentID shared.ID, reason string, now time.Time) (int, error) {
	var n int
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `
			UPDATE work_orders SET state='cancelled', refuse_reason=$3, updated_at=$4
			WHERE tenant_id=$1 AND agent_id=$2 AND state IN ('issued','claimed','running')`,
			tenantID.String(), agentID.String(), reason, now)
		if e != nil {
			return e
		}
		n = int(tag.RowsAffected())
		return nil
	})
	return n, err
}

func scanWorkOrder(row rowScanner) (*workorder.WorkOrder, error) {
	var (
		id, tid, asset, agent, cap, auth, idem, state, reason, sig string
		wo                                                         workorder.WorkOrder
		responseCommand                                            []byte
		responseHaltCommand                                        []byte
		responseObservation                                        []byte
		responseResult                                             []byte
	)
	var leaseUntil *time.Time
	if err := row.Scan(&id, &tid, &asset, &agent, &cap, &auth, &idem, &wo.NotAfter, &wo.LeaseID, &leaseUntil, &wo.TimeBucket,
		&state, &reason, &sig, &wo.Audit.CreatedAt, &wo.Audit.UpdatedAt, &wo.Priority, &responseCommand, &responseHaltCommand, &responseObservation, &responseResult); err != nil {
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
	if leaseUntil != nil {
		wo.LeaseUntil = leaseUntil.UTC()
	}
	if len(responseCommand) > 0 && string(responseCommand) != "null" {
		if err := json.Unmarshal(responseCommand, &wo.ResponseCommand); err != nil {
			return nil, fmt.Errorf("decode response work-order command: %w", err)
		}
	}
	if len(responseResult) > 0 && string(responseResult) != "null" {
		if err := json.Unmarshal(responseResult, &wo.ResponseResult); err != nil {
			return nil, fmt.Errorf("decode response work-order result: %w", err)
		}
	}
	if len(responseHaltCommand) > 0 && string(responseHaltCommand) != "null" {
		if err := json.Unmarshal(responseHaltCommand, &wo.ResponseHalt); err != nil {
			return nil, fmt.Errorf("decode response halt work-order command: %w", err)
		}
	}
	if len(responseObservation) > 0 && string(responseObservation) != "null" {
		if err := json.Unmarshal(responseObservation, &wo.ResponseObserve); err != nil {
			return nil, fmt.Errorf("decode response observation work-order request: %w", err)
		}
	}
	if err := wo.ValidateResponseBinding(); err != nil {
		return nil, fmt.Errorf("validate response work-order command: %w", err)
	}
	return &wo, nil
}
