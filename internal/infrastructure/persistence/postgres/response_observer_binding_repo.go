package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type ResponseObserverBindingRepository struct {
	pool *pgxpool.Pool
	*FleetAuditRepository
}

var _ ports.ResponseObserverBindingAuditStore = (*ResponseObserverBindingRepository)(nil)

func NewResponseObserverBindingRepository(pool *pgxpool.Pool) (*ResponseObserverBindingRepository, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: response-observer binding repository requires a database pool", shared.ErrValidation)
	}
	audits, err := NewFleetAuditRepository(pool)
	if err != nil {
		return nil, err
	}
	return &ResponseObserverBindingRepository{pool: pool, FleetAuditRepository: audits}, nil
}

func (r *ResponseObserverBindingRepository) SaveResponseObserverBindingWithAudit(ctx context.Context, binding fleetagent.ResponseObserverBinding, expectedVersion int, intent ports.FleetAuditIntent) (fleetagent.ResponseObserverBinding, ports.FleetAuditIntent, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return fleetagent.ResponseObserverBinding{}, ports.FleetAuditIntent{}, shared.ErrValidation
	}
	if err := binding.Validate(); err != nil {
		return fleetagent.ResponseObserverBinding{}, ports.FleetAuditIntent{}, err
	}
	if binding.TenantID != tenantID || expectedVersion < 0 || binding.Version != expectedVersion+1 {
		return fleetagent.ResponseObserverBinding{}, ports.FleetAuditIntent{}, shared.ErrValidation
	}
	var committed ports.FleetAuditIntent
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		transactionCtx := context.WithValue(ctx, tenantTransactionKey{}, tenantTransaction{tenantID: tenantID.String(), tx: tx})
		existing, found, err := getResponseObserverBindingTx(ctx, tx, tenantID, binding.AgentID, true)
		if err != nil {
			return err
		}
		if found && existing.Version == expectedVersion+1 && samePostgresResponseObserverBindingRequest(existing, binding) {
			// Exact transaction retries still have to recover the matching audit obligation.
			binding = existing
			intent.Entry.At = existing.AssignedAt
		} else {
			currentVersion := 0
			if found {
				currentVersion = existing.Version
			}
			if currentVersion != expectedVersion {
				return fmt.Errorf("%w: response-observer binding version changed from %d to %d", shared.ErrConflict, expectedVersion, currentVersion)
			}
			if found {
				tag, err := tx.Exec(ctx, `UPDATE response_observer_bindings
					SET asset_id=$3,assigned_by=$4,assigned_at=$5,expires_at=$6,version=$7
					WHERE tenant_id=$1 AND agent_id=$2 AND version=$8`,
					tenantID.String(), binding.AgentID.String(), binding.AssetID.String(), binding.AssignedBy,
					binding.AssignedAt.UTC(), binding.ExpiresAt.UTC(), binding.Version, expectedVersion)
				if err != nil {
					return fmt.Errorf("update response-observer binding: %w", err)
				}
				if tag.RowsAffected() != 1 {
					return shared.ErrConflict
				}
			} else if _, err := tx.Exec(ctx, `INSERT INTO response_observer_bindings
				(tenant_id,agent_id,asset_id,assigned_by,assigned_at,expires_at,version)
				VALUES ($1,$2,$3,$4,$5,$6,$7)`, tenantID.String(), binding.AgentID.String(), binding.AssetID.String(),
				binding.AssignedBy, binding.AssignedAt.UTC(), binding.ExpiresAt.UTC(), binding.Version); err != nil {
				return fmt.Errorf("insert response-observer binding: %w", err)
			}
		}
		intent, _, err = validateFleetAuditIntent(intent)
		if err != nil {
			return err
		}
		var existingAt time.Time
		err = tx.QueryRow(ctx, `SELECT occurred_at FROM fleet_audit_intents WHERE tenant_id=$1 AND intent_id=$2`, tenantID.String(), intent.ID).Scan(&existingAt)
		if err == nil {
			intent.Entry.At = existingAt.UTC()
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("read response-observer audit intention: %w", err)
		}
		committed, err = r.insertFleetAudit(transactionCtx, intent)
		return err
	})
	return binding, committed, err
}

func (r *ResponseObserverBindingRepository) GetResponseObserverBinding(ctx context.Context, agentID shared.ID) (fleetagent.ResponseObserverBinding, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() || agentID.IsZero() {
		return fleetagent.ResponseObserverBinding{}, shared.ErrValidation
	}
	var binding fleetagent.ResponseObserverBinding
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var found bool
		var err error
		binding, found, err = getResponseObserverBindingTx(ctx, tx, tenantID, agentID, false)
		if err != nil {
			return err
		}
		if !found {
			return shared.ErrNotFound
		}
		return nil
	})
	return binding, err
}

func (r *ResponseObserverBindingRepository) ListResponseObserverBindings(ctx context.Context, assetID shared.ID) ([]fleetagent.ResponseObserverBinding, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() || assetID.IsZero() {
		return nil, shared.ErrValidation
	}
	var out []fleetagent.ResponseObserverBinding
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id,agent_id,asset_id,assigned_by,assigned_at,expires_at,version
			FROM response_observer_bindings WHERE tenant_id=$1 AND asset_id=$2 ORDER BY agent_id`, tenantID.String(), assetID.String())
		if err != nil {
			return fmt.Errorf("list response-observer bindings: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var binding fleetagent.ResponseObserverBinding
			if err := rows.Scan(&binding.TenantID, &binding.AgentID, &binding.AssetID, &binding.AssignedBy,
				&binding.AssignedAt, &binding.ExpiresAt, &binding.Version); err != nil {
				return fmt.Errorf("scan response-observer binding: %w", err)
			}
			out = append(out, binding)
		}
		return rows.Err()
	})
	return out, err
}

func getResponseObserverBindingTx(ctx context.Context, tx pgx.Tx, tenantID, agentID shared.ID, lock bool) (fleetagent.ResponseObserverBinding, bool, error) {
	query := `SELECT tenant_id,agent_id,asset_id,assigned_by,assigned_at,expires_at,version
		FROM response_observer_bindings WHERE tenant_id=$1 AND agent_id=$2`
	if lock {
		query += ` FOR UPDATE`
	}
	var binding fleetagent.ResponseObserverBinding
	err := tx.QueryRow(ctx, query, tenantID.String(), agentID.String()).Scan(
		&binding.TenantID, &binding.AgentID, &binding.AssetID, &binding.AssignedBy,
		&binding.AssignedAt, &binding.ExpiresAt, &binding.Version,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return fleetagent.ResponseObserverBinding{}, false, nil
	}
	if err != nil {
		return fleetagent.ResponseObserverBinding{}, false, fmt.Errorf("read response-observer binding: %w", err)
	}
	return binding, true, nil
}

func samePostgresResponseObserverBindingRequest(left, right fleetagent.ResponseObserverBinding) bool {
	return left.TenantID == right.TenantID && left.AgentID == right.AgentID && left.AssetID == right.AssetID &&
		left.AssignedBy == right.AssignedBy && left.ExpiresAt.Equal(right.ExpiresAt) && left.Version == right.Version
}
