package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.FleetAuditIntentStore = (*FleetAuditRepository)(nil)

type FleetAuditRepository struct {
	pool *pgxpool.Pool
}

func NewFleetAuditRepository(pool *pgxpool.Pool) (*FleetAuditRepository, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: fleet audit repository pool is required", shared.ErrValidation)
	}
	return &FleetAuditRepository{pool: pool}, nil
}

// insertFleetAudit durably records one immutable audit intention alongside the
// mutation that requires it, and returns the EXACT payload that became durable.
// Callers must audit the returned intention rather than their own candidate: the
// stored occurred_at is microsecond-normalized, so a restart-time reconciler and
// an immediate delivery would otherwise hash two different entries for one
// intention identity.
func (r *FleetAuditRepository) insertFleetAudit(ctx context.Context, intent ports.FleetAuditIntent) (ports.FleetAuditIntent, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return ports.FleetAuditIntent{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	intent, metadata, err := validateFleetAuditIntent(intent)
	if err != nil {
		return ports.FleetAuditIntent{}, err
	}
	insert := func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO fleet_audit_intents
			(tenant_id,intent_id,actor,action,target,metadata,occurred_at)
			VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id,intent_id) DO NOTHING`,
			tenantID.String(), intent.ID, intent.Entry.Actor, intent.Entry.Action,
			intent.Entry.Target, metadata, intent.Entry.At)
		if err != nil {
			return fmt.Errorf("insert fleet audit intention: %w", err)
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var actor, action, target string
		var metadataEqual bool
		var at time.Time
		// Compare metadata by PostgreSQL jsonb semantics, not by serialized bytes: Go map
		// ordering must not turn an identical retry into a false equivocation.
		if err := tx.QueryRow(ctx, `SELECT actor,action,target,metadata=$3::jsonb,occurred_at
			FROM fleet_audit_intents WHERE tenant_id=$1 AND intent_id=$2`,
			tenantID.String(), intent.ID, string(metadata)).Scan(&actor, &action, &target, &metadataEqual, &at); err != nil {
			return fmt.Errorf("read fleet audit intention collision: %w", err)
		}
		if actor != intent.Entry.Actor || action != intent.Entry.Action || target != intent.Entry.Target ||
			!at.Equal(intent.Entry.At) || !metadataEqual {
			return fmt.Errorf("%w: fleet audit intention id is already committed to different content", shared.ErrConflict)
		}
		return nil
	}
	if tx, bound, err := contextTenantTx(ctx, tenantID); bound || err != nil {
		if err != nil {
			return ports.FleetAuditIntent{}, err
		}
		if err := insert(tx); err != nil {
			return ports.FleetAuditIntent{}, err
		}
		return intent, nil
	}
	if err := WithContextTenant(ctx, r.pool, insert); err != nil {
		return ports.FleetAuditIntent{}, err
	}
	return intent, nil
}

// ListPendingFleetAudits returns the calling tenant's committed-but-undelivered
// audit obligations, oldest first. The tenant predicate is explicit rather than
// left to RLS alone: a runtime role holding BYPASSRLS would otherwise let one
// tenant's recovery sweep read another tenant's obligations and write them into
// its own audit chain.
func (r *FleetAuditRepository) ListPendingFleetAudits(ctx context.Context) (out []ports.FleetAuditIntent, err error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT intent_id,actor,action,target,metadata,occurred_at
			FROM fleet_audit_intents WHERE tenant_id=$1 AND completed_at IS NULL
			ORDER BY occurred_at,intent_id`, tenantID.String())
		if err != nil {
			return fmt.Errorf("list pending fleet audit intentions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var intent ports.FleetAuditIntent
			var metadata []byte
			if err := rows.Scan(&intent.ID, &intent.Entry.Actor, &intent.Entry.Action,
				&intent.Entry.Target, &metadata, &intent.Entry.At); err != nil {
				return fmt.Errorf("scan pending fleet audit intention: %w", err)
			}
			if err := json.Unmarshal(metadata, &intent.Entry.Metadata); err != nil {
				return fmt.Errorf("decode pending fleet audit metadata: %w", err)
			}
			// pgx scans timestamptz in the session's local zone. Restart-time delivery must
			// reproduce the payload the in-process caller already audited, so the entry
			// hashes identically no matter which TZ this process runs in.
			intent.Entry.At = intent.Entry.At.UTC()
			out = append(out, intent)
		}
		return rows.Err()
	})
	return out, err
}

// AcknowledgeFleetAudit marks one of the calling tenant's intentions delivered. It
// is monotonic (COALESCE keeps the first completion) and tenant-scoped in SQL, so
// it cannot retire another tenant's outstanding obligation.
func (r *FleetAuditRepository) AcknowledgeFleetAudit(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: fleet audit intention id is required", shared.ErrValidation)
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE fleet_audit_intents
			SET completed_at=COALESCE(completed_at,now())
			WHERE tenant_id=$1 AND intent_id=$2`, tenantID.String(), id)
		if err != nil {
			return fmt.Errorf("acknowledge fleet audit intention: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("fleet audit intention %s: %w", id, shared.ErrNotFound)
		}
		return nil
	})
}

// validateFleetAuditIntent canonicalizes the intention through the single shared
// normalizer, so this backend cannot drift from the memory one and hash the same
// obligation differently, and returns its serialized metadata for persistence.
func validateFleetAuditIntent(intent ports.FleetAuditIntent) (ports.FleetAuditIntent, []byte, error) {
	intent, err := intent.Normalize()
	if err != nil {
		return ports.FleetAuditIntent{}, nil, err
	}
	metadata, err := json.Marshal(intent.Entry.Metadata)
	if err != nil {
		return ports.FleetAuditIntent{}, nil, fmt.Errorf("marshal fleet audit intention metadata: %w", err)
	}
	return intent, metadata, nil
}
