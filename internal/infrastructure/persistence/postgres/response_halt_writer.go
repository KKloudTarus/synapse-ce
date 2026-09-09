package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ResponseHaltWriterRepository owns the only PostgreSQL pool permitted to manufacture
// response halt fences and immutable dispatch obligations. Its role is intentionally not
// usable for ordinary response, evidence, signing, or work-order mutations.
type ResponseHaltWriterRepository struct{ pool *pgxpool.Pool }

var _ ports.ResponseHaltWriter = (*ResponseHaltWriterRepository)(nil)

// NewResponseHaltWriterRepository constructs the dedicated halt-writer store.
func NewResponseHaltWriterRepository(pool *pgxpool.Pool) *ResponseHaltWriterRepository {
	return &ResponseHaltWriterRepository{pool: pool}
}

// CurrentHaltGeneration reads a tenant fence without creating one. A missing fence is the
// unhalted generation zero state; only AdvanceHaltGenerationWithAudit may create it.
func (r *ResponseHaltWriterRepository) CurrentHaltGeneration(ctx context.Context) (int64, error) {
	var generation int64
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			SELECT generation FROM response_halt_fences
			WHERE tenant_id=current_setting('app.current_tenant', true)`).Scan(&generation); err != nil {
			if err == pgx.ErrNoRows {
				return nil
			}
			return fmt.Errorf("read response halt fence: %w", err)
		}
		return nil
	})
	return generation, err
}

// AdvanceHaltGenerationWithAudit atomically inserts mandatory audit intent, locks and
// advances the tenant fence, and inserts the immutable dispatch obligation.
func (r *ResponseHaltWriterRepository) AdvanceHaltGenerationWithAudit(ctx context.Context, expected int64, intent ports.ResponseAuditIntent) (int64, ports.ResponseAuditIntent, ports.ResponseHaltDispatch, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return 0, ports.ResponseAuditIntent{}, ports.ResponseHaltDispatch{}, shared.ErrValidation
	}
	intent, metadata, err := normalizeResponseAuditIntent(intent)
	if err != nil {
		return 0, ports.ResponseAuditIntent{}, ports.ResponseHaltDispatch{}, err
	}
	if intent.Entry.Target != tenantID.String() {
		return 0, ports.ResponseAuditIntent{}, ports.ResponseHaltDispatch{}, shared.ErrForbidden
	}
	var (
		generation int64
		committed  ports.ResponseAuditIntent
		dispatch   ports.ResponseHaltDispatch
	)
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO response_halt_fences (tenant_id) VALUES (current_setting('app.current_tenant', true))
			ON CONFLICT (tenant_id) DO NOTHING`); err != nil {
			return fmt.Errorf("initialize response halt fence: %w", err)
		}
		if err := tx.QueryRow(ctx, `
			SELECT generation FROM response_halt_fences
			WHERE tenant_id=current_setting('app.current_tenant', true) FOR UPDATE`).Scan(&generation); err != nil {
			return fmt.Errorf("lock response halt fence: %w", err)
		}
		if generation != expected {
			return fmt.Errorf("%w: response halt generation changed from %d to %d", shared.ErrConflict, expected, generation)
		}
		committed, err = insertResponseAuditTx(ctx, tx, intent, metadata)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `
			UPDATE response_halt_fences SET generation=generation+1,halted=TRUE,updated_at=now()
			WHERE tenant_id=current_setting('app.current_tenant', true)
			RETURNING generation`).Scan(&generation); err != nil {
			return fmt.Errorf("advance response halt fence: %w", err)
		}
		dispatch = ports.ResponseHaltDispatch{TenantID: tenantID, Generation: generation, CreatedAt: intent.Entry.At}
		if _, err := tx.Exec(ctx, `
			INSERT INTO response_halt_dispatches (tenant_id,generation,created_at)
			VALUES (current_setting('app.current_tenant', true),$1,$2)`, generation, dispatch.CreatedAt); err != nil {
			return fmt.Errorf("insert response halt dispatch %d: %w", generation, err)
		}
		return nil
	})
	return generation, committed, dispatch, err
}
