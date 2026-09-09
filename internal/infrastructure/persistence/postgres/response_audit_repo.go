package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.ResponseAuditStore = (*ResponseRepository)(nil)

// AdvanceHaltGenerationWithAudit is intentionally unavailable to the normal runtime role.
// PostgreSQL composition passes ResponseHaltWriterRepository to the response service instead.
func (r *ResponseRepository) AdvanceHaltGenerationWithAudit(context.Context, int64, ports.ResponseAuditIntent) (int64, ports.ResponseAuditIntent, ports.ResponseHaltDispatch, error) {
	return 0, ports.ResponseAuditIntent{}, ports.ResponseHaltDispatch{}, fmt.Errorf("%w: normal response store cannot manufacture halt fences or dispatches", shared.ErrForbidden)
}

func normalizeResponseAuditIntent(intent ports.ResponseAuditIntent) (ports.ResponseAuditIntent, []byte, error) {
	normalized, err := intent.Normalize()
	if err != nil {
		return ports.ResponseAuditIntent{}, nil, err
	}
	metadata, err := json.Marshal(normalized.Entry.Metadata)
	if err != nil {
		return ports.ResponseAuditIntent{}, nil, fmt.Errorf("marshal response audit intention metadata: %w", err)
	}
	return normalized, metadata, nil
}

func insertResponseAuditTx(ctx context.Context, tx pgx.Tx, intent ports.ResponseAuditIntent, metadata []byte) (ports.ResponseAuditIntent, error) {
	tag, err := tx.Exec(ctx, `
		INSERT INTO response_audit_intents
		  (tenant_id,intent_id,actor,action,target,metadata,occurred_at)
		VALUES (current_setting('app.current_tenant', true),$1,$2,$3,$4,$5,$6)
		ON CONFLICT (tenant_id,intent_id) DO NOTHING`,
		intent.ID, intent.Entry.Actor, intent.Entry.Action, intent.Entry.Target, metadata, intent.Entry.At)
	if err != nil {
		return ports.ResponseAuditIntent{}, fmt.Errorf("insert response audit intention %s: %w", intent.ID, err)
	}
	if tag.RowsAffected() == 1 {
		return intent, nil
	}
	var (
		existing ports.ResponseAuditIntent
		raw      []byte
	)
	existing.ID = intent.ID
	if err := tx.QueryRow(ctx, `
		SELECT actor,action,target,metadata,occurred_at
		FROM response_audit_intents
		WHERE tenant_id=current_setting('app.current_tenant', true) AND intent_id=$1`, intent.ID).Scan(
		&existing.Entry.Actor, &existing.Entry.Action, &existing.Entry.Target, &raw, &existing.Entry.At,
	); err != nil {
		return ports.ResponseAuditIntent{}, fmt.Errorf("read response audit intention %s: %w", intent.ID, err)
	}
	if err := json.Unmarshal(raw, &existing.Entry.Metadata); err != nil {
		return ports.ResponseAuditIntent{}, fmt.Errorf("decode response audit intention %s: %w", intent.ID, err)
	}
	existing, err = existing.Normalize()
	if err != nil {
		return ports.ResponseAuditIntent{}, err
	}
	if !ports.SameResponseAuditIntent(existing, intent) {
		return ports.ResponseAuditIntent{}, fmt.Errorf("%w: response audit intention identity collision", shared.ErrConflict)
	}
	return existing, nil
}

// TransitionWithAudit atomically commits a response transition and its audit obligation.
func (r *ResponseRepository) TransitionWithAudit(ctx context.Context, rec rdom.Record, from rdom.State, intent ports.ResponseAuditIntent) (bool, ports.ResponseAuditIntent, error) {
	if tenant, ok := shared.TenantFrom(ctx); !ok || tenant.IsZero() {
		return false, ports.ResponseAuditIntent{}, shared.ErrValidation
	} else if rec.TenantID != tenant {
		return false, ports.ResponseAuditIntent{}, shared.ErrForbidden
	}
	intent, metadata, err := normalizeResponseAuditIntent(intent)
	if err != nil {
		return false, ports.ResponseAuditIntent{}, err
	}
	var (
		transitioned bool
		committed    ports.ResponseAuditIntent
	)
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		var existing rdom.Record
		row := tx.QueryRow(ctx, `
			SELECT tenant_id,id,engagement_id,kind,target,blast_radius,reversibility_class,argv,reversal,authorization_target,target_fingerprint,submitted_by,reversal_requested_by,state,approved_by,approval_evidence_id,applied_at,verification
			FROM response_actions WHERE tenant_id=current_setting('app.current_tenant', true) AND id=$1 FOR UPDATE`, rec.ID.String())
		if err := scanResponse(row, &existing); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return shared.ErrNotFound
			}
			return fmt.Errorf("load response action %s for audited transition: %w", rec.ID, err)
		}
		if !sameResponseIdentity(existing, rec) {
			return fmt.Errorf("%w: response action identity is immutable", shared.ErrConflict)
		}
		if existing.State != from {
			return nil
		}
		var applied *time.Time
		if !rec.AppliedAt.IsZero() {
			value := rec.AppliedAt.UTC()
			applied = &value
		}
		var evidenceID *string
		if !rec.ApprovalEvidenceID.IsZero() {
			value := rec.ApprovalEvidenceID.String()
			evidenceID = &value
		}
		committed, err = insertResponseAuditTx(ctx, tx, intent, metadata)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE response_actions SET state=$2,approved_by=$3,approval_evidence_id=$4,
			applied_at=$5,updated_at=$6,verification=$7,reversal_requested_by=$8
			WHERE tenant_id=current_setting('app.current_tenant', true) AND id=$1`, rec.ID.String(),
			string(rec.State), rec.ApprovedBy, evidenceID, applied, rec.UpdatedAt.UTC(), string(rec.Verification), rec.ReversalRequestedBy); err != nil {
			return fmt.Errorf("transition response action %s with audit: %w", rec.ID, err)
		}
		transitioned = true
		return nil
	})
	return transitioned, committed, err
}

// TransitionAttemptWithAudit atomically commits an attempt transition and its audit obligation.
func (r *ResponseRepository) TransitionAttemptWithAudit(ctx context.Context, attempt responsesaga.ResponseAttempt, from responsesaga.SagaState, intent ports.ResponseAuditIntent) (responsesaga.ResponseAttempt, bool, ports.ResponseAuditIntent, error) {
	if err := attempt.Validate(); err != nil {
		return responsesaga.ResponseAttempt{}, false, ports.ResponseAuditIntent{}, err
	}
	if !responsesaga.CanTransition(from, attempt.State) {
		return responsesaga.ResponseAttempt{}, false, ports.ResponseAuditIntent{}, fmt.Errorf("%w: illegal response attempt transition %s -> %s", shared.ErrValidation, from, attempt.State)
	}
	intent, metadata, err := normalizeResponseAuditIntent(intent)
	if err != nil {
		return responsesaga.ResponseAttempt{}, false, ports.ResponseAuditIntent{}, err
	}
	var (
		stored       responsesaga.ResponseAttempt
		transitioned bool
		committed    ports.ResponseAuditIntent
	)
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT action_id,attempt,idempotency_key,target_fingerprint,is_reversal,state,
			       command_outcome,verification_outcome,created_at,halt_generation,
			       observed_radius,affected_count,already_applied,decided_by,executor_id,executor_agent_id,verifier_id,
			       verification_evidence_id,verification_challenge,deadline_at,terminal_reason
			FROM response_attempts
			WHERE tenant_id=current_setting('app.current_tenant', true) AND idempotency_key=$1 FOR UPDATE`, attempt.IdempotencyKey)
		if err := scanResponseAttempt(row, &stored); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return shared.ErrNotFound
			}
			return fmt.Errorf("load response attempt %s for audited transition: %w", attempt.IdempotencyKey, err)
		}
		if !sameResponseAttemptTransitionIdentity(stored, attempt) {
			return fmt.Errorf("%w: response attempt identity is immutable", shared.ErrConflict)
		}
		if stored.State != from {
			return nil
		}
		committed, err = insertResponseAuditTx(ctx, tx, intent, metadata)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE response_attempts
			SET state=$2,command_outcome=$3,verification_outcome=$4,observed_radius=$5,
			    affected_count=$6,already_applied=$7,decided_by=$8,verifier_id=$9,
			    verification_evidence_id=$10,verification_challenge=$11,
			    terminal_reason=$12,updated_at=now()
			WHERE tenant_id=current_setting('app.current_tenant', true) AND idempotency_key=$1`,
			attempt.IdempotencyKey, string(attempt.State), attempt.CommandOutcome, string(attempt.VerificationOutcome),
			string(attempt.ObservedRadius), attempt.AffectedCount, attempt.AlreadyApplied, attempt.DecidedBy,
			attempt.VerifierID, attempt.VerificationEvidenceID.String(), attempt.VerificationChallenge,
			attempt.TerminalReason); err != nil {
			return fmt.Errorf("transition response attempt %s with audit: %w", attempt.IdempotencyKey, err)
		}
		stored = attempt
		transitioned = true
		return nil
	})
	return stored, transitioned, committed, err
}

// EnqueueResponseAudit persists an idempotent response summary obligation.
func (r *ResponseRepository) EnqueueResponseAudit(ctx context.Context, intent ports.ResponseAuditIntent) (ports.ResponseAuditIntent, error) {
	intent, metadata, err := normalizeResponseAuditIntent(intent)
	if err != nil {
		return ports.ResponseAuditIntent{}, err
	}
	var committed ports.ResponseAuditIntent
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		committed, err = insertResponseAuditTx(ctx, tx, intent, metadata)
		return err
	})
	return committed, err
}

// ListPendingResponseAudits returns the calling tenant's pending obligations in stable order.
func (r *ResponseRepository) ListPendingResponseAudits(ctx context.Context) ([]ports.ResponseAuditIntent, error) {
	var out []ports.ResponseAuditIntent
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT intent_id,actor,action,target,metadata,occurred_at
			FROM response_audit_intents
			WHERE tenant_id=current_setting('app.current_tenant', true) AND completed_at IS NULL
			ORDER BY occurred_at,intent_id`)
		if err != nil {
			return fmt.Errorf("list pending response audits: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var intent ports.ResponseAuditIntent
			var raw []byte
			if err := rows.Scan(&intent.ID, &intent.Entry.Actor, &intent.Entry.Action, &intent.Entry.Target, &raw, &intent.Entry.At); err != nil {
				return fmt.Errorf("scan pending response audit: %w", err)
			}
			if err := json.Unmarshal(raw, &intent.Entry.Metadata); err != nil {
				return fmt.Errorf("decode pending response audit %s: %w", intent.ID, err)
			}
			intent, err = intent.Normalize()
			if err != nil {
				return err
			}
			out = append(out, intent)
		}
		return rows.Err()
	})
	return out, err
}

// AcknowledgeResponseAudit monotonically marks an obligation delivered to the audit chain.
func (r *ResponseRepository) AcknowledgeResponseAudit(ctx context.Context, id string) error {
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE response_audit_intents SET completed_at=COALESCE(completed_at,now())
			WHERE tenant_id=current_setting('app.current_tenant', true) AND intent_id=$1`, id)
		if err != nil {
			return fmt.Errorf("acknowledge response audit %s: %w", id, err)
		}
		if tag.RowsAffected() != 1 {
			return shared.ErrNotFound
		}
		return nil
	})
}

// ListPendingResponseHaltDispatches returns durable executor-fence obligations in generation order.
func (r *ResponseRepository) ListPendingResponseHaltDispatches(ctx context.Context) ([]ports.ResponseHaltDispatch, error) {
	var out []ports.ResponseHaltDispatch
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT tenant_id,generation,created_at
			FROM response_halt_dispatches
			WHERE tenant_id=current_setting('app.current_tenant', true)
			ORDER BY generation`)
		if err != nil {
			return fmt.Errorf("list pending response halt dispatches: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var dispatch ports.ResponseHaltDispatch
			if err := rows.Scan(&dispatch.TenantID, &dispatch.Generation, &dispatch.CreatedAt); err != nil {
				return fmt.Errorf("scan pending response halt dispatch: %w", err)
			}
			dispatch.CreatedAt = dispatch.CreatedAt.UTC()
			out = append(out, dispatch)
		}
		return rows.Err()
	})
	return out, err
}

// AcknowledgeResponseHaltDispatch verifies the immutable delivery obligation still exists.
// Completion is deliberately not persisted: the application role can issue raw SQL, so it
// cannot receive a database-side capability to forge a delivery acknowledgement. Replaying
// the signed endpoint fence remains idempotent and is therefore the fail-safe recovery path.
func (r *ResponseRepository) AcknowledgeResponseHaltDispatch(ctx context.Context, generation int64) error {
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM response_halt_dispatches
			WHERE tenant_id=current_setting('app.current_tenant', true) AND generation=$1)`, generation).Scan(&exists); err != nil {
			return fmt.Errorf("acknowledge response halt dispatch %d: %w", generation, err)
		}
		if !exists {
			return shared.ErrNotFound
		}
		return nil
	})
}
