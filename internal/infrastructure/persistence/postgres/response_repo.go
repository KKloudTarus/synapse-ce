package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ResponseRepository persists governed response actions (migration 0076), tenant-scoped via
// WithTenant/RLS so one tenant's actions are never visible to another.
type ResponseRepository struct{ pool *pgxpool.Pool }

var _ ports.ResponseStore = (*ResponseRepository)(nil)

// CurrentHaltGeneration reads a tenant's fence without creating it. A missing row is the
// unhalted zero generation; only ResponseHaltWriterRepository can initialize a fence.
func (r *ResponseRepository) CurrentHaltGeneration(ctx context.Context) (int64, error) {
	var generation int64
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			SELECT generation FROM response_halt_fences
			WHERE tenant_id=current_setting('app.current_tenant', true)`).Scan(&generation)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read response halt fence: %w", err)
		}
		return nil
	})
	return generation, err
}

// NewResponseRepository constructs the repository.
func NewResponseRepository(pool *pgxpool.Pool) *ResponseRepository {
	return &ResponseRepository{pool: pool}
}

// Put creates a response record or refreshes mutable fields without changing state or immutable identity.
func (r *ResponseRepository) Put(ctx context.Context, rec rdom.Record) error {
	if tenant, ok := shared.TenantFrom(ctx); !ok || tenant.IsZero() {
		return shared.ErrValidation
	} else if rec.TenantID != tenant {
		return shared.ErrForbidden
	}
	argv, err := json.Marshal(rec.Action.Argv)
	if err != nil {
		return fmt.Errorf("marshal argv: %w", err)
	}
	reversal, err := json.Marshal(rec.Action.Reversal)
	if err != nil {
		return fmt.Errorf("marshal reversal: %w", err)
	}
	authorizationTarget, err := json.Marshal(rec.AuthorizationTarget)
	if err != nil {
		return fmt.Errorf("marshal response authorization target: %w", err)
	}
	targetFingerprint, err := json.Marshal(rec.TargetFingerprint)
	if err != nil {
		return fmt.Errorf("marshal response target fingerprint: %w", err)
	}
	var applied *time.Time
	if !rec.AppliedAt.IsZero() {
		a := rec.AppliedAt.UTC()
		applied = &a
	}
	var evID *string
	if rec.ApprovalEvidenceID != "" {
		e := rec.ApprovalEvidenceID.String()
		evID = &e
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			INSERT INTO response_actions
			  (tenant_id, id, engagement_id, kind, target, blast_radius, reversibility_class, argv, reversal, authorization_target, target_fingerprint, submitted_by, reversal_requested_by, state, approved_by, approval_evidence_id, applied_at, updated_at, verification)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
			ON CONFLICT (tenant_id, id) DO NOTHING`,
			rec.TenantID.String(), rec.ID.String(), rec.EngagementID.String(), string(rec.Action.Kind),
			rec.Action.Target.String(), string(rec.Action.BlastRadius), string(rec.Action.Reversibility), argv, reversal,
			authorizationTarget, targetFingerprint, rec.SubmittedBy, rec.ReversalRequestedBy, string(rec.State), rec.ApprovedBy, evID, applied, rec.UpdatedAt.UTC(), string(rec.Verification))
		if err != nil {
			return fmt.Errorf("insert response action %s: %w", rec.ID, err)
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var existing rdom.Record
		row := tx.QueryRow(ctx, `
			SELECT tenant_id, id, engagement_id, kind, target, blast_radius, reversibility_class, argv, reversal, authorization_target, target_fingerprint, submitted_by, reversal_requested_by, state, approved_by, approval_evidence_id, applied_at, verification
			FROM response_actions WHERE tenant_id=current_setting('app.current_tenant', true) AND id = $1 FOR UPDATE`, rec.ID.String())
		if err := scanResponse(row, &existing); err != nil {
			return fmt.Errorf("load response action %s after insert conflict: %w", rec.ID, err)
		}
		if !sameResponseIdentity(existing, rec) {
			return fmt.Errorf("%w: response action identity is immutable", shared.ErrConflict)
		}
		if existing.State != rec.State {
			return fmt.Errorf("%w: response action state requires a conditional transition", shared.ErrConflict)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE response_actions SET approved_by=$2, approval_evidence_id=$3, applied_at=$4,
			updated_at=$5, verification=$6, reversal_requested_by=$7
			WHERE tenant_id=current_setting('app.current_tenant', true) AND id=$1`, rec.ID.String(), rec.ApprovedBy, evID,
			applied, rec.UpdatedAt.UTC(), string(rec.Verification), rec.ReversalRequestedBy); err != nil {
			return fmt.Errorf("refresh response action %s: %w", rec.ID, err)
		}
		return nil
	})
}

// Transition atomically replaces mutable fields and state when the persisted state still matches from.
func (r *ResponseRepository) Transition(ctx context.Context, rec rdom.Record, from rdom.State) (bool, error) {
	if tenant, ok := shared.TenantFrom(ctx); !ok || tenant.IsZero() {
		return false, shared.ErrValidation
	} else if rec.TenantID != tenant {
		return false, shared.ErrForbidden
	}
	var transitioned bool
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		var existing rdom.Record
		row := tx.QueryRow(ctx, `
			SELECT tenant_id, id, engagement_id, kind, target, blast_radius, reversibility_class, argv, reversal, authorization_target, target_fingerprint, submitted_by, reversal_requested_by, state, approved_by, approval_evidence_id, applied_at, verification
			FROM response_actions WHERE tenant_id=current_setting('app.current_tenant', true) AND id = $1 FOR UPDATE`, rec.ID.String())
		if err := scanResponse(row, &existing); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return shared.ErrNotFound
			}
			return fmt.Errorf("load response action %s for transition: %w", rec.ID, err)
		}
		if !sameResponseIdentity(existing, rec) {
			return fmt.Errorf("%w: response action identity is immutable", shared.ErrConflict)
		}
		if existing.State != from {
			return nil
		}
		var applied *time.Time
		if !rec.AppliedAt.IsZero() {
			a := rec.AppliedAt.UTC()
			applied = &a
		}
		var evID *string
		if rec.ApprovalEvidenceID != "" {
			e := rec.ApprovalEvidenceID.String()
			evID = &e
		}
		if _, err := tx.Exec(ctx, `
			UPDATE response_actions SET state=$2, approved_by=$3, approval_evidence_id=$4,
			applied_at=$5, updated_at=$6, verification=$7, reversal_requested_by=$8
			WHERE tenant_id=current_setting('app.current_tenant', true) AND id=$1`, rec.ID.String(),
			string(rec.State), rec.ApprovedBy, evID, applied, rec.UpdatedAt.UTC(), string(rec.Verification), rec.ReversalRequestedBy); err != nil {
			return fmt.Errorf("transition response action %s: %w", rec.ID, err)
		}
		transitioned = true
		return nil
	})
	return transitioned, err
}

// Get returns the record for an id in the ctx tenant.
func (r *ResponseRepository) Get(ctx context.Context, id shared.ID) (rdom.Record, bool, error) {
	var rec rdom.Record
	found := false
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT tenant_id, id, engagement_id, kind, target, blast_radius, reversibility_class, argv, reversal, authorization_target, target_fingerprint, submitted_by, reversal_requested_by, state, approved_by, approval_evidence_id, applied_at, verification
			FROM response_actions WHERE tenant_id=current_setting('app.current_tenant', true) AND id = $1`, id.String())
		var scanned rdom.Record
		if err := scanResponse(row, &scanned); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		rec = scanned
		found = true
		return nil
	})
	return rec, found, err
}

// ListByState returns the ctx tenant's records in a state, deterministically ordered by id.
func (r *ResponseRepository) ListByState(ctx context.Context, state rdom.State) ([]rdom.Record, error) {
	var out []rdom.Record
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT tenant_id, id, engagement_id, kind, target, blast_radius, reversibility_class, argv, reversal, authorization_target, target_fingerprint, submitted_by, reversal_requested_by, state, approved_by, approval_evidence_id, applied_at, verification
			FROM response_actions WHERE tenant_id=current_setting('app.current_tenant', true) AND state = $1 ORDER BY id ASC`, string(state))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec rdom.Record
			if err := scanResponse(rows, &rec); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}

// StartAttempt durably inserts the pre-side-effect execution journal entry. Concurrent redeliveries race
// on the idempotency primary key and all observe the same immutable attempt identity.
func (r *ResponseRepository) StartAttempt(ctx context.Context, a responsesaga.ResponseAttempt) (responsesaga.ResponseAttempt, bool, error) {
	if err := a.Validate(); err != nil {
		return responsesaga.ResponseAttempt{}, false, err
	}
	target, err := json.Marshal(a.Target)
	if err != nil {
		return responsesaga.ResponseAttempt{}, false, fmt.Errorf("marshal response target fingerprint: %w", err)
	}
	var (
		stored  responsesaga.ResponseAttempt
		created bool
	)
	var deadline any
	if !a.DeadlineAt.IsZero() {
		deadline = a.DeadlineAt.UTC()
	}
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		var (
			generation int64
			halted     bool
		)
		err := tx.QueryRow(ctx, `
			SELECT generation, halted FROM response_halt_fences
			WHERE tenant_id=current_setting('app.current_tenant', true) FOR SHARE`).Scan(&generation, &halted)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("read response halt fence for attempt: %w", err)
		}
		if generation != a.HaltGeneration {
			return fmt.Errorf("%w: %w: response attempt uses generation %d, current %d", shared.ErrConflict, responsesaga.ErrStaleHaltGeneration, a.HaltGeneration, generation)
		}
		if halted {
			return fmt.Errorf("%w: tenant response dispatch is disabled", responsesaga.ErrHaltLatched)
		}
		tag, err := tx.Exec(ctx, `
			INSERT INTO response_attempts
			  (tenant_id, action_id, attempt, idempotency_key, target_fingerprint, is_reversal, state,
			   command_outcome, verification_outcome, created_at, updated_at, halt_generation,
			   observed_radius, affected_count, already_applied, decided_by, executor_id, executor_agent_id, verifier_id,
			   verification_evidence_id, verification_challenge, deadline_at, terminal_reason)
			VALUES (current_setting('app.current_tenant', true),$1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
			ON CONFLICT (tenant_id, idempotency_key) DO NOTHING`,
			a.ActionID.String(), a.Attempt, a.IdempotencyKey, target, a.IsReversal, string(a.State),
			a.CommandOutcome, string(a.VerificationOutcome), a.At.UTC(), a.HaltGeneration,
			string(a.ObservedRadius), a.AffectedCount, a.AlreadyApplied, a.DecidedBy, a.ExecutorID,
			a.ExecutorAgentID.String(), a.VerifierID, a.VerificationEvidenceID.String(), a.VerificationChallenge,
			deadline, a.TerminalReason)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "response_attempts_operation_key" {
				return fmt.Errorf("%w: response attempt operation identity already exists", shared.ErrConflict)
			}
			return fmt.Errorf("start response attempt %s: %w", a.IdempotencyKey, err)
		}
		created = tag.RowsAffected() == 1
		row := tx.QueryRow(ctx, `
			SELECT action_id, attempt, idempotency_key, target_fingerprint, is_reversal, state,
			       command_outcome, verification_outcome, created_at, halt_generation,
			       observed_radius, affected_count, already_applied, decided_by, executor_id, executor_agent_id, verifier_id,
			       verification_evidence_id, verification_challenge, deadline_at, terminal_reason
			FROM response_attempts WHERE tenant_id=current_setting('app.current_tenant', true) AND idempotency_key = $1`, a.IdempotencyKey)
		if err := scanResponseAttempt(row, &stored); err != nil {
			return fmt.Errorf("read response attempt %s after insert: %w", a.IdempotencyKey, err)
		}
		if !sameResponseAttemptIdentity(stored, a) {
			return fmt.Errorf("%w: response attempt idempotency key collision", shared.ErrConflict)
		}
		return nil
	})
	return stored, created, err
}

// ClaimAttempt uses one conditional UPDATE to ensure only one concurrent delivery owns execution.
func (r *ResponseRepository) ClaimAttempt(ctx context.Context, idempotencyKey string, from, to responsesaga.SagaState, at time.Time) (responsesaga.ResponseAttempt, bool, error) {
	if !responsesaga.CanTransition(from, to) {
		return responsesaga.ResponseAttempt{}, false, fmt.Errorf("%w: illegal response attempt claim %s -> %s", shared.ErrValidation, from, to)
	}
	var (
		stored  responsesaga.ResponseAttempt
		claimed bool
	)
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			UPDATE response_attempts SET state=$3, updated_at=now()
			WHERE tenant_id=current_setting('app.current_tenant', true) AND idempotency_key=$1 AND state=$2 AND deadline_at>$4
			RETURNING action_id, attempt, idempotency_key, target_fingerprint, is_reversal, state,
			          command_outcome, verification_outcome, created_at, halt_generation,
			          observed_radius, affected_count, already_applied, decided_by, executor_id, executor_agent_id, verifier_id,
			          verification_evidence_id, verification_challenge, deadline_at, terminal_reason`, idempotencyKey, string(from), string(to), at.UTC())
		if err := scanResponseAttempt(row, &stored); err == nil {
			claimed = true
			return nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("claim response attempt %s: %w", idempotencyKey, err)
		}
		row = tx.QueryRow(ctx, `
			SELECT action_id, attempt, idempotency_key, target_fingerprint, is_reversal, state,
			       command_outcome, verification_outcome, created_at, halt_generation,
			       observed_radius, affected_count, already_applied, decided_by, executor_id, executor_agent_id, verifier_id,
			       verification_evidence_id, verification_challenge, deadline_at, terminal_reason
			FROM response_attempts WHERE tenant_id=current_setting('app.current_tenant', true) AND idempotency_key=$1`, idempotencyKey)
		if err := scanResponseAttempt(row, &stored); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return shared.ErrNotFound
			}
			return fmt.Errorf("read unclaimed response attempt %s: %w", idempotencyKey, err)
		}
		return nil
	})
	return stored, claimed, err
}

// TransitionAttempt atomically persists a state transition and its outcome/provenance payload.
func (r *ResponseRepository) TransitionAttempt(ctx context.Context, a responsesaga.ResponseAttempt, from responsesaga.SagaState) (responsesaga.ResponseAttempt, bool, error) {
	if err := a.Validate(); err != nil {
		return responsesaga.ResponseAttempt{}, false, err
	}
	if !responsesaga.CanTransition(from, a.State) {
		return responsesaga.ResponseAttempt{}, false, fmt.Errorf("%w: illegal response attempt transition %s -> %s", shared.ErrValidation, from, a.State)
	}
	var (
		stored       responsesaga.ResponseAttempt
		transitioned bool
	)
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT action_id, attempt, idempotency_key, target_fingerprint, is_reversal, state,
			       command_outcome, verification_outcome, created_at, halt_generation,
			       observed_radius, affected_count, already_applied, decided_by, executor_id, executor_agent_id, verifier_id,
			       verification_evidence_id, verification_challenge, deadline_at, terminal_reason
			FROM response_attempts
			WHERE tenant_id=current_setting('app.current_tenant', true) AND idempotency_key=$1
			FOR UPDATE`, a.IdempotencyKey)
		if err := scanResponseAttempt(row, &stored); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return shared.ErrNotFound
			}
			return fmt.Errorf("load response attempt %s for transition: %w", a.IdempotencyKey, err)
		}
		if !sameResponseAttemptTransitionIdentity(stored, a) {
			return fmt.Errorf("%w: response attempt identity is immutable", shared.ErrConflict)
		}
		if stored.State != from {
			return nil
		}
		if _, err := tx.Exec(ctx, `
			UPDATE response_attempts
			SET state=$2, command_outcome=$3, verification_outcome=$4, observed_radius=$5,
			    affected_count=$6, already_applied=$7, decided_by=$8, verifier_id=$9,
			    verification_evidence_id=$10, verification_challenge=$11,
			    terminal_reason=$12, updated_at=now()
			WHERE tenant_id=current_setting('app.current_tenant', true) AND idempotency_key=$1`,
			a.IdempotencyKey, string(a.State), a.CommandOutcome, string(a.VerificationOutcome),
			string(a.ObservedRadius), a.AffectedCount, a.AlreadyApplied, a.DecidedBy,
			a.VerifierID, a.VerificationEvidenceID.String(), a.VerificationChallenge,
			a.TerminalReason); err != nil {
			return fmt.Errorf("transition response attempt %s: %w", a.IdempotencyKey, err)
		}
		stored = a
		transitioned = true
		return nil
	})
	return stored, transitioned, err
}

// GetAttempt returns a tenant-scoped execution journal entry by idempotency key.
func (r *ResponseRepository) GetAttempt(ctx context.Context, idempotencyKey string) (responsesaga.ResponseAttempt, bool, error) {
	var (
		a     responsesaga.ResponseAttempt
		found bool
	)
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT action_id, attempt, idempotency_key, target_fingerprint, is_reversal, state,
			       command_outcome, verification_outcome, created_at, halt_generation,
			       observed_radius, affected_count, already_applied, decided_by, executor_id, executor_agent_id, verifier_id,
			       verification_evidence_id, verification_challenge, deadline_at, terminal_reason
			FROM response_attempts WHERE tenant_id=current_setting('app.current_tenant', true) AND idempotency_key = $1`, idempotencyKey)
		if err := scanResponseAttempt(row, &a); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("get response attempt %s: %w", idempotencyKey, err)
		}
		found = true
		return nil
	})
	return a, found, err
}

// AttemptStillCurrent checks attempt state and halt generation in one tenant-scoped query.
func (r *ResponseRepository) AttemptStillCurrent(ctx context.Context, idempotencyKey string, state responsesaga.SagaState, at time.Time) (bool, error) {
	var current bool
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM response_attempts a
				LEFT JOIN response_halt_fences f ON f.tenant_id=a.tenant_id
				WHERE a.tenant_id=current_setting('app.current_tenant', true) AND a.idempotency_key=$1
				  AND a.state=$2 AND a.deadline_at>$3
				  AND a.halt_generation=COALESCE(f.generation, 0) AND NOT COALESCE(f.halted, FALSE)
			)`, idempotencyKey, string(state), at.UTC()).Scan(&current); err != nil {
			return fmt.Errorf("check response attempt fence %s: %w", idempotencyKey, err)
		}
		return nil
	})
	return current, err
}

// ListAttemptsByState returns matching tenant attempts in deterministic execution order.
func (r *ResponseRepository) ListAttemptsByState(ctx context.Context, states ...responsesaga.SagaState) ([]responsesaga.ResponseAttempt, error) {
	wanted := make([]string, 0, len(states))
	for _, state := range states {
		wanted = append(wanted, string(state))
	}
	var out []responsesaga.ResponseAttempt
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT action_id, attempt, idempotency_key, target_fingerprint, is_reversal, state,
			       command_outcome, verification_outcome, created_at, halt_generation,
			       observed_radius, affected_count, already_applied, decided_by, executor_id, executor_agent_id, verifier_id,
			       verification_evidence_id, verification_challenge, deadline_at, terminal_reason
			FROM response_attempts WHERE tenant_id=current_setting('app.current_tenant', true) AND state = ANY($1)
			ORDER BY action_id, is_reversal, attempt`, wanted)
		if err != nil {
			return fmt.Errorf("list response attempts by state: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var attempt responsesaga.ResponseAttempt
			if err := scanResponseAttempt(rows, &attempt); err != nil {
				return err
			}
			out = append(out, attempt)
		}
		return rows.Err()
	})
	return out, err
}

func scanResponseAttempt(row rowScanner, a *responsesaga.ResponseAttempt) error {
	var (
		actionID, key, state, commandOutcome, verificationOutcome                      string
		observedRadius, decidedBy, executorID, executorAgentID, verifierID, evidenceID string
		target                                                                         []byte
		deadline                                                                       *time.Time
	)
	if err := row.Scan(&actionID, &a.Attempt, &key, &target, &a.IsReversal, &state,
		&commandOutcome, &verificationOutcome, &a.At, &a.HaltGeneration,
		&observedRadius, &a.AffectedCount, &a.AlreadyApplied, &decidedBy,
		&executorID, &executorAgentID, &verifierID, &evidenceID, &a.VerificationChallenge,
		&deadline, &a.TerminalReason); err != nil {
		return err
	}
	if err := json.Unmarshal(target, &a.Target); err != nil {
		return fmt.Errorf("unmarshal response target fingerprint: %w", err)
	}
	a.ActionID = shared.ID(actionID)
	a.IdempotencyKey = key
	a.State = responsesaga.SagaState(state)
	a.CommandOutcome = commandOutcome
	a.VerificationOutcome = responsesaga.VerificationOutcome(verificationOutcome)
	a.ObservedRadius = offensivepolicy.Radius(observedRadius)
	a.DecidedBy = decidedBy
	a.ExecutorID = executorID
	a.ExecutorAgentID = shared.ID(executorAgentID)
	a.VerifierID = verifierID
	a.VerificationEvidenceID = shared.ID(evidenceID)
	if deadline != nil {
		a.DeadlineAt = deadline.UTC()
	}
	return nil
}

func sameResponseAttemptIdentity(a, b responsesaga.ResponseAttempt) bool {
	return a.ActionID == b.ActionID &&
		a.Attempt == b.Attempt &&
		a.IdempotencyKey == b.IdempotencyKey &&
		a.Target == b.Target &&
		a.IsReversal == b.IsReversal &&
		a.HaltGeneration == b.HaltGeneration &&
		a.DecidedBy == b.DecidedBy &&
		a.ExecutorID == b.ExecutorID &&
		a.ExecutorAgentID == b.ExecutorAgentID
}

func sameResponseAttemptTransitionIdentity(a, b responsesaga.ResponseAttempt) bool {
	return sameResponseAttemptIdentity(a, b) && a.At.Equal(b.At) && a.DeadlineAt.Equal(b.DeadlineAt)
}

func sameResponseIdentity(a, b rdom.Record) bool {
	return a.ID == b.ID && a.TenantID == b.TenantID && a.EngagementID == b.EngagementID &&
		a.Action.ID == b.Action.ID && a.Action.Kind == b.Action.Kind && a.Action.Target == b.Action.Target &&
		a.AuthorizationTarget == b.AuthorizationTarget && a.TargetFingerprint == b.TargetFingerprint &&
		a.SubmittedBy == b.SubmittedBy &&
		a.Action.BlastRadius == b.Action.BlastRadius && a.Action.Reversibility == b.Action.Reversibility &&
		slices.Equal(a.Action.Argv, b.Action.Argv) &&
		a.Action.Reversal.Kind == b.Action.Reversal.Kind &&
		a.Action.Reversal.Description == b.Action.Reversal.Description &&
		slices.Equal(a.Action.Reversal.Argv, b.Action.Reversal.Argv)
}

func scanResponse(row rowScanner, rec *rdom.Record) error {
	var (
		tenant, id, eng, kind, targetStr, radius, reversibility, submittedBy, reversalRequestedBy, state, approvedBy string
		verification                                                                                                 string
		argv, reversal, authorizationTarget, targetFingerprint                                                       []byte
		evID                                                                                                         *string
		applied                                                                                                      *time.Time
	)
	if err := row.Scan(&tenant, &id, &eng, &kind, &targetStr, &radius, &reversibility, &argv, &reversal,
		&authorizationTarget, &targetFingerprint, &submittedBy, &reversalRequestedBy, &state, &approvedBy, &evID, &applied, &verification); err != nil {
		return err
	}
	var argvSlice []string
	if err := json.Unmarshal(argv, &argvSlice); err != nil {
		return fmt.Errorf("unmarshal argv: %w", err)
	}
	var rev rdom.ReversalSpec
	if err := json.Unmarshal(reversal, &rev); err != nil {
		return fmt.Errorf("unmarshal reversal: %w", err)
	}
	if len(authorizationTarget) > 0 {
		if err := json.Unmarshal(authorizationTarget, &rec.AuthorizationTarget); err != nil {
			return fmt.Errorf("unmarshal response authorization target: %w", err)
		}
	}
	if len(targetFingerprint) > 0 {
		if err := json.Unmarshal(targetFingerprint, &rec.TargetFingerprint); err != nil {
			return fmt.Errorf("unmarshal response target fingerprint: %w", err)
		}
	}
	rec.ID = shared.ID(id)
	rec.TenantID = shared.ID(tenant)
	rec.EngagementID = shared.ID(eng)
	rec.SubmittedBy = submittedBy
	rec.ReversalRequestedBy = reversalRequestedBy
	rec.State = rdom.State(state)
	rec.Verification = rdom.Verification(verification)
	rec.ApprovedBy = approvedBy
	if evID != nil {
		rec.ApprovalEvidenceID = shared.ID(*evID)
	}
	if applied != nil {
		rec.AppliedAt = *applied
	}
	rec.Action = rdom.Action{
		ID: shared.ID(id), Kind: rdom.Kind(kind), Target: shared.ID(targetStr),
		BlastRadius: offensivepolicy.Radius(radius), Reversibility: responsesaga.ReversibilityClass(reversibility),
		Argv: argvSlice, Reversal: rev,
	}
	return nil
}
