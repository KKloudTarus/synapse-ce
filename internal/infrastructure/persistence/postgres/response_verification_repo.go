package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type ResponseVerificationRepository struct {
	pool *pgxpool.Pool
	*FleetAuditRepository
}

var _ ports.ResponseVerificationAuditStore = (*ResponseVerificationRepository)(nil)
var _ ports.ResponseTargetEvidenceReceiptStore = (*ResponseVerificationRepository)(nil)

func NewResponseVerificationRepository(pool *pgxpool.Pool) (*ResponseVerificationRepository, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: response-verification repository requires a database pool", shared.ErrValidation)
	}
	audits, err := NewFleetAuditRepository(pool)
	if err != nil {
		return nil, err
	}
	return &ResponseVerificationRepository{pool: pool, FleetAuditRepository: audits}, nil
}

func (r *ResponseVerificationRepository) AppendResponseTargetEvidenceReceipt(ctx context.Context, receipt fleetagent.ResponseTargetEvidenceReceipt) (fleetagent.ResponseTargetEvidenceReceipt, error) {
	if err := receipt.Validate(); err != nil {
		return fleetagent.ResponseTargetEvidenceReceipt{}, err
	}
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant != receipt.TenantID {
		return fleetagent.ResponseTargetEvidenceReceipt{}, shared.ErrForbidden
	}
	payload, err := json.Marshal(receipt)
	if err != nil {
		return fleetagent.ResponseTargetEvidenceReceipt{}, fmt.Errorf("marshal target evidence receipt: %w", err)
	}
	var stored []byte
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO response_target_evidence_receipts (tenant_id,receipt_id,attempt_key,digest,engagement_id,action_id,verification_challenge,recorded_at,receipt) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (tenant_id,attempt_key) DO NOTHING`, receipt.TenantID.String(), receipt.ReceiptID.String(), receipt.AttemptKey, receipt.Digest, receipt.EngagementID.String(), receipt.ActionID.String(), receipt.VerificationChallenge, receipt.RecordedAt, payload)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return fmt.Errorf("%w: target evidence receipt id or digest is already bound to another attempt", shared.ErrConflict)
			}
			return fmt.Errorf("insert target evidence receipt: %w", err)
		}
		if tag.RowsAffected() == 1 {
			stored = payload
			return nil
		}
		return tx.QueryRow(ctx, `SELECT receipt FROM response_target_evidence_receipts WHERE tenant_id=$1 AND attempt_key=$2`, receipt.TenantID.String(), receipt.AttemptKey).Scan(&stored)
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fleetagent.ResponseTargetEvidenceReceipt{}, fmt.Errorf("%w: target evidence receipt id or digest is already bound to another attempt", shared.ErrConflict)
		}
		return fleetagent.ResponseTargetEvidenceReceipt{}, err
	}
	var existing fleetagent.ResponseTargetEvidenceReceipt
	if err := json.Unmarshal(stored, &existing); err != nil {
		return fleetagent.ResponseTargetEvidenceReceipt{}, fmt.Errorf("decode target evidence receipt: %w", err)
	}
	if !fleetagent.SameResponseTargetEvidenceReceipt(existing, receipt) || existing.Digest != receipt.Digest || existing.ReceiptID != receipt.ReceiptID {
		return fleetagent.ResponseTargetEvidenceReceipt{}, fmt.Errorf("%w: target evidence receipt attempt equivocation", shared.ErrConflict)
	}
	return fleetagent.CloneResponseTargetEvidenceReceipt(existing), nil
}

func (r *ResponseVerificationRepository) GetResponseTargetEvidenceReceipt(ctx context.Context, attemptKey string) (fleetagent.ResponseTargetEvidenceReceipt, bool, error) {
	var receipt fleetagent.ResponseTargetEvidenceReceipt
	found := false
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		var payload []byte
		err := tx.QueryRow(ctx, `SELECT receipt FROM response_target_evidence_receipts WHERE tenant_id=$1 AND attempt_key=$2`, mustContextTenant(ctx), strings.TrimSpace(attemptKey)).Scan(&payload)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return json.Unmarshal(payload, &receipt)
	})
	if err != nil || !found {
		return fleetagent.ResponseTargetEvidenceReceipt{}, false, err
	}
	if err := receipt.Validate(); err != nil {
		return fleetagent.ResponseTargetEvidenceReceipt{}, false, err
	}
	return fleetagent.CloneResponseTargetEvidenceReceipt(receipt), true, nil
}

func mustContextTenant(ctx context.Context) string {
	tenant, _ := shared.TenantFrom(ctx)
	return tenant.String()
}

func (r *ResponseVerificationRepository) AppendResponseVerificationWithAudit(ctx context.Context, observation ports.AcceptedResponseVerification, intent ports.FleetAuditIntent) (ports.FleetAuditIntent, error) {
	if err := observation.Validate(); err != nil {
		return ports.FleetAuditIntent{}, err
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return ports.FleetAuditIntent{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	var committed ports.FleetAuditIntent
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		transactionCtx := context.WithValue(ctx, tenantTransactionKey{}, tenantTransaction{tenantID: tenantID.String(), tx: tx})
		if err := r.append(transactionCtx, observation); err != nil {
			return err
		}
		var err error
		intent, _, err = validateFleetAuditIntent(intent)
		if err != nil {
			return err
		}
		var existingAt time.Time
		err = tx.QueryRow(ctx, `SELECT occurred_at FROM fleet_audit_intents
			WHERE tenant_id=$1 AND intent_id=$2`, tenantID.String(), intent.ID).Scan(&existingAt)
		if err == nil {
			intent.Entry.At = existingAt.UTC()
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("read response-verification audit intention: %w", err)
		}
		stored, err := r.insertFleetAudit(transactionCtx, intent)
		if err != nil {
			return err
		}
		committed = stored
		return nil
	})
	return committed, err
}

func (r *ResponseVerificationRepository) append(ctx context.Context, observation ports.AcceptedResponseVerification) error {
	report, err := json.Marshal(observation.Report)
	if err != nil {
		return fmt.Errorf("marshal response-verification report: %w", err)
	}
	tenant, _ := shared.TenantFrom(ctx)
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO response_verification_observations
			(tenant_id,report_id,attempt_key,verification_challenge,action_id,engagement_id,agent_id,asset_id,observer_id,observed_at,recorded_at,signed_content_digest,report)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			ON CONFLICT (tenant_id,report_id) DO NOTHING`,
			tenant.String(), observation.Report.ReportID.String(), strings.TrimSpace(observation.Report.AttemptKey),
			observation.Report.VerificationChallenge,
			observation.Report.ActionID.String(), observation.Report.EngagementID.String(), observation.Report.AgentID.String(),
			observation.Report.AssetID.String(), observation.ObserverID, observation.Report.ObservedAt.UTC(), observation.RecordedAt.UTC(),
			observation.SignedContentDigest, report)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return fmt.Errorf("%w: response-verification attempt already has a report", shared.ErrConflict)
			}
			return fmt.Errorf("insert response-verification observation: %w", err)
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var existing ports.AcceptedResponseVerification
		if err := tx.QueryRow(ctx, `SELECT attempt_key,observer_id,signed_content_digest,recorded_at,report
			FROM response_verification_observations WHERE tenant_id=$1 AND report_id=$2`, tenant.String(), observation.Report.ReportID.String()).
			Scan(&existing.Report.AttemptKey, &existing.ObserverID, &existing.SignedContentDigest, &existing.RecordedAt, &report); err != nil {
			return fmt.Errorf("read response-verification collision: %w", err)
		}
		if err := json.Unmarshal(report, &existing.Report); err != nil {
			return fmt.Errorf("decode response-verification collision: %w", err)
		}
		if !ports.SameAcceptedResponseVerification(existing, observation) {
			return fmt.Errorf("%w: response-verification report id is already committed to different signed content", shared.ErrConflict)
		}
		return nil
	})
}

func (r *ResponseVerificationRepository) GetResponseVerification(ctx context.Context, attemptKey string) (ports.AcceptedResponseVerification, bool, error) {
	if strings.TrimSpace(attemptKey) == "" {
		return ports.AcceptedResponseVerification{}, false, shared.ErrValidation
	}
	var observation ports.AcceptedResponseVerification
	found := false
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		var report []byte
		err := tx.QueryRow(ctx, `SELECT observer_id,signed_content_digest,recorded_at,report
			FROM response_verification_observations WHERE tenant_id=$1 AND attempt_key=$2`, tenant.String(), strings.TrimSpace(attemptKey)).
			Scan(&observation.ObserverID, &observation.SignedContentDigest, &observation.RecordedAt, &report)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read response-verification observation: %w", err)
		}
		if err := json.Unmarshal(report, &observation.Report); err != nil {
			return fmt.Errorf("decode response-verification observation: %w", err)
		}
		found = true
		return nil
	})
	if err != nil || !found {
		return ports.AcceptedResponseVerification{}, found, err
	}
	if err := observation.Validate(); err != nil {
		return ports.AcceptedResponseVerification{}, false, fmt.Errorf("validate stored response-verification observation: %w", err)
	}
	return observation, true, nil
}
