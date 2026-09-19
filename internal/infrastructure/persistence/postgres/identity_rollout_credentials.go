package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.IdentityCredentialRolloutLedger = (*IdentityRolloutRepository)(nil)

// AppendIdentityCredentialRolloutPhaseRecord writes D4 + D5 gate evidence to the same immutable
// rollout ledger. The D4-only append method remains source-compatible, but callers advancing to an
// authoritative-read phase must use this method so credential classification evidence cannot be
// silently omitted and interpreted as a clean zero count.
func (repository *IdentityRolloutRepository) AppendIdentityCredentialRolloutPhaseRecord(ctx context.Context, record ports.IdentityRolloutPhaseRecord) error {
	record.TenantID = shared.TenantOrDefault(record.TenantID)
	record.Owner = strings.TrimSpace(record.Owner)
	record.CreatedBy = strings.TrimSpace(record.CreatedBy)
	record.RollbackAction = strings.TrimSpace(record.RollbackAction)
	if record.TenantID.IsZero() || record.ID.IsZero() || record.Owner == "" || len(record.Owner) > 256 || record.CreatedBy == "" || len(record.CreatedBy) > 256 || record.RollbackAction == "" || record.CreatedAt.IsZero() {
		return fmt.Errorf("%w: identity credential rollout phase record is invalid", shared.ErrValidation)
	}
	counts := []int{
		record.SourceCount, record.ProjectedCount, record.DriftCount, record.CorruptCredentialCount, record.DuplicateCredentialCount,
		record.CredentialProjectedCount, record.IssuedCredentialCount, record.PlaceholderCredentialCount, record.AmbiguousCredentialCount,
		record.MissingCredentialCount, record.CredentialDriftCount, record.CredentialIndexDriftCount,
		record.DenialCount, record.ErrorCount, record.SessionCount, record.ObservationMinutes, record.AbortThresholdBPS,
	}
	for _, count := range counts {
		if count < 0 {
			return fmt.Errorf("%w: identity credential rollout counts must be non-negative", shared.ErrValidation)
		}
	}
	if record.AbortThresholdBPS > 10000 || record.IssuedCredentialCount+record.PlaceholderCredentialCount+record.AmbiguousCredentialCount != record.CredentialProjectedCount {
		return fmt.Errorf("%w: identity credential rollout reconciliation is invalid", shared.ErrValidation)
	}

	return WithTenant(ctx, repository.pool, record.TenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO identity_rollout_phase_records
			(tenant_id,id,phase,owner,source_of_truth,allowed_writers,source_count,projected_count,drift_count,corrupt_credential_count,duplicate_credential_count,
			 credential_projection_complete,credential_projected_count,issued_credential_count,placeholder_credential_count,ambiguous_credential_count,
			 missing_credential_count,credential_drift_count,credential_index_drift_count,denial_count,error_count,session_count,observation_minutes,
			 abort_threshold_bps,last_known_good_phase,rollback_action,metrics_recorded,approval_recorded,created_by,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30)`,
			record.TenantID.String(), record.ID.String(), record.Phase, record.Owner, record.SourceOfTruth, record.AllowedWriters,
			record.SourceCount, record.ProjectedCount, record.DriftCount, record.CorruptCredentialCount, record.DuplicateCredentialCount,
			record.CredentialProjectionComplete, record.CredentialProjectedCount, record.IssuedCredentialCount, record.PlaceholderCredentialCount,
			record.AmbiguousCredentialCount, record.MissingCredentialCount, record.CredentialDriftCount, record.CredentialIndexDriftCount,
			record.DenialCount, record.ErrorCount, record.SessionCount, record.ObservationMinutes, record.AbortThresholdBPS,
			record.LastKnownGoodPhase, record.RollbackAction, record.MetricsRecorded, record.ApprovalRecorded, record.CreatedBy, record.CreatedAt.UTC())
		if err != nil {
			return fmt.Errorf("append identity credential rollout phase record: %w", err)
		}
		return nil
	})
}
