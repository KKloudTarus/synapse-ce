package postgres

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

var _ ports.DASTApprovalConsumer = (*ApprovalStore)(nil)

// ConsumeForDASTRun participates in the caller's custody transaction. Approval
// is locked before the run, consistently with grant issuance.
func (s *ApprovalStore) ConsumeForDASTRun(ctx context.Context, actionID, runID shared.ID) error {
	tenant, err := approvalTenant(ctx)
	if err != nil {
		return err
	}
	if _, ok, err := contextTenantTx(ctx, tenant); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("%w: DAST custody transaction required", shared.ErrValidation)
	}
	if actionID.IsZero() || runID.IsZero() {
		return fmt.Errorf("%w: action and run required", shared.ErrValidation)
	}
	return requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var state, engagement string
		err := tx.QueryRow(ctx, `SELECT decision_state, engagement_id FROM agent_approvals WHERE tenant_id=$1 AND action_id=$2 FOR UPDATE`, tenant.String(), actionID.String()).Scan(&state, &engagement)
		if err == pgx.ErrNoRows {
			return fmt.Errorf("%w: approval", shared.ErrNotFound)
		}
		if err != nil {
			return err
		}
		if state != "approved" {
			return fmt.Errorf("%w: approval unavailable", shared.ErrConflict)
		}
		var runEngagement, runAction, status string
		err = tx.QueryRow(ctx, `SELECT engagement_id,action_id,status FROM dast_runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant.String(), runID.String()).Scan(&runEngagement, &runAction, &status)
		if err == pgx.ErrNoRows {
			return fmt.Errorf("%w: DAST run", shared.ErrNotFound)
		}
		if err != nil {
			return err
		}
		if runEngagement != engagement || runAction != actionID.String() || status != "running" {
			return fmt.Errorf("%w: DAST run does not own approval", shared.ErrForbidden)
		}
		tag, err := tx.Exec(ctx, `UPDATE agent_approvals SET decision_state='consumed', consumed_by_dast_run_id=$3 WHERE tenant_id=$1 AND action_id=$2 AND decision_state='approved' AND consumed_by_dast_run_id IS NULL`, tenant.String(), actionID.String(), runID.String())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: approval unavailable", shared.ErrConflict)
		}
		return nil
	})
}
